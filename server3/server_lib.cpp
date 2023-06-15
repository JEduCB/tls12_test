#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <errno.h>
#include <limits.h>
#include <openssl/async.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <queue>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#define MAX_PAYLOAD (1024 * 1024)

static volatile sig_atomic_t keep_running = 1;
int g_async_jobs = 1;
char g_async_mode = 0;
int g_payload = 0;
int g_server = 0;
int g_thread_count = 1;
SSL_CTX* g_ctx = NULL;

void keep_running_handler(int _)
{
    (void)_;

    keep_running = 0;
    close(g_server);    /* close server socket */

    ERR_free_strings(); /* free memory from SSL_load_error_strings */
    EVP_cleanup();      /* free memory from OpenSSL_add_all_algorithms */

    printf("\n\nserver has been closed by user\n\n");
}

struct async_job_parameters
{
    async_job_parameters(ASYNC_WAIT_CTX* _waitctx, int _client) : job{NULL}, waitctx{_waitctx}, client{_client}{}
    ASYNC_JOB* job;
    ASYNC_WAIT_CTX* waitctx;
    int client;
};

void set_certificates(const char* pem_public_file, const char* pem_private_file)
{
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(g_ctx, pem_public_file, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(g_ctx, pem_private_file, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* verify private key */
    if (!SSL_CTX_check_private_key(g_ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void send_html_response(SSL* ssl, int payload_size)
{
    static const char* _template = "HTTP/1.1 200 OK\r\n"
        "Content-type: text/html\r\n"
        "\r\n"
        "<html>\n"
        "<body>\n"
        "%s"
        "</body>\n"
        "</html>\n";

    static char _payload[MAX_PAYLOAD + 1];
    static char _response[MAX_PAYLOAD + 128 + 1]; //MAX_PAYLOAD + enough space for _template

    srand(clock());

    char random_char = 'A' + (random() % 25);
    
    memset(_payload, random_char, payload_size);
    _payload[payload_size] = 0;

    sprintf(_response, _template, _payload);

    int size = strlen(_response);

    SSL_write(ssl, _response, size); /* send response */
}

void io_handler(SSL* ssl)
{
    char* request = (char*)calloc(UINT16_MAX + 1, sizeof(char));
    int bytes = SSL_read(ssl, request, UINT16_MAX);    /* read incoming message and just ignore it*/
    free(request);
    send_html_response(ssl, g_payload);
}

void* sync_request_handler(void* args)
{
    int* client = (int*)args;

    SSL *ssl = SSL_new(g_ctx);  /* get new SSL state with context */
    SSL_set_fd(ssl, *client);    /* set connection socket to SSL state */

    if (SSL_accept(ssl) > 0)    /* do SSL-protocol accept */
    {
        io_handler(ssl);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);  /* release SSL state */
    close(*client);  /* close client socket */

    return NULL;
}

int async_job_function(void* args)
{
    sync_request_handler(args);
    return 0;
}

void* async_request_handler(void* args)
{
    std::vector<async_job_parameters>* job_params = (std::vector<async_job_parameters>*)args;

    OSSL_ASYNC_FD job_fd = 0;
    size_t num_job_fds = 0;

    int ret;
    int in_progress = 0;

    int error = 0;
    int size = job_params->size();

    for(int i = 0; i < size; ++i)
    {
        switch (ASYNC_start_job(&((*job_params)[i].job), (*job_params)[i].waitctx, &ret, async_job_function, &(*job_params)[i].client, sizeof(int)))
        {
        case ASYNC_ERR:
        case ASYNC_NO_JOBS:
            printf("ASYNC_start_job error\n");
            error = 1;
            goto end;
        case ASYNC_FINISH:
            (*job_params)[i].job = NULL;          
            break;
        case ASYNC_PAUSE:
            ++in_progress;
            break;
        }
    }

    while(in_progress > 0)
    {
        int select_result;
        OSSL_ASYNC_FD max_fd = 0;
        fd_set waitfdset;

        FD_ZERO(&waitfdset);

        for(int i = 0; i < size && in_progress > 0; ++i)
        {
            if((*job_params)[i].job == NULL)
            {
                continue;
            }

            if (!ASYNC_WAIT_CTX_get_all_fds((*job_params)[i].waitctx, NULL, &num_job_fds) || num_job_fds > 1)
            {
                printf("Too many fds in ASYNC_WAIT_CTX\n");
                error = 1;
                goto end;
            }

            ASYNC_WAIT_CTX_get_all_fds((*job_params)[i].waitctx, &job_fd, &num_job_fds);
            FD_SET(job_fd, &waitfdset);
        
            if (job_fd > max_fd)
            {
                max_fd = job_fd;
            }
        }

        if (max_fd >= (OSSL_ASYNC_FD)FD_SETSIZE)
        {
            printf("Error: max_fd (%d) must be smaller than FD_SETSIZE (%d). Decrease the value of async_jobs\n", max_fd, FD_SETSIZE);
            error = 1;
            goto end;
        }

        select_result = select(max_fd + 1, &waitfdset, NULL, NULL, NULL);

        if (select_result == 0 || select_result == -1 && errno == EINTR)
        {
            continue;
        }

        if (select_result == -1)
        {
            printf("Failure in the select\n");
            error = 1;
            goto end;
        }

        for (int i = 0; i < size; i++)
        {
            if ((*job_params)[i].job == NULL)
            {
                continue;
            }

            if (!ASYNC_WAIT_CTX_get_all_fds((*job_params)[i].waitctx, NULL, &num_job_fds) || num_job_fds > 1)
            {
                printf("Too many fds in ASYNC_WAIT_CTX\n");
                error = 1;
                goto end;
            }

            ASYNC_WAIT_CTX_get_all_fds((*job_params)[i].waitctx, &job_fd, &num_job_fds);

            if (num_job_fds == 1 && !FD_ISSET(job_fd, &waitfdset))
            {
                continue;
            }

            ret = ASYNC_start_job(&(*job_params)[i].job, (*job_params)[i].waitctx, &ret, async_job_function, &(*job_params)[i].client, sizeof(int));

            switch (ret)
            {
            case ASYNC_PAUSE:
                break;

            case ASYNC_FINISH:
                --in_progress;
                (*job_params)[i].job = NULL;
                break;

            case ASYNC_NO_JOBS:
            case ASYNC_ERR:
                error = 1;
                goto end;
            }
        }
    }

end:
    if(error)
    {
        abort();
    }

    return NULL;
}

void run_async_handler()
{
    struct timeval tv = {0, 100};

    std::unordered_map<pthread_t, std::vector<async_job_parameters>*> threads;
    std::vector<async_job_parameters> job_requests;
    std::queue<ASYNC_WAIT_CTX*> waitctx_queue;

    for(int i = 0; i < g_async_jobs * g_thread_count; ++i)
    {
        ASYNC_WAIT_CTX* waitctx = ASYNC_WAIT_CTX_new();

        if(!waitctx)
        {
            printf("Can't create ASYNC_WAIT_CTX\n");
            goto end;
        }

        waitctx_queue.emplace();
    }

    job_requests.reserve(g_async_jobs);
    threads.reserve(g_thread_count);

    while(keep_running)
    {   
        if(threads.size() < g_thread_count && job_requests.size() < g_async_jobs)
        {
            fd_set fds;

            //clear the socket set  
            FD_ZERO(&fds);
            
            //add master socket to set  
            FD_SET(g_server, &fds);

            int ret = select(g_server + 1, &fds, NULL, NULL, &tv);

            if(ret > 0 && FD_ISSET(g_server, &fds))
            {
                struct sockaddr_in addr;
                socklen_t len = sizeof(addr);

                int client = accept(g_server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */

                job_requests.emplace_back(waitctx_queue.front(), client);
                waitctx_queue.pop();
                
                continue;
            }
        }

        if(threads.size() < g_thread_count && job_requests.size())
        {
            pthread_t thread;

            std::vector<async_job_parameters>* job_params = new std::vector<async_job_parameters>(std::move(job_requests));
            pthread_create(&thread, NULL, async_request_handler, job_params);
            threads.emplace(thread, job_params);
        }
        
        if(threads.size())
        {
            for(auto it = threads.begin(); it != threads.end();)
            {
                if(pthread_tryjoin_np(it->first, NULL) == 0)
                {
                    if(it->second->size() > 0)
                    {
                        for(const auto& param : (*it->second))
                        {
                            waitctx_queue.emplace(param.waitctx);
                        }
                    }

                    delete it->second;
                    it = threads.erase(it);
                }   
                else
                {
                    ++it;
                }           
            }
        }
    }

end:
    if(!waitctx_queue.size())
    {
        abort();       
    }

    while(waitctx_queue.size())
    {
        ASYNC_WAIT_CTX_free(waitctx_queue.front());
        waitctx_queue.pop();
    }
}

void run_sync_handler()
{
    std::unordered_map<pthread_t, int*> threads;

    threads.reserve(g_thread_count);

    struct timeval tv = {0, 100};

    while(keep_running)
    {   
        if(threads.size() < g_thread_count)
        {
            fd_set fds;

            //clear the socket set  
            FD_ZERO(&fds);
            
            //add master socket to set  
            FD_SET(g_server, &fds);

            int ret = select(g_server + 1, &fds, NULL, NULL, &tv);

            if(ret > 0 && FD_ISSET(g_server, &fds))
            {
                struct sockaddr_in addr;
                socklen_t len = sizeof(addr);

                int client = accept(g_server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */

                pthread_t thread;
                int* p_client = new int{client};
                pthread_create(&thread, NULL, sync_request_handler, p_client);
                threads.emplace(thread, p_client);
                continue;
            }
        }
        
        if(threads.size())
        {
            for(auto it = threads.begin(); it != threads.end();)
            {
                int result = pthread_tryjoin_np(it->first, NULL);

                if(result == 0 || result != EBUSY)
                {
                    delete it->second;
                    it = threads.erase(it);
                }   
                else
                {
                    ++it;
                }           
            }
        }
    }
}

extern "C" int run_server(const char* port, const char* job_mode, const char* payload, const char* threads, const char* pem_public_file, const char* pem_private_file)
{
    int portnum = atoi(port);

    if (portnum < 1024)
    {
        if (portnum <= 0)
        {
            printf("Invalid port number %d\n", portnum);
            return -1;
        }
        else if (getuid() != 0)
        {
            printf("Run as admin/root/sudo_user since port # (%d) is < 1024\n", portnum);
            return -1;
        }
    }

    const char*_async = "async=";
    int async_param_size = strlen(_async);

    if(strncmp(_async, job_mode, async_param_size) && strcmp("sync", job_mode))
    {
        printf("Invalid job mode %s. Use sync or async=num.\n", job_mode);
        return -1;
    }

    if(!strncmp(_async, job_mode, async_param_size) && !ASYNC_is_capable())  
    {
        printf("async mode specified but async not supported\n");
        return -1;
    }

    g_payload = atoi(payload);

    if(g_payload <= 0 || g_payload > MAX_PAYLOAD)
    {
        printf("payload size must be a positive value <= %d\n", MAX_PAYLOAD);
        return -1;     
    }

    g_thread_count = atol(threads);
    
    if(g_thread_count <= 0)
    {
        g_thread_count = sysconf(_SC_NPROCESSORS_ONLN);
    }

    struct sockaddr_in addr;
    
    g_server = socket(AF_INET, SOCK_STREAM, 0);
    
    bzero(&addr, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(portnum);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(g_server, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        perror("can't bind port");
        abort();
    }

    if (listen (g_server, SOMAXCONN) != 0)
    {
        perror("Can't configure listening port");
        abort();
    }

    struct sigaction running_action;
    running_action.sa_handler = keep_running_handler;
    sigaction(SIGINT, &running_action, NULL);

    /* Set non-default library initialisation settings */
    if (!OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL))
    {
        printf("Error in OpenSSL init\n");
        abort();
    }

    //initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    g_ctx = SSL_CTX_new(TLS_server_method());    /* create new context from method */

    if (g_ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    set_certificates(pem_public_file, pem_private_file);

    g_async_mode = !strncmp(_async, job_mode, async_param_size);

    if(g_async_mode)
    {
        SSL_CTX_set_mode(g_ctx, SSL_MODE_ASYNC);
        ASYNC_init_thread(0, 0);
        g_async_jobs = atoi(job_mode + async_param_size);
    }
    
    pid_t pid = getpid();

    if(g_async_mode)
    {
        run_async_handler();
    }
    else
    {
        run_sync_handler();
    }

    if(getpid() == pid)
    {
        SSL_CTX_free(g_ctx);  /* release context */
    }

    return 0;
}
