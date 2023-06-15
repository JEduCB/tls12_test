#include <arpa/inet.h>
#include <atomic>
#include <errno.h>
#include <limits.h>
#include <openssl/async.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <unordered_set>
#include <vector>

#define MAX_PAYLOAD (1024 * 1024)

static volatile sig_atomic_t keep_running = 1;
int g_server;

void keep_running_handler(int _)
{
    (void)_;

    ERR_free_strings(); /* free memory from SSL_load_error_strings */
    EVP_cleanup();      /* free memory from OpenSSL_add_all_algorithms */

    printf("\n\nserver has been closed by user\n\n");
    keep_running = 0;

    close(g_server);    /* close server socket */
}

typedef struct 
{
    SSL_CTX* ctx;
    int client;
    int payload;
} request_params;

struct async_data
{
    async_data(ASYNC_JOB *_job, ASYNC_WAIT_CTX* _waitctx, request_params _params) : job{_job}, waitctx{_waitctx}, params{_params} {}

    ASYNC_JOB *job;
    ASYNC_WAIT_CTX* waitctx;
    request_params params;
};

void set_certificates(SSL_CTX* ctx, const char* pem_public_file, const char* pem_private_file)
{
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, pem_public_file, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, pem_private_file, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void send_response_html(SSL* ssl, int payload_size)
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

void handle_client_io(SSL* ssl, int payload)
{
    char* request = (char*)calloc(UINT16_MAX + 1, sizeof(char));
    int bytes = SSL_read(ssl, request, UINT16_MAX);    /* read incoming message and just ignore it*/
    free(request);
    send_response_html(ssl, payload);
}

void process_request(SSL_CTX* ctx, int client, int payload)
{
    SSL *ssl = SSL_new(ctx);    /* get new SSL state with context */
    SSL_set_fd(ssl, client);    /* set connection socket to SSL state */

    if (SSL_accept(ssl) > 0)    /* do SSL-protocol accept */
    {
        handle_client_io(ssl, payload);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);              /* release SSL state */
    close(client);              /* close client socket */
}

int request_function(void* arg)
{
    request_params* params = (request_params*)arg;

    process_request(params->ctx, params->client, params->payload);

    return 0;
}

void run_async_mode(SSL_CTX* ctx, int server, int payload)
{
    SSL_CTX_set_mode(ctx, SSL_MODE_ASYNC);

    ASYNC_init_thread(0, 0);

    int ret;

    OSSL_ASYNC_FD waitfd;
    fd_set waitfdset;
    size_t numfds; 

    int jobs_paused = 0;

    struct timeval tv = {0, 100};

    std::vector<async_data> asyncdata;

    while(keep_running)
    {
        fd_set readfds;

        //clear the socket set  
        FD_ZERO(&readfds);
        
        //add master socket to set  
        FD_SET(server, &readfds);

        int ret = select(server + 1, &readfds, NULL, NULL, &tv);

        if(ret > 0 && FD_ISSET(server, &readfds) && jobs_paused < 1) //Process incoming requests with in 256 async jobs
        {
            struct sockaddr_in addr;
            socklen_t len = sizeof(addr);

            int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */

            request_params params = {ctx, client, payload};
            async_data _asyncdata = {(ASYNC_JOB*)NULL, ASYNC_WAIT_CTX_new(), params};

            switch (ASYNC_start_job(&_asyncdata.job, _asyncdata.waitctx, &ret, request_function, &_asyncdata.params, sizeof(request_params)))
            {
            case ASYNC_ERR:
            case ASYNC_NO_JOBS:
                printf("ASYNC_start_job error\n");
                break;
            case ASYNC_PAUSE:
                asyncdata.emplace_back(_asyncdata);
                ++jobs_paused;
                continue;
            case ASYNC_FINISH:
                _asyncdata.job = NULL;
                ASYNC_WAIT_CTX_free(_asyncdata.waitctx);
                break;
            }
        }

        int in_progress = asyncdata.size();
        jobs_paused = in_progress;

        while(in_progress)
        {
            for(int i = 0; i < jobs_paused && in_progress > 0; ++i)
            {
                if(asyncdata[i].job == NULL)
                {
                    continue;
                }

                OSSL_ASYNC_FD waitfd;
                fd_set waitfdset;
                size_t numfds;    

                if (!ASYNC_WAIT_CTX_get_all_fds(asyncdata[i].waitctx, NULL, &numfds) || numfds > 1)
                {
                    printf("Unexpected number of fds\n");
                    abort();
                }

                ASYNC_WAIT_CTX_get_all_fds(asyncdata[i].waitctx, &waitfd, &numfds);
                FD_ZERO(&waitfdset);
                FD_SET(waitfd, &waitfdset);
                
                int select_result = select(waitfd + 1, &waitfdset, NULL, NULL, NULL);

                if (select_result == 0 || select_result == -1 && errno == EINTR)
                {
                    continue;
                }

                if (select_result == -1)
                {
                    break;
                }

                switch (ASYNC_start_job(&asyncdata[i].job, asyncdata[i].waitctx, &ret, request_function, &asyncdata[i].params, sizeof(request_params)))
                {
                case ASYNC_PAUSE:
                    break;

                case ASYNC_FINISH:
                case ASYNC_NO_JOBS:
                case ASYNC_ERR:
                    --in_progress;
                    asyncdata[i].job = NULL;
                    ASYNC_WAIT_CTX_free(asyncdata[i].waitctx);
                    break;
                }        
            }
        }

        asyncdata.clear();
    }
}

void run_sync_mode(SSL_CTX *ctx, int server, int payload)
{
    while(keep_running)
    {   
        fd_set fds;

        //clear the socket set  
        FD_ZERO(&fds);
        
        //add master socket to set  
        FD_SET(server, &fds);

        int ret = select(server + 1, &fds, NULL, NULL, NULL);

        if (ret == 1)
        {
            struct sockaddr_in addr;
            socklen_t len = sizeof(addr);

            int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */

            process_request(ctx, client, payload);
        }
    }
}
 
extern "C" int run_server(const char* port, const char* job_mode, const char* payload, const char* pem_public_file, const char* pem_private_file)
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

    if(strcmp("async", job_mode) && strcmp("sync", job_mode))
    {
        printf("Invalid job mode %s. Use sync or async.\n", job_mode);
        return -1;
    }

    if(!strcmp("async", job_mode) && !ASYNC_is_capable())  
    {
        printf("async mode specified but async not supported\n");
        return -1;
    }

    int _payload = atoi(payload);

    if(_payload <= 0 || _payload > MAX_PAYLOAD)
    {
        printf("payload size must be a positive value <= %d\n", MAX_PAYLOAD);
        return -1;     
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

    //initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* Set non-default library initialisation settings */
    if (!OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL))
    {
        printf("Error in OpenSSL init\n");
        abort();
    }

    SSL_CTX *ctx = NULL;
    const SSL_METHOD *method;

    method = TLS_server_method();     /* create new server-method instance */
    ctx = SSL_CTX_new(method);        /* create new context from method */

    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    set_certificates(ctx, pem_public_file, pem_private_file);

    pid_t pid = getpid();

    if(!strcmp("sync", job_mode))
    {
        run_sync_mode(ctx, g_server, _payload);
    }
    else
    {
        run_async_mode(ctx, g_server, _payload);
    }

    if(getpid() == pid)
    {
        SSL_CTX_free(ctx);  /* release context */
    }

    return 0;
}
