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
char g_async_mode = 0;
int g_payload = 0;
int g_server = 0;
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
    send_html_response(ssl, g_payload); //Just send a 200 OK response and some pre-defined size random payload 
}

void* request_handler(void* args)
{
    int* client = (int*)args;

    SSL *ssl = SSL_new(g_ctx);  /* get new SSL state with context */
    SSL_set_fd(ssl, *client);    /* set connection socket to SSL state */

    int result = 0;
    int error = 0;

    while((result = SSL_accept(ssl)) != 1)
    {
        error = SSL_get_error(ssl, result);

        if(error == SSL_ERROR_WANT_ASYNC)
        {
            while(error == SSL_ERROR_WANT_ASYNC)
            {
                OSSL_ASYNC_FD waitfd;
                fd_set waitfdset;
                size_t numfds;
                int select_result = 0;

                SSL_get_all_async_fds(ssl, &waitfd, &numfds);
                FD_ZERO(&waitfdset);
                FD_SET(waitfd, &waitfdset);

                select_result = select(waitfd + 1, &waitfdset, NULL, NULL, NULL);

                if(select_result > 0 && FD_ISSET(waitfd, &waitfdset))
                { 
                    break;
                }
            }
        }
        else
        {
            break;
        }
    }

    if(result == 1 && g_payload) 
    {
        io_handler(ssl);
    }

    //Change this logic
    SSL_shutdown(ssl);
    SSL_free(ssl);  /* release SSL state */
    close(*client);  /* close client socket */
    free(client);
    return NULL;
}

void run_connection_handler()
{
    while(keep_running)
    {   
        fd_set fds;

        //clear the socket set  
        FD_ZERO(&fds);
        
        //add master socket to set  
        FD_SET(g_server, &fds);

        int ret = select(g_server + 1, &fds, NULL, NULL, NULL);

        if(ret > 0 && FD_ISSET(g_server, &fds))
        {
            struct sockaddr_in addr;
            socklen_t len = sizeof(addr);

            int client = accept(g_server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */

            pthread_t thread;
            int* p_client = new int{client};
            pthread_create(&thread, NULL, request_handler, p_client);
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

    if(g_payload < 0 || g_payload > MAX_PAYLOAD)
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
    }
    
    run_connection_handler();

    SSL_CTX_free(g_ctx);  /* release context */

    return 0;
}
