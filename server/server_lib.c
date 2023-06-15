// Based on: https://wiki.openssl.org/index.php/Simple_TLS_Server

#include <arpa/inet.h>
#include <errno.h>
#include <malloc.h>
#include <netinet/in.h>
#include <resolv.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/async.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL    -1
#define MAX_PAYLOAD (1024 * 1024)

typedef struct 
{
    SSL_CTX* ctx;
    int server;
} params;

static volatile sig_atomic_t keep_running = 1;
int g_server;
int g_payload;

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

void process_ssl(SSL* ssl)
{
    int bytes;

    char szPayload[MAX_PAYLOAD + 1] = {0};
    char szHttpServerResponse[MAX_PAYLOAD + 128 + 1] = {0};

    bytes = SSL_read(ssl, szPayload, sizeof(szPayload)); /* get request */
    szPayload[bytes] = 0;

    memset(szPayload, 65, g_payload - 74);

    sprintf(szHttpServerResponse, "HTTP/1.1 200 OK\r\n"
        "Content-type: text/html\r\n"
        "\r\n"
        "<html>\n"
        "<body>\n"
        "%s"
        "</body>\n"
        "</html>\n", szPayload);

    SSL_write(ssl, szHttpServerResponse, strlen(szHttpServerResponse)); /* send response */
}

void process_request(SSL_CTX* ctx, int server)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */

    SSL *ssl;

    ssl = SSL_new(ctx);         /* get new SSL state with context */
    SSL_set_fd(ssl, client);    /* set connection socket to SSL state */

    if (SSL_accept(ssl) > 0)    /* do SSL-protocol accept */
    {
        process_ssl(ssl);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);              /* release SSL state */
    close(client);
}

static void keep_running_handler(int _)
{
    (void)_;

    close(g_server);    /* close server socket */
  
    ERR_free_strings(); /* free memory from SSL_load_error_strings */
    EVP_cleanup();      /* free memory from OpenSSL_add_all_algorithms */

    printf("\n\nserver has been closed by user\n\n");
    keep_running = 0;
}

void run_sync_mode(SSL_CTX* ctx, int server, const char* pem_public_file, const char* pem_private_file)
{
    fd_set fds;

    //clear the socket set  
    FD_ZERO(&fds);
    
    //add master socket to set  
    FD_SET(server, &fds);

    while(keep_running)
    {      
        int activity = select(server + 1, &fds , NULL , NULL , NULL);

        if(activity > 0 && FD_ISSET(server, &fds))
        {
            process_request(ctx, server);
        }
    }
}

int preprocess_request(void* args)
{
    params* _args = args;
    process_request(_args->ctx, _args->server);
}

void process_async_request(SSL_CTX* ctx, ASYNC_WAIT_CTX *async_ctx, int server)
{
    ASYNC_JOB *job = NULL;

    int ret;

    params _args = {ctx, server};

    char job_paused = 0;

    switch (ASYNC_start_job(&job, async_ctx, &ret, preprocess_request, &_args, sizeof(params)))
    {
    case ASYNC_ERR:
    case ASYNC_NO_JOBS:
        printf("ASYNC_start_job error\n");
        break;
    case ASYNC_PAUSE:
        job_paused = 1;
        break;
    case ASYNC_FINISH:
        break;
    }

    while(job_paused)
    {
        OSSL_ASYNC_FD waitfd;
        fd_set waitfdset;
        size_t numfds;    

        if (!ASYNC_WAIT_CTX_get_all_fds(async_ctx, NULL, &numfds) || numfds > 1)
        {
            printf("Unexpected number of fds\n");
            abort();
        }

        ASYNC_WAIT_CTX_get_all_fds(async_ctx, &waitfd, &numfds);
        FD_ZERO(&waitfdset);
        FD_SET(waitfd, &waitfdset);
        
        int select_result = select(waitfd + 1, &waitfdset, NULL, NULL, NULL);

        if (select_result == -1 && errno == EINTR)
        {
            continue;
        }

        if (select_result == -1)
        {
            break;
        }

        if (select_result == 0)
        {
            continue;
        }

        switch (ASYNC_start_job(&job, async_ctx, &ret, preprocess_request, &_args, sizeof(params)))
        {
        case ASYNC_FINISH:
            job_paused = 0;
            break;

        case ASYNC_PAUSE:
            break;

        case ASYNC_NO_JOBS:
        case ASYNC_ERR:
            job_paused = 0;
            job = NULL;
            break;
        }        
    }
}

void run_async_mode(SSL_CTX *ctx, int server, const char* pem_public_file, const char* pem_private_file)
{
    SSL_CTX_set_mode(ctx, SSL_MODE_ASYNC);

    long number_of_processors = sysconf(_SC_NPROCESSORS_ONLN);

    int async_init = ASYNC_init_thread(number_of_processors, number_of_processors);

    if (!async_init)
    {
        printf("Error creating the ASYNC job pool\n");
        return;
    }

    ASYNC_WAIT_CTX *async_ctx = NULL;

    async_ctx = ASYNC_WAIT_CTX_new();

    if (async_ctx == NULL)
    {
        printf("Failed to create ASYNC_WAIT_CTX\n");
        abort();
    }    

    fd_set fds;

    //clear the socket set  
    FD_ZERO(&fds);
    
    //add master socket to set  
    FD_SET(server, &fds);

    while(keep_running)
    {
        int activity = select(server + 1, &fds , NULL , NULL , NULL);

        if(activity > 0 && FD_ISSET(server, &fds))
        {
            process_async_request(ctx, async_ctx, server);
        }
    }

    ASYNC_WAIT_CTX_free(async_ctx);

    if (async_init)
    {
        ASYNC_cleanup_thread();
    }
}

int run_server(const char* port, const char* job_mode, const char* payload, const char* pem_public_file, const char* pem_private_file)
{
    int portnum;

    portnum = atoi(port);

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

    g_payload = atoi(payload);

    if(g_payload <= 0 || g_payload > MAX_PAYLOAD)
    {
        printf("payload size must be a positive value <= %d\n", MAX_PAYLOAD);
        return -1;     
    }

    /* Set non-default library initialisation settings */
    if (!OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL))
    {
        printf("Error in OpenSSL init\n");
        return -1;
    }

    struct sockaddr_in addr;
    
    g_server = socket(PF_INET, SOCK_STREAM, 0);
    
    bzero(&addr, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(portnum);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(g_server, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        perror("can't bind port");
        abort();
    }

    if (listen (g_server, 2048) != 0)
    {
        perror("Can't configure listening port");
        abort();
    }

    struct sigaction running_action;
    running_action.sa_handler = keep_running_handler;
    sigaction(SIGINT, &running_action, NULL);

    SSL_CTX *ctx;
    const SSL_METHOD *method;

    method = TLS_server_method();     /* create new server-method instance */
    ctx = SSL_CTX_new(method);        /* create new context from method */

    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    set_certificates(ctx, pem_public_file, pem_private_file);

    if(!strcmp("sync", job_mode))
    {
        run_sync_mode(ctx, g_server, pem_public_file, pem_private_file);
    }
    else
    {
        run_async_mode(ctx, g_server, pem_public_file, pem_private_file);
    }

    SSL_CTX_free(ctx);  /* release context */

    return 0;
}
