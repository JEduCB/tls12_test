#include <errno.h>
#include <malloc.h>
#include <netdb.h>
#include <omp.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

 #include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_PAYLOAD (1024 * 1024)

#define LOCAL_ABORT()                                  \
do                                                     \
{                                                      \
    printf("Abort at %s:%d\n", __FILE__, __LINE__);    \
    abort();                                           \
} while (0)

int OpenConnection(const char *hostname, uint16_t port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        LOCAL_ABORT();
    }

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        close(sd);
        perror(hostname);
        fprintf(stderr, "Cannot connect to the server on port (%d).\n", port);
        LOCAL_ABORT();
    }

    return sd;
}

SSL_CTX* InitCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();     /* Create new client-method instance */
    ctx = SSL_CTX_new(method);        /* Create new context */

    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        LOCAL_ABORT();
    }

    return ctx;
}

void process_request(const char *hostname, uint16_t portnum, SSL_CTX* ctx, char* cipher, int* response_size)
{
    char buf[MAX_PAYLOAD + 128 + 1] = {0};
    int bytes = {0};

    int server = OpenConnection(hostname, portnum);

    SSL* ssl = SSL_new(ctx);    /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */

    if (SSL_connect(ssl) <= 0)  /* perform the connection */
    {
        ERR_print_errors_fp(stderr);
        printf("TLS handshake has failed.\n");
    }
    else
    {      
        if(cipher)
        {
            strcpy(cipher, SSL_get_cipher(ssl));
        }

        sprintf(buf, 
            "GET / HTTP/1.1\r\n"
            "User-Agent: Wget/1.17.1 (linux-gnu)\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Host: %s:%d\r\n"
            "\r\n", hostname, portnum);

        SSL_write(ssl, buf, strlen(buf));          /* encrypt & send message */

        bytes = SSL_read(ssl, buf, sizeof(buf));   /* get reply & decrypt */      
        buf[bytes] = 0;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);        /* release connection state */
    close(server);        /* close socket */

    if(!bytes) //Some error's ocurred
    {
        LOCAL_ABORT();
    }

    if(response_size)
    {
        *response_size = bytes;
    }
}

void run_client(const char *hostname, uint16_t portnum, int iterations, int concurrent_iterations)
{   
    int count = 0;
    int show_partial_count_at = iterations < 100 ? 10 : iterations < 1000 ? 100 : iterations / 10;
    char cipher[128] = {0};
    int bytes = 0;

    SSL_CTX* ctx = InitCTX();
    process_request(hostname, portnum, ctx, cipher, &bytes); //Make a request just to get the cipher description
   
    SSL_CTX_free(ctx);      /* release context */

    while(iterations)
    {
        pid_t _pid[concurrent_iterations];

        for(int i = 0; i < concurrent_iterations; ++i)
        {
            pid_t pid = fork();

            if(pid == 0)
            {
                SSL_CTX* ctx = InitCTX();
                process_request(hostname, portnum, ctx, NULL, NULL);
                SSL_CTX_free(ctx);      /* release context */
                exit(0);
            }        

            _pid[i] = pid;
            ++count;
        }

        for(int i = 0; i < concurrent_iterations; ++i)
        {
            waitpid(_pid[i], NULL, 0);
        }

        if(!(count % show_partial_count_at))
        {
            printf("%d connections completed\n", count);
        }

        if(iterations >= concurrent_iterations)
        {
            iterations -= concurrent_iterations;

            if(iterations > 0 && iterations < concurrent_iterations)
            {
                concurrent_iterations = iterations;
            }
        }
    }

    printf("\nTotal of %d connections completed\nResponse size in bytes = %d\n", count, bytes); 

    if(cipher[0])
    {
        printf("Connected using %s encryption\n", cipher);
    }
}

int main(int argc, char **argv)
{
    char *hostname;
    uint16_t portnum;
    int iterations;
    int concurrent_iterations;

    // if (argc != 4)
    // {
    //     printf("usage: %s <hostname> <portnum> <iterations>\n", argv[0]);
    //     exit(1);
    // }

    if (argc != 5)
    {
        printf("usage: %s <hostname> <portnum> <iterations> <concurrent_iterations>\n", argv[0]);
        exit(1);
    }

    hostname = argv[1];
    portnum = atoi(argv[2]);
    iterations = atoi(argv[3]);
    concurrent_iterations = atoi(argv[4]);

    if(iterations <= 0)
    {
        printf("Invalid iteration number = %d\n", iterations);
        exit(1);
    }

    if(concurrent_iterations <= 0 || concurrent_iterations > iterations)
    {
        printf("Invalid concurrent number\n1 <= concurrent_iteration <= %d\n", iterations);
        exit(1);
    }

    struct timespec begin, end; 
    clock_gettime(CLOCK_REALTIME, &begin);

    // Initialize the SSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();     /* Load cryptos, et.al. */
    SSL_load_error_strings();         /* Bring in and register error messages */

    run_client(hostname, portnum, iterations, concurrent_iterations);

    clock_gettime(CLOCK_REALTIME, &end);

    long seconds = end.tv_sec - begin.tv_sec;
    long nanoseconds = end.tv_nsec - begin.tv_nsec;
    double elapsed = seconds + nanoseconds*1e-9;    

    printf("Elapsed time = %f seconds\n\n", elapsed);

    return 0;
}
