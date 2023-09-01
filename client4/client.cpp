#include <algorithm>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <vector>

//#define MAX_PAYLOAD (1024 * 1024)
#define NUM_TESTS   5

int g_requests_count;
int g_response_size;
char g_cipher[128 + 1];
char g_protocol[32 + 1];
int g_pk_bits;
int g_sk_bits;
char g_get_cipher_info = 1;

#define LOCAL_ABORT()                                  \
do                                                     \
{                                                      \
    printf("Abort at %s:%d\n", __FILE__, __LINE__);    \
    abort();                                           \
} while (0)

SSL_CTX* InitCTX(char use_tls1_3)
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

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, !use_tls1_3 ? TLS1_2_VERSION : TLS_MAX_VERSION);
   
    return ctx;
}

struct thread_parameters
{
    const char *hostname;
    uint16_t portnum;
    SSL_CTX* ctx;
};    

void* process_request(void* args)
{
    long offset = {0};
    
    thread_parameters* params = (thread_parameters*)args;

    SSL* ssl = NULL;
    BIO* bio = BIO_new_ssl_connect(params->ctx);
    int ret;

    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    char szhostname[64] = {0};
    sprintf(szhostname, "%s:%d", params->hostname, params->portnum);

    BIO_set_conn_hostname(bio, szhostname);
    ret = BIO_do_connect(bio);

    if (ret <= 0)
    {
        fprintf(stderr, "BIO_do_connect failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto exit;
    }

    ret = SSL_do_handshake(ssl);

    if (ret <= 0)
    {
        fprintf(stderr, "SSL_do_handshake failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto exit;
    }

//char buf[MAX_PAYLOAD + 128 + 1]; //MAX_PAYLOAD and enough space for the HTTP header.
//     sprintf(buf, "GET / HTTP/1.1\r\n"
//         "User-Agent: Wget/1.17.1 (linux-gnu)\r\n"
//         "Accept: */*\r\n"
//         "Accept-Encoding: identity\r\n"
//         "Host: %s:%d\r\n"
//         "\r\n", params->hostname, params->portnum);

//     ret = SSL_write(ssl, buf, strlen(buf)); /* encrypt & send message */

//     if (ret <= 0)
//     {
//         fprintf(stderr, "SSL_write failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
//         goto exit;
//     }

//     do
//     {
//         ret = SSL_read(ssl, buf + offset, sizeof(buf) - offset);

//         if (ret <= 0)
//         {
//             fprintf(stderr, "SSL_read failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
//             goto exit;
//         }

//         offset += ret;
//         buf[offset] = 0;
//     } while (ret > 0);//!strstr(buf, "</html>\n"));

exit:
//     // if(!offset) //Some error's ocurred
//     // {
//     //     BIO_free_all(bio);
//     //     LOCAL_ABORT();
//     // }

    if(g_get_cipher_info)
    {
        g_get_cipher_info = 0;

        strcpy(g_cipher, SSL_get_cipher(ssl));
        strcpy(g_protocol, SSL_get_version(ssl));
        
        g_response_size = offset;
        g_sk_bits = SSL_CIPHER_get_bits(SSL_get_current_cipher(ssl), NULL);
        
        X509* cert = SSL_get_peer_certificate(ssl);

        g_pk_bits = 0;

        if(cert)
        {
            g_pk_bits = EVP_PKEY_bits(X509_get_pubkey(cert));
        }
    }

    BIO_free_all(bio);

    return NULL;
}

void run_client(const char *hostname, uint16_t portnum, int requests, int concurrent_requests, char use_tls1_3)
{   
    int count = 0;
    int show_partial_count_at = requests < 100 ? 10 : requests < 1000 ? 100 : requests / 10;
    int num_requests = requests;

    SSL_CTX* ctx = InitCTX(use_tls1_3);

    while(requests)
    {
        pthread_t threads[concurrent_requests];
        thread_parameters thread_params[concurrent_requests];

        for(int i = 0; i < concurrent_requests; ++i)
        {
            thread_params[i] = {hostname, portnum, ctx};
            pthread_create(&threads[i], NULL, process_request, (void*)&thread_params[i]);
            ++count;
        }

        for(int i = 0; i < concurrent_requests; ++i)
        {
            pthread_join(threads[i], NULL);
        }

        if(count != num_requests && !(count % show_partial_count_at))
        {
            printf("%d requests completed\n", count);
        }

        if(requests >= concurrent_requests)
        {
            requests -= concurrent_requests;

            if(requests > 0 && requests < concurrent_requests)
            {
                concurrent_requests = requests;
            }
        }
    }

    g_requests_count = count;
   
    SSL_CTX_free(ctx);      /* release context */
}

int main(int argc, char **argv)
{
    char *hostname;
    uint16_t portnum;
    int requests;
    int concurrent_requests;
    int iterations;
    char use_tls1_3 = false;
    char* protocol;
    const char* protocols[] = {"tls1_2", "tls1_3"};

    if (argc != 7)
    {
        printf("usage: %s <hostname> <portnum> <protocol> <iterations> <requests> <concurrent_requests>\n", argv[0]);
        printf("\tprotocol -> [%s | %s]\n", protocols[0], protocols[1]);
        exit(1);
    }

    hostname = argv[1];
    portnum = atoi(argv[2]);
    protocol = argv[3];
    iterations = atoi(argv[4]);
    requests = atoi(argv[5]);
    concurrent_requests = atoi(argv[6]);

    if(strcmp(protocol, protocols[0]) && strcmp(protocol, protocols[1]))
    {
        printf("Invalid protocol = %s\n", protocol);
        exit(1);
    }

    use_tls1_3 = !strcmp(protocol, protocols[1]);

    if(iterations <= 0)
    {
        iterations = NUM_TESTS;
    }

    if(requests <= 0)
    {
        printf("Invalid request number = %d\n", requests);
        exit(1);
    }

    if(concurrent_requests <= 0 || concurrent_requests > requests)
    {
        printf("Invalid concurrent value\n1 <= concurrent_requests <= %d\n", requests);
        exit(1);
    }

    double elapsed_client[iterations];

    g_requests_count = 0;
    g_response_size = 0;
    g_pk_bits = 0;
    g_sk_bits = 0;

    memset(g_cipher, 0, sizeof(g_cipher));
    memset(g_protocol, 0, sizeof(protocol));

    // Initialize the SSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();     /* Load cryptos, et.al. */
    SSL_load_error_strings();         /* Bring in and register error messages */

    SSL_CTX* ctx = InitCTX(use_tls1_3);
    thread_parameters params = {hostname, portnum, ctx};
    process_request(&params); //Make a request just to get protocol and cipher details
    SSL_CTX_free(ctx);
    
    struct timespec begin, end; 

    for(int i = 0; i < iterations; ++i)
    {
        printf("\nRunning test %d of %d\n", i + 1, iterations);

        clock_gettime(CLOCK_REALTIME, &begin);
        run_client(hostname, portnum, requests, concurrent_requests, use_tls1_3);
        clock_gettime(CLOCK_REALTIME, &end);

        long seconds = end.tv_sec - begin.tv_sec;
        long nanoseconds = end.tv_nsec - begin.tv_nsec;
        elapsed_client[i] = seconds + nanoseconds * 1e-9;    
        printf("Finished %d requests in %f seconds\n", g_requests_count, elapsed_client[i]);
    }

    printf("\nResponse size in bytes = %d\n", g_response_size); 
    printf("TLS Protocol: %s,%s,%d,%d\n", g_protocol, g_cipher, g_pk_bits, g_sk_bits);

    // printf("\nTest #,Runtime in seconds\n");

    // for(int i = 0; i < iterations; ++i)
    // {
    //     printf("%d,%f\n", i + 1, elapsed_client[i]);
    // }

    printf("\nRuntime in seconds\n");

    for(int i = 0; i < iterations; ++i)
    {
        printf("%f\n", elapsed_client[i]);
    }

    printf("\n");

    return 0;
}
