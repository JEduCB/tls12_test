#include <stdio.h>

int run_server(const char* port, const char* job_mode, const char* payload, const char* pem_public_file, const char* pem_private_file);

int main (int argc, char **argv)
{
    if (argc != 4)
    {
        printf("Usage: %s <portnum> <sync | async> <payload>\n", argv[0]);
        return 1;
    }

    run_server(argv[1], argv[2], argv[3], "yarp.qat+5.pem", "yarp.qat+5-key.pem");

    return 0;
}