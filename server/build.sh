cc -g -fPIC -shared server_lib.c -o server_lib.so
cc -g server.c -o server -Wl,-rpath='$ORIGIN' -L. -l:server_lib.so -L/lib/x86_64-linux-gnu -l:libssl.so -l:libcrypto.so
