#g++ -g -I. -fPIC -shared server_lib.cpp -o server_lib.so
#cc -g server.c -o server -Wl,-rpath='$ORIGIN' -L. -l:server_lib.so -L/lib/x86_64-linux-gnu -l:libssl.so -l:libcrypto.so

g++ -g -I. -fPIC -shared server_lib.cpp -o server_lib.so -Wl,-rpath='$ORIGIN' -L/lib/x86_64-linux-gnu -l:libssl.so -l:libcrypto.so
cc -g server.c -o server -Wl,-rpath='$ORIGIN' -L. -l:server_lib.so
