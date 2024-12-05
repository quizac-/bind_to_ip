# bind_to_ip
Uses LD_PRELOAD to hijack connect() calls to bind connection to one of outgoing IP addresses from the list

# Compilation
gcc -nostartfiles -O2 -Wall -fvisibility=hidden -fpic -shared bind_to_ip.c -o bind_to_ip.so -ldl
