# bind_to_ip
Uses LD_PRELOAD to hijack connect() calls and to bind connections to one of outgoing IP addresses from the list. All parameters are loaded from environmental variables:
BIP_IP=<IP,IP,...>      Comma separated list of IP address to choose from in round-robin fashion as outgoing IP when user's application calls connect().
BIP_EXCLUDE<IP,IP,...>  Comma separated list of IP address to exclude from binding to one of IPs from BIP_IP list. Usually, it's a good idea to define "127.0.0.1,127.0.0.53" as default value.
BIP_ID=[integer]        (optional; defaults to PID). Creates a group identified by given number. It forces all processes within the group to use the same round-robin index to choose IPs.

# Compilation
gcc -nostartfiles -O2 -Wall -fvisibility=hidden -fpic -shared bind_to_ip.c -o bind_to_ip.so -ldl -lrt

# Usage examples
env BIP_ID=11 BIP_EXCLUDE=127.0.0.1,127.0.0.53 BIP_IP=10.0.5.247,10.0.13.99,10.0.15.189 LD_PRELOAD=./bind_to_ip.so sleep 60 &
env BIP_ID=11 LD_PRELOAD=./bind_to_ip.so curl ifconfig.me ; echo
54.x.y.53
env BIP_ID=11 LD_PRELOAD=./bind_to_ip.so curl ifconfig.me ; echo
194.x.y.173

env BIP_EXCLUDE=127.0.0.1,127.0.0.53 BIP_IP=10.0.5.247,10.0.13.99,10.0.15.189 LD_PRELOAD=./bind_to_ip.so curl --location -o /dev/null google.com
