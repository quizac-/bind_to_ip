// #define DEBUG
#define _GNU_SOURCE
#define __USE_GNU

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <unistd.h>

// env BIP_ID=11 BIP_EXCLUDE=127.0.0.1,127.0.0.53 BIP_IP=10.0.5.247,10.0.13.99,10.0.15.189 LD_PRELOAD=./bind_to_ip.so curl --location -o /dev/null google.com


#define ATOMIC_GET(var)               __atomic_load_n(&(var), __ATOMIC_RELAXED)
#define ATOMIC_SET(var,val)           __atomic_store_n(&(var), val, __ATOMIC_RELAXED)
#define MAX_NUMBER_OF_IPS             256

typedef struct {
    int32_t             write_lock;
    int32_t             ips_elems;
    int32_t             ips_rr_idx;
    int32_t             excludes_elems;
    int32_t             id;
    in_addr_t           excludes_addrs[MAX_NUMBER_OF_IPS];
    in_addr_t           ips_addrs[MAX_NUMBER_OF_IPS];
} bip_data_t;

#define SHARED_MEM_SIZE (sizeof(bip_data_t))

static bip_data_t *bip_data = NULL;


static void bip_acquire_write_lock(void) {
    while (__sync_lock_test_and_set(&(bip_data->write_lock), 1));
}


static void bip_release_write_lock(void) {
    __sync_lock_release(&(bip_data->write_lock));
}


static in_addr_t bip_get_next_ip(void) {
    int idx;

    bip_acquire_write_lock();
    idx = ATOMIC_GET(bip_data->ips_rr_idx);
    ATOMIC_SET(bip_data->ips_rr_idx, (idx + 1) % ATOMIC_GET(bip_data->ips_elems));
    bip_release_write_lock();

    return ATOMIC_GET(bip_data->ips_addrs[idx]);
}


static void bip_load_excludes(void) {
    int elems       = 0;
    char *env_copy  = getenv("BIP_EXCLUDE");

    if ((env_copy != NULL) && (strlen(env_copy) > 0)) {
        env_copy = (char*)malloc(strlen(getenv("BIP_EXCLUDE")) * sizeof(char) + 1);
        strcpy(env_copy, getenv("BIP_EXCLUDE"));
        char *iplist;
        char sep[]  = ",";
        iplist      = strtok(env_copy, sep);

        for (elems=0; elems<MAX_NUMBER_OF_IPS; elems++) {
            if (iplist == NULL) {
                break;
            }
#           ifdef DEBUG
                fprintf(stderr, "BIP: Adding %s to excludes_addrs\n", iplist);
#           endif
            ATOMIC_SET(bip_data->excludes_addrs[elems], inet_addr(iplist));
            iplist = strtok(NULL, sep);
        }

        free(env_copy);
    } else {
        fprintf(stderr, "BIP: No BIP_EXCLUDE environmental variable set\n");
    }
    ATOMIC_SET(bip_data->excludes_elems, elems);

#   ifdef DEBUG
        fprintf(stderr, "BIP: Loaded %d IPs to excludes_addrs\n", ATOMIC_GET(bip_data->excludes_elems));
#   endif
}


static bool bip_ips_available(void) {
    if (bip_data == NULL) {
        return false;
    } else if (ATOMIC_GET(bip_data->ips_elems) == 0) {
        return false;
    } else {
        return true;
    }
}


static bool bip_ip_is_excluded(in_addr_t addr) {
    if (bip_data == NULL) {
        return false;
    } else if (ATOMIC_GET(bip_data->excludes_elems) == 0) {
        return false;
    }

    for (int idx=0; idx<ATOMIC_GET(bip_data->excludes_elems); idx++) {
        if (addr == ATOMIC_GET(bip_data->excludes_addrs[idx])) {
#           ifdef DEBUG
                fprintf(stderr, "BIP: IP excluded by IP-List idx=%d\n", idx);
#           endif
            return true;
        }
    }

    return false;
}


static void bip_load_ips(void) {
    int elems       = 0;
    char *env_copy  = getenv("BIP_IP");

    if ((env_copy != NULL) && (strlen(env_copy) > 0)) {
        char *iplist;
        char sep[] = ",";

        env_copy = (char*) malloc(strlen(getenv("BIP_IP")) * sizeof(char) + 1);
        strcpy(env_copy, getenv("BIP_IP"));
        iplist = strtok(env_copy, sep);

        for (elems=0; elems<MAX_NUMBER_OF_IPS; elems++) {
            if (iplist == NULL) {
                break;
            }
#           ifdef DEBUG
                fprintf(stderr, "BIP: Adding %s to bind_ips_addrs\n", iplist);
#           endif
            ATOMIC_SET(bip_data->ips_addrs[elems], inet_addr(iplist));
            iplist = strtok(NULL, sep);
        }

        free(env_copy);
    } else {
        fprintf(stderr, "BIP: No BIP_IP environmental variable set\n");
    }
    ATOMIC_SET(bip_data->ips_elems, elems);

#   ifdef DEBUG
        fprintf(stderr, "BIP: Loaded %d IPs to ips_addrs with PID=%d\n", elems, getpid());
#   endif
}


static void __attribute__ ((constructor)) bip_setup_shared_region() {
    char filename[32] = {0};
    int bip_id        = getpid();
    int shm_fd        = -1;
    char *env_copy    = getenv("BIP_ID");

    if (env_copy != NULL) {
        bip_id = atoi(env_copy);
    }

    snprintf(filename, 31, "/bip_shared%d", bip_id);

#   ifdef DEBUG
        fprintf(stderr, "BIP: bip_id=%d, filename=%s, size=%d\n", bip_id, filename, (int)SHARED_MEM_SIZE);
#   endif

    shm_fd = shm_open(filename, O_RDWR | O_CREAT, 0666);
    if (shm_fd == -1) {
        fprintf(stderr, "BIP: shm_open(): %d(%s)\n", errno, strerror(errno));
        return;
    }

    // Set the size of the shared memory segment
    if (ftruncate(shm_fd, SHARED_MEM_SIZE) != 0) {
        fprintf(stderr, "BIP: ftruncate(): %d(%s)\n", errno, strerror(errno));
        return;
    }

    /* map the shared memory segment to the address space of the process */
    bip_data = mmap(NULL, SHARED_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (bip_data == MAP_FAILED) {
        bip_data = NULL;
        close(shm_fd);
        fprintf(stderr, "BIP: Map failed: %d(%s)\n", errno, strerror(errno));
        return;
    }

    if (ATOMIC_GET(bip_data->id) == bip_id) {
#       ifdef DEBUG
            fprintf(stderr, "BIP: bip_data already initialized\n");
#       endif
        return;
    }

    bip_acquire_write_lock();
        ATOMIC_SET(bip_data->id, bip_id);
        bip_load_excludes();
        bip_load_ips();
    bip_release_write_lock();

#   ifdef DEBUG
        fprintf(stderr, "BIP: constructor setup_shared_region() OK\n");
#   endif
}


int __attribute__((visibility("default"))) connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    // [pid   163] connect(29, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("54.199.154.25")}, 16)
    int *(*original_connect)(int, const struct sockaddr *, socklen_t);
    original_connect = dlsym(RTLD_NEXT, "connect");

    static struct sockaddr_in *socketAddress;
    socketAddress = (struct sockaddr_in *)addr;

    if (socketAddress->sin_family == AF_INET) {
#       ifdef DEBUG
            char *dest = inet_ntoa(socketAddress->sin_addr); //with #include <arpa/inet.h>
            unsigned short port = ntohs(socketAddress->sin_port);
            fprintf(stderr, "BIP: connecting to: %s:%d\n", dest, port);
#       endif

        if (bip_data == NULL) {
            bip_setup_shared_region();
        }

        bool ip_excluded = bip_ip_is_excluded(socketAddress->sin_addr.s_addr);

        if (!ip_excluded) { //Don't bind when destination is localhost, because it couldn't be reached anymore
            struct sockaddr_in bound_address;
            int errorCode;
            socklen_t bound_len = sizeof(bound_address);

            errorCode = getsockname(sockfd, &bound_address, &bound_len);
            if (errorCode < 0) {
                perror("getsockname");
            };

#           ifdef DEBUG
                fprintf(stderr, "BIP: Orig bound IP: 0x%08x, port: %d\n", bound_address.sin_addr.s_addr, ntohs(bound_address.sin_port));
#           endif

            if (bip_ips_available()) {
                in_addr_t next_ip = bip_get_next_ip();
                if (bound_address.sin_addr.s_addr != next_ip) {
#                   ifdef DEBUG
                        fprintf(stderr, "BIP: Socket bound to 0x08%x. Binding to IP: 0x%08x\n", bound_address.sin_addr.s_addr, next_ip);
#                   endif
                    bound_address.sin_family        = AF_INET;
                    bound_address.sin_addr.s_addr   = next_ip;
                    bound_address.sin_port          = 0;
                    errorCode                       = bind(sockfd, &bound_address, bound_len);

                    if (errorCode < 0) {
                        //getsockopt should not fail
                        perror("bind");
                        return -1;
                    };
                }
            }
        }
    }

    return (uintptr_t)original_connect(sockfd, addr, addrlen);
}
