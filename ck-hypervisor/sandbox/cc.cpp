#include "./cc.h"
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/mman.h>

int kSendMessage(const uint8_t *data, size_t n) {
    return send(hypervisor_fd, (void *) data, n, 0);
}

int kRecvMessage(uint8_t *data, size_t n) {
    return recv(hypervisor_fd, (void *) data, n, 0);
}

void * uMapHeap(size_t n) {
    unsigned long result = (unsigned long) mmap((void *) ((uint8_t *) mmap_end), n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if(result == (unsigned long) -1ll) return (void *) result;
    mmap_end += n;
    return (void *) result;
}
