#include "./kernel.h"
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>

int kDebugLog(const char *data, size_t n) {
    for(int i = 0; i < n; i++) putchar(data[i]);
    putchar('\n');
    return n;
}

int kSendMessage(const uint8_t *data, size_t n) {
    return send(hypervisor_fd, (void *) data, n, 0);
}

int kRecvMessage(uint8_t *data, size_t n) {
    return recv(hypervisor_fd, (void *) data, n, 0);
}
