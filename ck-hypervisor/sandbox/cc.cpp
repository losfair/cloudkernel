#include "./cc.h"
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/mman.h>

int kSendMessage(const ck_pid_t *recipient, uint64_t session, uint32_t tag, const uint8_t *data, size_t n) {
    struct iovec parts[4];

    parts[0].iov_base = (void *) recipient;
    parts[0].iov_len = sizeof(ck_pid_t);
    parts[1].iov_base = (void *) &session;
    parts[1].iov_len = sizeof(uint64_t);
    parts[2].iov_base = (void *) &tag;
    parts[2].iov_len = sizeof(uint32_t);
    parts[3].iov_base = (void *) data;
    parts[3].iov_len = n;

    struct msghdr hdr = {
        .msg_iov = parts,
        .msg_iovlen = 4
    };

    int header_len = parts[0].iov_len + parts[1].iov_len + parts[2].iov_len;
    int ret = sendmsg(hypervisor_fd, &hdr, 0);
    if(ret < header_len) return -1;
    return ret - header_len;
}

int kRecvMessage(ck_pid_t *sender, uint64_t *session, uint32_t *tag, uint8_t *data, size_t n) {
    struct iovec parts[4];

    parts[0].iov_base = (void *) sender;
    parts[0].iov_len = sizeof(ck_pid_t);
    parts[1].iov_base = (void *) session;
    parts[1].iov_len = sizeof(uint64_t);
    parts[2].iov_base = (void *) tag;
    parts[2].iov_len = sizeof(uint32_t);
    parts[3].iov_base = (void *) data;
    parts[3].iov_len = n;

    struct msghdr hdr = {
        .msg_iov = parts,
        .msg_iovlen = 4
    };

    int header_len = parts[0].iov_len + parts[1].iov_len + parts[2].iov_len;
    int ret = recvmsg(hypervisor_fd, &hdr, 0);
    if(ret < header_len) return -1;
    return ret - header_len;
}

void * uMapHeap(size_t n) {
    unsigned long result = (unsigned long) mmap((void *) ((uint8_t *) mmap_end), n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if(result == (unsigned long) -1ll) return (void *) result;
    mmap_end += n;
    return (void *) result;
}
