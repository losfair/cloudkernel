#pragma once

#include <stdint.h>
#include <sys/socket.h>

enum class MessageType {
    INVALID = 0,
    MODULE_REQUEST,
    MODULE_OFFER,
    REJECT,
    PROCESS_CREATE,
    PROCESS_OFFER,
    DEBUG_PRINT,
    OK,
    PROCESS_WAIT,
};

class Message {
    public:
    __uint128_t sender_or_recipient = 0;
    uint64_t session = 0;
    MessageType tag = MessageType::INVALID;
    const uint8_t *body = nullptr;
    size_t body_len = 0;
    int fd = -1;

    int send(int socket) {
        uint32_t raw_tag = (uint32_t) tag;

        struct iovec parts[4];

        parts[0].iov_base = (void *) &sender_or_recipient;
        parts[0].iov_len = sizeof(__uint128_t);
        parts[1].iov_base = (void *) &session;
        parts[1].iov_len = sizeof(uint64_t);
        parts[2].iov_base = (void *) &raw_tag;
        parts[2].iov_len = sizeof(uint32_t);
        parts[3].iov_base = (void *) body;
        parts[3].iov_len = body_len;

        struct msghdr out_hdr = {
            .msg_iov = parts,
            .msg_iovlen = 4
        };
        char fdbuf[CMSG_SPACE(sizeof(int))] = {};

        if(this->fd >= 0) {
            out_hdr.msg_control = fdbuf;
            out_hdr.msg_controllen = sizeof(fdbuf);

            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&out_hdr);
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type = SCM_RIGHTS;
            cmsg->cmsg_len = CMSG_LEN(sizeof(this->fd));

            *((int *) CMSG_DATA(cmsg)) = this->fd;
        }

        return sendmsg(socket, &out_hdr, 0) <= 0 ? -1 : 0;
    }
};
