#pragma once

#include <stdint.h>
#include <sys/socket.h>
#include <vector>

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
    MessageType ty;
    const uint8_t *body = nullptr;
    size_t body_len = 0;
    int fd = -1;

    int send(int socket) {
        std::vector<uint8_t> payload(4 + this->body_len);
        * (uint32_t *) &payload[0] = (uint32_t) this->ty;
        std::copy(this->body, this->body + this->body_len, &payload[4]);

        struct iovec out_iov = { .iov_base = &payload[0], .iov_len = payload.size() };
        struct msghdr out_hdr = {
            .msg_iov = &out_iov,
            .msg_iovlen = 1,
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

        return sendmsg(socket, &out_hdr, 0);
    }
};
