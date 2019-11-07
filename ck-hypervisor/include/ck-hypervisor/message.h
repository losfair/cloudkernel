#pragma once

#include <stdint.h>
#include <sys/socket.h>
#include <string.h>
#include <ck-hypervisor/consts.h>

enum class MessageType {
    INVALID = 0,
    TRIVIAL_RESULT,
    MODULE_REQUEST,
    MODULE_OFFER,
    PROCESS_CREATE,
    PROCESS_OFFER,
    DEBUG_PRINT,
    PROCESS_WAIT,
    POLL,
    SERVICE_REGISTER,
    SERVICE_GET,
    IP_PACKET,
    IP_ADDRESS_REGISTER_V4,
    IP_ADDRESS_REGISTER_V6,
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

struct __attribute__((packed)) TrivialResult {
    int code = -1;
    char description[TRIVIAL_RESULT_DESCRIPTION_SIZE] = {};
    uint16_t description_len = 0;

    TrivialResult() {}

    TrivialResult(int code, const char *msg) {
        this->code = code;

        int len = strlen(msg);
        if(len > sizeof(this->description) - 1) {
            len = sizeof(this->description) - 1;
        }

        memcpy(this->description, msg, len);
        this->description_len = len;
    }

    bool validate() const {
        if(description_len > sizeof(description) - 1) {
            return false;
        }

        return true;
    }

    Message kernel_message() const {
        Message msg;
        msg.tag = MessageType::TRIVIAL_RESULT;
        msg.body = (const uint8_t *) this;
        msg.body_len = sizeof(TrivialResult);
        return msg;
    }
};
