#pragma once

#include <ck-hypervisor/message.h>
#include <vector>

class OwnedMessage {
    public:
    __uint128_t sender_or_recipient = 0;
    uint64_t session = 0;
    MessageType tag = MessageType::INVALID;
    std::vector<uint8_t> body;

    OwnedMessage() {}

    Message borrow() const {
        Message msg;
        msg.sender_or_recipient = sender_or_recipient;
        msg.session = session;
        msg.tag = tag;
        msg.body = body.size() ? &body[0] : nullptr;
        msg.body_len = body.size();
        return msg;
    }
};
