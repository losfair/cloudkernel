#pragma once

#include <ck-hypervisor/fdset.h>
#include <ck-hypervisor/message.h>
#include <unistd.h>
#include <vector>

class OwnedMessage {
public:
  __uint128_t sender_or_recipient = 0;
  uint64_t session = 0;
  MessageType tag = MessageType::INVALID;
  std::vector<uint8_t> body;
  std::unique_ptr<FdSet> fds;

  OwnedMessage() {}
  OwnedMessage(const OwnedMessage &that) = delete;
  OwnedMessage(OwnedMessage &&that) {
    sender_or_recipient = that.sender_or_recipient;
    session = that.session;
    tag = that.tag;
    body = std::move(that.body);
    fds = std::move(that.fds);
  }

  Message borrow() const {
    Message msg;
    msg.sender_or_recipient = sender_or_recipient;
    msg.session = session;
    msg.tag = tag;
    msg.body = body.size() ? &body[0] : nullptr;
    msg.body_len = body.size();
    msg.fds = &*fds;
    return msg;
  }
};
