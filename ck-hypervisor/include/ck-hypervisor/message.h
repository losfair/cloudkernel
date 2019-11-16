#pragma once

#include <ck-hypervisor/consts.h>
#include <ck-hypervisor/fdset.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <vector>

enum class MessageType {
  INVALID = 0,
  TRIVIAL_RESULT,
  MODULE_REQUEST,
  MODULE_OFFER,
  PROCESS_CREATE,
  PROCESS_OFFER,
  PROCESS_WAIT,
  POLL,
  SNAPSHOT_CREATE,
  PROCESS_COMPLETION,
  IP_QUEUE_OPEN,
  IP_QUEUE_OFFER,
};

class Message {
public:
  __uint128_t sender_or_recipient = 0;
  uint64_t session = 0;
  MessageType tag = MessageType::INVALID;
  const uint8_t *body = nullptr;
  size_t body_len = 0;
  const FdSet *fds = nullptr;

  int send(int socket) {
    uint32_t raw_tag = (uint32_t)tag;

    struct iovec parts[4];

    parts[0].iov_base = (void *)&sender_or_recipient;
    parts[0].iov_len = sizeof(__uint128_t);
    parts[1].iov_base = (void *)&session;
    parts[1].iov_len = sizeof(uint64_t);
    parts[2].iov_base = (void *)&raw_tag;
    parts[2].iov_len = sizeof(uint32_t);
    parts[3].iov_base = (void *)body;
    parts[3].iov_len = body_len;

    struct msghdr out_hdr = {.msg_iov = parts, .msg_iovlen = 4};
    std::vector<char> control_buf;

    if (fds) {
      control_buf.resize(CMSG_SPACE(fds->fds.size() * sizeof(int)));

      cmsghdr *cmsg = (cmsghdr *)&control_buf[0];
      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_RIGHTS;
      cmsg->cmsg_len = CMSG_LEN(fds->fds.size() * sizeof(int));

      int *fds_raw = (int *)CMSG_DATA(cmsg);
      size_t pos = 0;

      for (int fd : fds->fds) {
        fds_raw[pos++] = fd;
      }

      out_hdr.msg_control = &control_buf[0];
      out_hdr.msg_controllen = control_buf.size();
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
    if (len > sizeof(this->description) - 1) {
      len = sizeof(this->description) - 1;
    }

    memcpy(this->description, msg, len);
    this->description_len = len;
  }

  bool validate() const {
    if (description_len > sizeof(description) - 1) {
      return false;
    }

    return true;
  }

  Message kernel_message() const {
    Message msg;
    msg.tag = MessageType::TRIVIAL_RESULT;
    msg.body = (const uint8_t *)this;
    msg.body_len = sizeof(TrivialResult);
    return msg;
  }
};
