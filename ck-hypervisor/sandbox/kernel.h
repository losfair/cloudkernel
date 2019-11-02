#pragma once

#include <stdint.h>
#include <sys/types.h>

extern int hypervisor_fd;

int kDebugLog(const char *data, size_t n);
int kSendMessage(const uint8_t *data, size_t n);
int kRecvMessage(uint8_t *data, size_t n);
