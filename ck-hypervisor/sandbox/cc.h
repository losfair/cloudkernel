#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <ck-hypervisor/memory_layout.h>

typedef __uint128_t ck_pid_t;

extern int hypervisor_fd;
extern unsigned long text_end;
extern unsigned long mmap_end;
extern bool sandbox_privileged;

int kDebugLog(const char *data, size_t n);
int kSendMessage(const ck_pid_t *recipient, uint64_t session, uint32_t tag, const uint8_t *data, size_t n);
int kRecvMessage(ck_pid_t *sender, uint64_t *session, uint32_t *tag, uint8_t *data, size_t n);

void * uMapHeap(size_t n);

#define _QUOTE(x) #x
#define _STR(x) _QUOTE(x)
