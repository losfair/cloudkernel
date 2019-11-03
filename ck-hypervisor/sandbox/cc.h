#pragma once

#include <stdint.h>
#include <sys/types.h>

typedef __uint128_t ck_pid_t;

extern int hypervisor_fd;
extern unsigned long text_end;
extern unsigned long mmap_end;
extern bool sandbox_privileged;

int kDebugLog(const char *data, size_t n);
int kSendMessage(const ck_pid_t *recipient, uint64_t session, uint32_t tag, const uint8_t *data, size_t n);
int kRecvMessage(ck_pid_t *sender, uint64_t *session, uint32_t *tag, uint8_t *data, size_t n);

void * uMapHeap(size_t n);

#define TEXT_BASE 0x60000000ull
#define MMAP_BASE 0x3000000000ull
#define STACK_TOP 0x8000000000ull
#define STACK_SIZE 1048576 * 512 // Only virtual memory size; not actually allocated until used.
