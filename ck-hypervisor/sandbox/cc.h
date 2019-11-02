#pragma once

#include <stdint.h>
#include <sys/types.h>

extern int hypervisor_fd;
extern unsigned long text_end;
extern unsigned long mmap_end;

int kDebugLog(const char *data, size_t n);
int kSendMessage(const uint8_t *data, size_t n);
int kRecvMessage(uint8_t *data, size_t n);

void * uMapHeap(size_t n);

#define TEXT_BASE 0x60000000ull
#define MMAP_BASE 0x3000000000ull
#define STACK_TOP 0x8000000000ull
#define STACK_SIZE 1048576 * 512 // Only virtual memory size; not actually allocated until used.
