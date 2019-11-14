#pragma once

#include <stdint.h>

#define APIVER_ProcessCreationInfo 0x1

struct __attribute__((packed)) RemoteString {
    unsigned long rptr;
    uint64_t len;
};

struct __attribute__((packed)) ProcessCreationInfo {
    uint32_t api_version;
    uint32_t argc;
    unsigned long argv;
};

#define APIVER_ProcessOffer 0x1

struct __attribute__((packed)) ProcessOffer {
    uint32_t api_version;
    __uint128_t pid;
};

#define APIVER_ProcessWait 0x1

struct __attribute__((packed)) ProcessWait {
    uint32_t api_version;
    __uint128_t pid;
};
