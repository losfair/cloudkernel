#pragma once

#include <stdint.h>

struct __attribute__((packed)) OKOrReject {
    uint32_t Tag;
    char Message[256];
};

#define APIVER_ProcessCreationInfo 0x1

struct __attribute__((packed)) ProcessCreationInfo {
    uint32_t APIVersion;
    char FullName[256];
    int Privileged;
};

#define APIVER_ProcessOffer 0x1

struct __attribute__((packed)) ProcessOffer {
    uint32_t APIVersion;
    __uint128_t PID;
};

#define APIVER_ProcessWait 0x1

struct __attribute__((packed)) ProcessWait {
    uint32_t APIVersion;
    __uint128_t PID;
};
