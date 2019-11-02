#pragma once

#include <stdint.h>

#define APIVER_ProcessCreationInfo 0x1

struct __attribute__((packed)) ProcessCreationInfo {
    uint32_t api_version;
    char full_name[256];
    int privileged;
};

#define APIVER_ProcessOffer 0x1

struct __attribute__((packed)) ProcessOffer {
    uint32_t api_version;
    __uint128_t pid;
};

struct __attribute__((packed)) ProcessOfferMessage {
    uint32_t tag;
    ProcessOffer offer;
};

#define APIVER_ProcessWait 0x1

struct __attribute__((packed)) ProcessWait {
    uint32_t api_version;
    __uint128_t pid;
};
