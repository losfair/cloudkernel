#pragma once

#include <stdint.h>

#define APIVER_ProcessCreationInfo 0x1

struct __attribute__((packed)) ProcessCreationInfo {
    uint32_t api_version;
    char full_name[256];
    int privileged;
};
