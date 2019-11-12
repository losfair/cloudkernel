#pragma once

#include <vector>
#include <stdint.h>
#include <string>
#include <sys/user.h>
#include <functional>
#include "file_base.h"
#include "snapshot_base.h"

class MemoryRangeSnapshot {
    public:
    uint64_t start = 0;
    std::function<void(uint8_t *)> data_feed;
    size_t data_len = 0;
    int prot = 0;
    MemoryRangeType ty = MemoryRangeType::INVALID;
};

class FileSnapshot {
    public:
    int fd = -1;
    std::string path;
    uint64_t offset = 0;
    bool user = false;
    int flags = 0;
};

class ProcessSnapshot {
    public:
    bool notify_invalid_syscall = false;
    user_regs_struct regs = {};
    std::vector<MemoryRangeSnapshot> memory;
    std::vector<FileSnapshot> files;

    std::vector<uint8_t> serialize() const;
};
