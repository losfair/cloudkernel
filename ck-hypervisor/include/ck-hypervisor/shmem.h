#pragma once

#include <sys/types.h>

class SharedMemory {
private:
    int mfd = -1;
    size_t size = 0;
    bool remote_ro = false;
    void *mapping = nullptr;

public:
    SharedMemory(size_t new_size, bool new_remote_ro);
    SharedMemory(const SharedMemory& that) = delete;
    SharedMemory(SharedMemory&& that) = delete;

    virtual ~SharedMemory();

    inline size_t get_size() const {
        return size;
    }
    inline void * get_mapping() const {
        return mapping;
    }

    int create_remote_handle();
};
