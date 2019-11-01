#pragma once

#include <string>
#include <unistd.h>
#include <stdint.h>
#include <vector>
#include <memory>
#include <ck-hypervisor/symbol.h>
#include <ck-hypervisor/metadata.h>

class ModuleHandle {
    public:
    int module_fd = -1;
    size_t file_size = 0, metadata_size = 0;
    ModuleMetadata metadata;

    ModuleHandle(int new_fd);
    ModuleHandle(const ModuleHandle& that) = delete;
    ModuleHandle(ModuleHandle&& that) = delete;
    virtual ~ModuleHandle();

    inline size_t get_file_size() {
        return file_size;
    }

    inline size_t get_metadata_size() {
        return metadata_size;
    }

    inline ssize_t read(uint8_t *out, size_t count) {
        return ::read(module_fd, (void *) out, count);
    }
};

class Registry {
    private:
    std::string prefix;

    public:
    Registry();
    Registry(const Registry& that) = delete;
    Registry(Registry&& that) = delete;
    virtual ~Registry();

    inline void set_prefix(const std::string& new_prefix) {
        prefix = new_prefix;
    }

    std::unique_ptr<ModuleHandle> get_module(const char *name, VersionCode version);
};

extern Registry global_registry;
