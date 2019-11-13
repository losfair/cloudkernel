#pragma once

#include <string>
#include <unistd.h>
#include <stdint.h>
#include <vector>
#include <memory>
#include <mutex>
#include <ck-hypervisor/symbol.h>
#include <ck-hypervisor/metadata.h>

class ModuleHandle {
    public:
    int module_fd = -1;
    size_t file_size = 0;
    std::string module_type;

    ModuleHandle(int new_fd, const char *ty);
    ModuleHandle(const ModuleHandle& that) = delete;
    ModuleHandle(ModuleHandle&& that) = delete;
    virtual ~ModuleHandle();

    inline size_t get_file_size() {
        return file_size;
    }

    inline ssize_t read(uint8_t *out, size_t count) {
        return ::read(module_fd, (void *) out, count);
    }
};

class Registry {
    private:
    std::mutex mu;
    std::string prefix;

    public:
    Registry();
    Registry(const Registry& that) = delete;
    Registry(Registry&& that) = delete;
    virtual ~Registry();

    inline void set_prefix(const std::string& new_prefix) {
        mu.lock();
        prefix = new_prefix;
        mu.unlock();
    }

    std::unique_ptr<ModuleHandle> get_module(const char *name, VersionCode version);
    void save_module(const char *name, std::optional<VersionCode> version, const char *suffix, const uint8_t *code, size_t code_len);
};

extern Registry global_registry;
