#pragma once

#include <ck-hypervisor/registry.h>
#include <memory>
#include <functional>
#include <string>
#include <sys/types.h>

#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)

class DynamicModule {
    private:
    std::unique_ptr<ModuleHandle> module_handle;

    public:
    int fd = -1;
    size_t module_size = 0;
    std::string module_type;

    DynamicModule(const char *name, VersionCode version);
    DynamicModule(const DynamicModule& that) = delete;
    DynamicModule(DynamicModule&& that) = delete;
    virtual ~DynamicModule();
};
