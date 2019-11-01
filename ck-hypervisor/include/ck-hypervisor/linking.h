#pragma once

#include <ck-hypervisor/registry.h>
#include <memory>

#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)

class DynamicModule {
    private:

    public:
    int mfd = -1;
    size_t module_size = 0;
    ModuleMetadata metadata;

    DynamicModule(const char *name, VersionCode version);
    DynamicModule(const DynamicModule& that) = delete;
    DynamicModule(DynamicModule&& that) = delete;
    virtual ~DynamicModule();

    static std::shared_ptr<DynamicModule> load_cached(const char *name, VersionCode version);
};
