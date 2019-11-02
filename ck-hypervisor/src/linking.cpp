#include <ck-hypervisor/linking.h>
#include <ck-hypervisor/registry.h>
#include <sys/mman.h>
#include <vector>
#include <unistd.h>
#include <iterator>
#include <stdexcept>
#include <fcntl.h>
#include <stdlib.h>
#include <map>
#include <string>
#include <mutex>
#include <iostream>
#include <string.h>

DynamicModule::DynamicModule(const char *name, VersionCode version) {
    auto handle = global_registry.get_module(name, version);
    size_t body_size = handle->get_file_size() - handle->get_metadata_size();
    module_size = round_up(body_size, getpagesize());

    mfd = memfd_create("dynamic-module", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if(mfd < 0) throw std::runtime_error("unable to create shared memory");

    if(ftruncate(mfd, module_size) < 0) {
        close(mfd);
        throw std::runtime_error("unable to set size for shared memory");
    }
    uint8_t *mapped = (uint8_t *) mmap(nullptr, module_size, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
    if(!mapped) {
        close(mfd);
        throw std::runtime_error("mmap on shared memory failed");
    }

    if(handle->read(mapped, body_size) != body_size) {
        munmap(mapped, module_size);
        close(mfd);
        throw std::runtime_error("unable to read module from file");
    }

    munmap(mapped, module_size);
    metadata = handle->metadata;

    if(fcntl(mfd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_WRITE | F_SEAL_SEAL) < 0) {
        close(mfd);
        throw std::runtime_error("unable to add seals");
    }

}

DynamicModule::~DynamicModule() {
    close(mfd);
}

static std::map<std::pair<std::string, VersionCode>, std::shared_ptr<DynamicModule>> dm_cache;
static std::mutex dm_cache_mu;

std::shared_ptr<DynamicModule> DynamicModule::load_cached(const char *name, VersionCode version) {
    std::lock_guard<std::mutex> lg(dm_cache_mu);

    auto key = std::make_pair(std::string(name), version);
    auto it = dm_cache.find(key);
    if(it != dm_cache.end()) {
        return it->second;
    } else {
        auto v = std::shared_ptr<DynamicModule>(new DynamicModule(name, version));
        dm_cache[key] = v;
        return std::move(v);
    }
}
