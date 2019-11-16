#pragma once

#include <ck-hypervisor/registry.h>
#include <functional>
#include <memory>
#include <string>
#include <sys/types.h>

class DynamicModule {
private:
  std::unique_ptr<ModuleHandle> module_handle;

public:
  int fd = -1;
  size_t module_size = 0;
  std::string module_type;

  DynamicModule(const char *name, VersionCode version);
  DynamicModule(const DynamicModule &that) = delete;
  DynamicModule(DynamicModule &&that) = delete;
  virtual ~DynamicModule();
};
