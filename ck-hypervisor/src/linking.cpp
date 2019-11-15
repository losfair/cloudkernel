#include <ck-hypervisor/linking.h>
#include <ck-hypervisor/registry.h>
#include <fcntl.h>
#include <iostream>
#include <iterator>
#include <map>
#include <mutex>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

DynamicModule::DynamicModule(const char *name, VersionCode version) {
  module_handle = global_registry.get_module(name, version);
  module_type = module_handle->module_type;
  module_size = module_handle->get_file_size();
  fd = module_handle->module_fd;
}

DynamicModule::~DynamicModule() {
  // `fd` is closed by `module_handle` destructor
}
