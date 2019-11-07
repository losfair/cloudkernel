#include <ck-hypervisor/linking.h>
#include <ck-hypervisor/config.h>
#include <ck-hypervisor/symbol.h>
#include <stdexcept>
#include <sstream>
#include <unistd.h>
#include <fcntl.h>
#include <memory>

static bool validate_module_name(const char *name) {
    for(; *name; name++) {
        if(*name >= '0' && *name <= '9') continue;
        if(*name >= 'a' && *name <= 'z') continue;
        if(*name >= 'A' && *name <= 'Z') continue;
        if(*name == '-') continue;
        return false;
    }
    return true;
}

ModuleHandle::ModuleHandle(int new_fd) {
    module_fd = new_fd;
    lseek(module_fd, 0, SEEK_END);
    file_size = lseek(module_fd, 0, SEEK_CUR);
    lseek(module_fd, 0, SEEK_SET);
}

ModuleHandle::~ModuleHandle() {
    if(module_fd != -1) close(module_fd);
}

Registry::Registry() {}
Registry::~Registry() {}

std::unique_ptr<ModuleHandle> Registry::get_module(const char *name, VersionCode version) {
    if(!validate_module_name(name)) throw std::runtime_error("invalid module name");

    std::lock_guard<std::mutex> lg(this->mu);

    std::stringstream filename_builder;
    filename_builder << prefix << name << "_" << version.major << "." << version.minor << "." << version.patch << ".elf";
    std::string filename = filename_builder.str();

    int fd = open(filename.c_str(), O_RDONLY | O_CLOEXEC);
    if(fd < 0) throw std::runtime_error("unable to open file for module");

    std::unique_ptr<ModuleHandle> handle(new ModuleHandle(fd));
    return handle;
}

Registry global_registry;
