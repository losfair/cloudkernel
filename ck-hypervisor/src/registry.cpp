#include <ck-hypervisor/config.h>
#include <ck-hypervisor/linking.h>
#include <ck-hypervisor/symbol.h>
#include <fcntl.h>
#include <filesystem>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <unistd.h>

static bool validate_module_name(const char *name) {
  for (; *name; name++) {
    if (*name >= '0' && *name <= '9')
      continue;
    if (*name >= 'a' && *name <= 'z')
      continue;
    if (*name >= 'A' && *name <= 'Z')
      continue;
    if (*name == '-')
      continue;
    if (*name == ':')
      continue;
    return false;
  }
  return true;
}

ModuleHandle::ModuleHandle(int new_fd, const char *ty) {
  module_fd = new_fd;
  module_type = ty;
  lseek(module_fd, 0, SEEK_END);
  file_size = lseek(module_fd, 0, SEEK_CUR);
  lseek(module_fd, 0, SEEK_SET);
}

ModuleHandle::~ModuleHandle() {
  if (module_fd != -1)
    close(module_fd);
}

Registry::Registry() {}
Registry::~Registry() {}

static ModuleHandle *try_open_module(const std::filesystem::path &prefix,
                                     const char *name, VersionCode version) {
  {
    std::stringstream filename_builder;
    filename_builder << name << "_" << version.major << "." << version.minor
                     << "." << version.patch << ".elf";
    std::filesystem::path full_path = prefix;
    full_path /= filename_builder.str();
    if (int fd = open(full_path.c_str(), O_RDONLY | O_CLOEXEC); fd >= 0) {
      return new ModuleHandle(fd, "elf");
    }
  }

  {
    std::filesystem::path full_path = prefix;
    full_path /= std::string(name) + ".snapshot";
    if (int fd = open(full_path.c_str(), O_RDONLY | O_CLOEXEC); fd >= 0) {
      return new ModuleHandle(fd, "snapshot");
    }
  }

  return nullptr;
}
std::unique_ptr<ModuleHandle> Registry::get_module(const char *name,
                                                   VersionCode version) {
  if (!validate_module_name(name))
    throw std::runtime_error("invalid module name");
  std::lock_guard<std::mutex> lg(this->mu);
  auto module = try_open_module(prefix, name, version);
  if (!module) {
    throw std::runtime_error("unable to open module");
  }
  return std::unique_ptr<ModuleHandle>(module);
}

void Registry::save_module(const char *name, std::optional<VersionCode> version,
                           const char *suffix, const uint8_t *code,
                           size_t code_len) {
  if (!validate_module_name(name))
    throw std::runtime_error("invalid module name");
  std::lock_guard<std::mutex> lg(this->mu);

  std::stringstream filename_builder;
  filename_builder << name;
  if (version) {
    filename_builder << "_" << version->major << "." << version->minor << "."
                     << version->patch;
  }
  filename_builder << "." << suffix;

  std::filesystem::path path = prefix;
  path += filename_builder.str();

  std::string path_s_tmp = path.string() + ".tmp";
  unlink(path_s_tmp.c_str());

  int fd =
      open(path_s_tmp.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC,
           S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
  if (fd < 0) {
    throw std::runtime_error("cannot open output file");
  }
  if (ftruncate(fd, code_len) != 0) {
    close(fd);
    unlink(path_s_tmp.c_str());
    throw std::runtime_error("cannot set output file size");
  }
  while (code_len) {
    ssize_t written = write(fd, (const void *)code, code_len);
    if (written <= 0) {
      close(fd);
      unlink(path_s_tmp.c_str());
      throw std::runtime_error("write() failed");
    }
    code += written;
    code_len -= written;
  }
  close(fd);

  std::string path_s = path.string();
  unlink(path_s.c_str());
  if (rename(path_s_tmp.c_str(), path_s.c_str()) < 0) {
    unlink(path_s_tmp.c_str());
    throw std::runtime_error("rename() failed");
  }
  unlink(path_s_tmp.c_str());
}

Registry global_registry;
