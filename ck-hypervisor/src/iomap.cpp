#include <ck-hypervisor/iomap.h>
#include <fcntl.h>

void IOMap::setup_defaults() {
    std::lock_guard<std::mutex> lg(mu);
    fd_map[next_fd++] = FileDescription::with_idmap(0);
    fd_map[next_fd++] = FileDescription::with_idmap(1);
    fd_map[next_fd++] = FileDescription::with_idmap(2);

    fd_map[AT_FDCWD] = FileDescription::with_idmap(AT_FDCWD);
}

std::shared_ptr<FileDescription> IOMap::get_file_description(int fd) {
    std::lock_guard<std::mutex> lg(mu);
    if(auto it = fd_map.find(fd); it != fd_map.end()) {
        return it->second;
    } else {
        return std::shared_ptr<FileDescription>();
    }
}

bool IOMap::remove_file_description(int fd) {
    std::lock_guard<std::mutex> lg(mu);
    if(auto it = fd_map.find(fd); it != fd_map.end()) {
        fd_map.erase(it);
        return true;
    } else {
        return false;
    }
}

int IOMap::insert_file_description(std::shared_ptr<FileDescription>&& description) {
    std::lock_guard<std::mutex> lg(mu);
    int new_fd = next_fd++;
    fd_map[new_fd] = std::move(description);
    return new_fd;
}