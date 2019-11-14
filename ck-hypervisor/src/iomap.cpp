#include <ck-hypervisor/iomap.h>
#include <fcntl.h>
#include <unistd.h>

void IOMap::setup_defaults() {
    std::lock_guard<std::mutex> lg(mu);

    fd_map[0] = std::shared_ptr<FileDescription>(new FileDescription);
    fd_map[0]->snapshot = false;
    fd_map[1] = std::shared_ptr<FileDescription>(new FileDescription);
    fd_map[1]->snapshot = false;
    fd_map[2] = std::shared_ptr<FileDescription>(new FileDescription);
    fd_map[2]->snapshot = false;
    fd_map[3] = std::shared_ptr<FileDescription>(new FileDescription);
    fd_map[3]->snapshot = false;
    fd_map[AT_FDCWD] = std::shared_ptr<FileDescription>(new FileDescription);
    fd_map[AT_FDCWD]->snapshot = false;
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

void IOMap::insert_file_description(int fd, std::shared_ptr<FileDescription>&& description) {
    std::lock_guard<std::mutex> lg(mu);
    fd_map[fd] = std::move(description);
}

std::vector<FileSnapshot> IOMap::snapshot_files() {
    std::vector<FileSnapshot> result;
    std::lock_guard<std::mutex> lg(mu);

    for(auto& [fd, desc] : fd_map) {
        if(!desc->snapshot) continue;
        FileSnapshot fs;
        fs.fd = fd;
        fs.path = desc->path.c_str();
        fs.offset = lseek(fd, 0, SEEK_CUR);
        fs.flags = desc->flags;
        result.push_back(std::move(fs));
    }

    return result;
}
