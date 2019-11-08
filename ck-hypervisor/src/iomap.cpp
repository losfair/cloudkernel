#include <ck-hypervisor/iomap.h>
#include <fcntl.h>
#include <unistd.h>

void IOMap::setup_defaults() {
    std::lock_guard<std::mutex> lg(mu);
    fd_map[0] = FileDescription::with_idmap(0);
    fd_map[1] = FileDescription::with_idmap(1);
    fd_map[2] = FileDescription::with_idmap(2);

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
    int new_fd = next_fd_locked();
    fd_map[new_fd] = std::move(description);
    return new_fd;
}

void IOMap::insert_file_description(int fd, std::shared_ptr<FileDescription>&& description) {
    std::lock_guard<std::mutex> lg(mu);
    fd_map[fd] = std::move(description);
}

int IOMap::next_fd_locked() {
    if(auto it = fd_map.rbegin(); it != fd_map.rend()) {
        return it->first + 1;
    } else {
        return 0;
    }
}

std::vector<FileSnapshot> IOMap::snapshot_files() {
    std::vector<FileSnapshot> result;
    std::lock_guard<std::mutex> lg(mu);

    for(auto& [vfd, desc] : fd_map) {
        FileSnapshot fs;
        fs.vfd = vfd;

        std::lock_guard<std::mutex> desc_lg(desc->mu);
        switch(desc->ty) {
            case FileInstanceType::IDMAP: {
                fs.ty = FileInstanceType::IDMAP;
                break;
            }
            case FileInstanceType::HYPERVISOR: {
                fs.ty = FileInstanceType::HYPERVISOR;
                break;
            }
            case FileInstanceType::NORMAL: {
                fs.ty = FileInstanceType::NORMAL;
                fs.path = desc->path.c_str();
                fs.offset = lseek(desc->os_fd, 0, SEEK_CUR);
                fs.flags = desc->flags;
                break;
            }
            case FileInstanceType::USER: {
                fs.ty = FileInstanceType::USER;
                break;
            }
            default: continue;
        }

        result.push_back(std::move(fs));
    }

    return result;
}
