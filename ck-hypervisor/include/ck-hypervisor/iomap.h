#pragma once

#include <map>
#include <mutex>
#include <optional>
#include <memory>
#include <filesystem>
#include "file_base.h"
#include "snapshot.h"

class FileDescription {
    public:
    std::mutex mu;
    int os_fd = -1;
    std::filesystem::path path;
    FileInstanceType ty = FileInstanceType::INVALID;
    int flags = 0;

    static inline std::shared_ptr<FileDescription> with_idmap(int fd) {
        auto ret = std::shared_ptr<FileDescription>(new FileDescription);
        ret->os_fd = fd;
        ret->ty = FileInstanceType::IDMAP;
        return ret;
    }

    static inline std::shared_ptr<FileDescription> with_hypervisor_fd(int fd) {
        auto ret = std::shared_ptr<FileDescription>(new FileDescription);
        ret->os_fd = fd;
        ret->ty = FileInstanceType::HYPERVISOR;
        return ret;
    }
};

class IOMap {
    private:
    std::mutex mu;
    std::map<int, std::shared_ptr<FileDescription>> fd_map;
    int next_fd_locked();

    public:
    void setup_defaults();
    std::shared_ptr<FileDescription> get_file_description(int fd);
    bool remove_file_description(int fd);
    int insert_file_description(std::shared_ptr<FileDescription>&& description);
    void insert_file_description(int fd, std::shared_ptr<FileDescription>&& description);
    std::vector<FileSnapshot> snapshot_files();
};
