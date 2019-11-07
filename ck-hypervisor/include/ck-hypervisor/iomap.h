#pragma once

#include <map>
#include <mutex>
#include <optional>
#include <memory>
#include <filesystem>


enum class FileInstanceType {
    INVALID,
    IDMAP, // identical mapping
    HYPERVISOR, // hypervisor fd
    NORMAL, // normal files
    USER, // triggers SIGSYS on I/O
};

class FileDescription {
    public:
    std::mutex mu;
    int os_fd = -1;
    std::filesystem::path path;
    FileInstanceType ty = FileInstanceType::INVALID;

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
    int next_fd = 0;
    std::map<int, std::shared_ptr<FileDescription>> fd_map;

    public:
    void setup_defaults();
    std::shared_ptr<FileDescription> get_file_description(int fd);
    bool remove_file_description(int fd);
    int insert_file_description(std::shared_ptr<FileDescription>&& description);
};
