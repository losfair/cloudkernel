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
    std::filesystem::path path;
    bool user = false;
    int flags = 0;
};

class IOMap {
    private:
    std::mutex mu;
    std::map<int, std::shared_ptr<FileDescription>> fd_map;

    public:
    void setup_defaults();
    std::shared_ptr<FileDescription> get_file_description(int fd);
    bool remove_file_description(int fd);
    void insert_file_description(int fd, std::shared_ptr<FileDescription>&& description);
    std::vector<FileSnapshot> snapshot_files();
};
