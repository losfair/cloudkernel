#pragma once

#include <set>
#include <map>
#include <filesystem>
#include <optional>
#include <memory>
#include <shared_mutex>
#include <vector>

/*
Capabilities:
- socket_listen
- socket_listen.<port>
- socket_connect
- profile_update
- snapshot_create
- process_create
*/

class AppProfile {
    public:
    std::string name;
    std::vector<std::string> args;
    std::set<std::string> capabilities;
    std::set<std::string> storage_groups;
};

class StorageGroupProfile {
    public:
    std::string name;
    std::map<std::string, std::filesystem::path> directories;
};

class GlobalProfile {
    public:
    std::string module_path;
    std::map<std::string, StorageGroupProfile> storage_groups;
    std::map<std::string, std::shared_ptr<AppProfile>> apps;
    bool parse(const std::string& input);
};

extern std::shared_mutex global_profile_mu;
extern GlobalProfile global_profile;
