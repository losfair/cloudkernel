#pragma once

#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <shared_mutex>
#include <vector>

/*
Capabilities:
- socket_listen
- socket_listen.<port>
- socket_connect
- profile_update
- process_create
- network_assign_ipv4
*/

class AppNetworkProfile {
public:
  std::optional<uint32_t> ipv4_address;
  std::optional<__uint128_t> ipv6_address;
  bool no_source_verification = false;
};

class AppProfile {
public:
  std::string name;
  std::string workdir;
  std::vector<std::string> args;
  std::set<std::string> capabilities;
  std::set<std::string> storage_groups;
  std::shared_ptr<AppNetworkProfile> network;
  std::string rootfs_profile;
};

class StorageGroupProfile {
public:
  std::string name;
  std::map<std::string, std::filesystem::path> directories;
};

class MountProfile {
public:
  std::string source, target, fstype;
  bool is_bind = false;
  bool is_readonly = false;
};

class RootfsProfile {
public:
  std::string name;
  std::vector<MountProfile> mounts;
};

class GlobalProfile {
public:
  std::string module_path;
  std::string ckrt_path;
  std::map<std::string, StorageGroupProfile> storage_groups;
  std::map<std::string, std::shared_ptr<AppProfile>> apps;
  std::map<std::string, std::shared_ptr<RootfsProfile>> rootfs_profiles;
  bool parse(const std::string &input);
};

extern std::shared_mutex global_profile_mu;
extern GlobalProfile global_profile;
