#include <arpa/inet.h>
#include <ck-hypervisor/byteutils.h>
#include <ck-hypervisor/profile.h>
#include <json.hpp>
#include <stdexcept>
#include <stdint.h>
#include <stdio.h>

using json = nlohmann::json;

bool GlobalProfile::parse(const std::string &_input) {
  try {
    json input = json::parse(_input);
    module_path = input["module_path"].get<std::string>();
    auto raw_storage_groups =
        input["storage_groups"].get<std::map<std::string, json>>();
    for (auto &[k, v] : raw_storage_groups) {
      StorageGroupProfile p;
      p.name = k;
      auto raw_directories =
          v["directories"].get<std::map<std::string, std::string>>();
      for (auto &[k, v] : raw_directories) {
        p.directories[k] = v;
      }
      storage_groups[k] = std::move(p);
    }
    auto raw_apps = input["apps"].get<std::map<std::string, json>>();
    for (auto &[k, v] : raw_apps) {
      auto p = std::shared_ptr<AppProfile>(new AppProfile);
      p->name = k;
      p->args = v["args"].get<std::vector<std::string>>();
      p->capabilities = v["capabilities"].get<std::set<std::string>>();
      p->storage_groups = v["storage_groups"].get<std::set<std::string>>();

      if (auto generic_ipv4_address = v["ipv4_address"];
          !generic_ipv4_address.is_null()) {
        auto ipv4_address = generic_ipv4_address.get<std::string>();
        if (auto addr = decode_ipv4_address(ipv4_address.c_str())) {
          p->ipv4_address = addr;
        } else {
          throw std::runtime_error("invalid ipv4 address");
        }
      }

      if (auto generic_ipv6_address = v["ipv6_address"];
          !generic_ipv6_address.is_null()) {
        auto ipv6_address = generic_ipv6_address.get<std::string>();
        if (auto addr = decode_ipv6_address(ipv6_address.c_str())) {
          p->ipv6_address = addr;
        } else {
          throw std::runtime_error("invalid ipv6 address");
        }
      }
      apps[k] = std::move(p);
    }
    return true;
  } catch (json::parse_error &e) {
    printf("Parse error: %s\n", e.what());
  } catch (json::invalid_iterator &e) {
    printf("Invalid iterator error: %s\n", e.what());
  } catch (json::type_error &e) {
    printf("Type error: %s\n", e.what());
  } catch (json::out_of_range &e) {
    printf("Out of range error: %s\n", e.what());
  } catch (json::other_error &e) {
    printf("Other error: %s\n", e.what());
  } catch (std::runtime_error &e) {
    printf("Error: %s\n", e.what());
  } catch (...) {
    printf("Unknown error while parsing JSON profile\n");
  }
  return false;
}

std::shared_mutex global_profile_mu;
GlobalProfile global_profile;
