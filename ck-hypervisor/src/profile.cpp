#include <ck-hypervisor/profile.h>
#include <json.hpp>
#include <stdio.h>

using json = nlohmann::json;

bool GlobalProfile::parse(const std::string& _input) {
    try {
        json input = json::parse(_input);
        module_path = input["module_path"].get<std::string>();
        auto raw_storage_groups = input["storage_groups"].get<std::map<std::string, json>>();
        for(auto& [k, v] : raw_storage_groups) {
            StorageGroupProfile p;
            p.name = k;
            auto raw_directories = v["directories"].get<std::map<std::string, std::string>>();
            for(auto& [k, v] : raw_directories) {
                p.directories[k] = v;
            }
            storage_groups[k] = std::move(p);
        }
        auto raw_apps = input["apps"].get<std::map<std::string, json>>();
        for(auto& [k, v] : raw_apps) {
            auto p = std::shared_ptr<AppProfile>(new AppProfile);
            p->name = k;
            p->args = v["args"].get<std::vector<std::string>>();
            p->capabilities = v["capabilities"].get<std::set<std::string>>();
            p->storage_groups = v["storage_groups"].get<std::set<std::string>>();
            apps[k] = std::move(p);
        }
        return true;
    } catch(json::parse_error& e) {
        printf("Parse error: %s\n", e.what());
    } catch(json::invalid_iterator& e) {
        printf("Invalid iterator error: %s\n", e.what());
    } catch(json::type_error& e) {
        printf("Type error: %s\n", e.what());
    } catch(json::out_of_range& e) {
        printf("Out of range error: %s\n", e.what());
    } catch(json::other_error& e) {
        printf("Other error: %s\n", e.what());
    } catch(...) {
        printf("Unknown error while parsing JSON profile\n");
    }
    return false;
}

std::shared_mutex global_profile_mu;
GlobalProfile global_profile;
