#pragma once

#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <utility>

class VersionCode {
public:
  int major = 0, minor = 0, patch = 0;
  inline bool operator<(const VersionCode &that) const {
    if (major < that.major)
      return true;
    else if (major > that.major)
      return false;

    if (minor < that.minor)
      return true;
    else if (minor > that.minor)
      return false;

    if (patch < that.patch)
      return true;
    else if (patch > that.patch)
      return false;

    return false;
  }
};

static inline std::optional<std::pair<std::string, VersionCode>>
parse_module_full_name(const char *full_name) {
  std::regex re("(.+)_([0-9]+).([0-9]+).([0-9]+)");
  std::cmatch cm;
  if (!std::regex_match(full_name, cm, re)) {
    return std::nullopt;
  } else {
    if (cm.size() != 5) {
      return std::nullopt;
    }
    std::string module_name(cm[1].str());
    VersionCode version_code;
    std::stringstream ss;
    ss << cm[2] << ' ' << cm[3] << ' ' << cm[4];
    ss >> version_code.major >> version_code.minor >> version_code.patch;
    return std::make_pair(std::move(module_name), version_code);
  }
}
