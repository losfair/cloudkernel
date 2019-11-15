#pragma once

#include <unordered_set>

class FdSet {
public:
  std::unordered_set<int> fds;

  FdSet();
  FdSet(const FdSet &that) = delete;
  FdSet(FdSet &&that) = delete;
  ~FdSet();

  void add(int fd);
  void forget(int fd);
  void forget();
};
