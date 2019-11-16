#pragma once

#include <vector>

class FdSet {
public:
  std::vector<int> fds;

  FdSet();
  FdSet(const FdSet &that) = delete;
  FdSet(FdSet &&that) = delete;
  ~FdSet();

  void add(int fd);
};
