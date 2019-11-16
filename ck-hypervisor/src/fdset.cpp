#include <ck-hypervisor/fdset.h>
#include <unistd.h>

FdSet::FdSet() {}

FdSet::~FdSet() {
  for (auto x : fds) {
    close(x);
  }
}

void FdSet::add(int fd) { fds.push_back(fd); }
