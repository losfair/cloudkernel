#include <ck-hypervisor/fdset.h>
#include <unistd.h>

FdSet::FdSet() {}

FdSet::~FdSet() {
  for (auto x : fds) {
    close(x);
  }
}

void FdSet::add(int fd) { fds.insert(fd); }

void FdSet::forget(int fd) {
  if (auto it = fds.find(fd); it != fds.end()) {
    fds.erase(it);
  }
}

void FdSet::forget() { fds.clear(); }
