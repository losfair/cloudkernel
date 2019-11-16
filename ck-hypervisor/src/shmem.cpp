#include <ck-hypervisor/shmem.h>
#include <ck-hypervisor/round.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdexcept>
#include <fcntl.h>
#include <sstream>

SharedMemory::SharedMemory(size_t new_size, bool new_remote_ro) {
    if(new_size == 0) {
        throw std::runtime_error("SharedMemory must have a size greater than zero");
    }

    size = round_up(new_size, getpagesize());
    remote_ro = new_remote_ro;
    mfd = memfd_create("shared-memory", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if(mfd < 0) throw std::runtime_error("unable to create memfd");
    if(
        ftruncate(mfd, size) < 0 ||
        fcntl(mfd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL) < 0 ||
        (mapping = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0)) == MAP_FAILED
    ) {
        close(mfd);
        throw std::runtime_error("unable to initialize memory mapping");
    }
}

SharedMemory::~SharedMemory() {
    munmap(mapping, size);
    close(mfd);
}

int SharedMemory::create_remote_handle() {
    std::stringstream fd_path_ss;
    fd_path_ss << "/proc/self/fd/" << mfd;
    std::string fd_path = fd_path_ss.str();

    return open(fd_path.c_str(), (remote_ro ? O_RDONLY : O_RDWR) | O_CLOEXEC);
}
