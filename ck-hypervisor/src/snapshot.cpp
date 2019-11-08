#include <ck-hypervisor/snapshot.h>
#include <ck-hypervisor/byteutils.h>

std::vector<uint8_t> ProcessSnapshot::serialize() const {
    std::vector<uint8_t> result;

    write_vec(result, (uint8_t) notify_invalid_syscall);
    write_vec(result, regs);

    write_vec(result, (uint32_t) memory.size());
    for(auto& mss : memory) {
        write_vec(result, (uint64_t) mss.start);
        write_vec(result, (uint32_t) mss.data.size());
        write_vec(result, (int32_t) mss.prot);
        write_vec(result, (uint32_t) mss.ty);
        std::copy(mss.data.begin(), mss.data.end(), std::back_inserter(result));
    }

    write_vec(result, (uint32_t) files.size());
    for(auto f : files) {
        write_vec(result, (int32_t) f.vfd);
        write_vec(result, (uint32_t) f.path.size());
        std::copy(f.path.begin(), f.path.end(), std::back_inserter(result));
        write_vec(result, (uint64_t) f.offset);
        write_vec(result, (uint32_t) f.ty);
        write_vec(result, (int32_t) f.flags);
    }
    return result;
}
