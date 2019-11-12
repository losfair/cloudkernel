#include <ck-hypervisor/snapshot.h>
#include <ck-hypervisor/byteutils.h>
#include <assert.h>

static void align_buffer(std::vector<uint8_t>& buf, size_t align) {
    while(buf.size() % align != 0) buf.push_back(0);
}

std::vector<uint8_t> ProcessSnapshot::serialize() const {
    std::vector<uint8_t> result;

    write_vec(result, (uint8_t) notify_invalid_syscall);
    write_vec(result, regs);

    std::vector<size_t> memory_ptr_offsets;
    write_vec(result, (uint32_t) memory.size());
    for(auto& mss : memory) {
        write_vec(result, (uint64_t) mss.start);
        write_vec(result, (uint32_t) mss.data_len);
        write_vec(result, (int32_t) mss.prot);
        write_vec(result, (uint32_t) mss.ty);
        memory_ptr_offsets.push_back(result.size());
        write_vec(result, (uint64_t) 0);
    }

    write_vec(result, (uint32_t) files.size());
    for(auto& f : files) {
        write_vec(result, (int32_t) f.fd);
        write_vec(result, (uint32_t) f.path.size());
        std::copy(f.path.begin(), f.path.end(), std::back_inserter(result));
        write_vec(result, (uint64_t) f.offset);
        write_vec(result, (uint32_t) f.user);
        write_vec(result, (int32_t) f.flags);
    }

    for(int i = 0; i < memory.size(); i++) {
        align_buffer(result, 4096);
        size_t offset_start = result.size();
        * (uint64_t *) &result[memory_ptr_offsets.at(i)] = offset_start;

        auto& mss = memory[i];
        result.resize(result.size() + mss.data_len);
        mss.data_feed(&result[offset_start]);
    }
    
    return result;
}
