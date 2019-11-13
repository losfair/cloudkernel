#pragma once

#include <sys/types.h>
#include <stdint.h>
#include <sys/user.h>
#include <array>

int load_snapshot(int mfd, const uint8_t *snapshot, size_t len, std::array<user_regs_struct, 1024>& regs_out);
