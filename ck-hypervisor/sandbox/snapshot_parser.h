#pragma once

#include <sys/types.h>
#include <stdint.h>
#include <sys/user.h>

void load_snapshot(int mfd, const uint8_t *snapshot, size_t len, user_regs_struct& regs_out);