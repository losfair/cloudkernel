#pragma once

#define CK_SYS_GET_ABI_VERSION 0xffff0300
#define CK_SYS_SET_REMOTE_HYPERVISOR_FD 0xffff0301 // privileged
#define CK_SYS_NOTIFY_INVALID_SYSCALL 0xffff0302
#define CK_SYS_CREATE_USER_FD 0xffff0303
#define CK_SYS_ENTER_SANDBOX_NO_FDMAP 0xffff0304 // privileged
#define CK_SYS_ENABLE_FDMAP 0xffff0305 // no_fdmap only
#define CK_SYS_ATTACH_VFD 0xffff0306 // no_fdmap only
#define CK_SYS_LOAD_PROCESSOR_STATE_AND_UNMAP_LOADER 0xffff0307
#define CK_SYS_SNAPSHOT_ME 0xffff0308
#define CK_SYS_GETPID 0xffff0309
#define CK_SYS_DEBUG_PRINT_REGS 0xffff030a