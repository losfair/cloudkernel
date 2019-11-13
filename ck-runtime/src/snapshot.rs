use crate::ipc;
use crate::process;
use std::time::Duration;

pub fn create(pid: u128) -> Result<String, String> {
    ipc::trivial_kernel_request(ipc::MessageType::SNAPSHOT_CREATE, unsafe { std::slice::from_raw_parts(
        &pid as *const u128 as *const u8,
        std::mem::size_of::<u128>(),
    ) })
}
