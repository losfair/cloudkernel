use nix::sys::socket::{sendmsg, recvmsg, MsgFlags};
use nix::sys::uio::IoVec;
use std::os::unix::io::RawFd;
use std::convert::TryFrom;
use num_enum::TryFromPrimitive;

pub const HYPERVISOR_FD: RawFd = 3;
pub const POLL_BUFFER_SIZE: usize = 65536;
pub const TRIVIAL_RESULT_DESCRIPTION_SIZE: usize = 256;

#[repr(u32)]
#[derive(Copy, Clone, Debug, TryFromPrimitive)]
pub enum MessageType {
    INVALID = 0,
    TRIVIAL_RESULT,
    MODULE_REQUEST,
    MODULE_OFFER,
    PROCESS_CREATE,
    PROCESS_OFFER,
    DEBUG_PRINT,
    PROCESS_WAIT,
    POLL,
    SERVICE_REGISTER,
    SERVICE_GET,
    IP_PACKET,
    IP_ADDRESS_REGISTER_V4,
    IP_ADDRESS_REGISTER_V6,
}

#[repr(packed)]
#[derive(Copy, Clone)]
pub struct TrivialResult {
    pub code: i32,
    pub description: [u8; TRIVIAL_RESULT_DESCRIPTION_SIZE],
    pub description_len: u16,
}

pub fn send_message(recipient: u128, session: u64, tag: u32, data: &[u8]) {
    let iovs: [IoVec<&[u8]>; 4] = unsafe { [
        IoVec::from_slice(std::slice::from_raw_parts(&recipient as *const u128 as *const u8, 16)),
        IoVec::from_slice(std::slice::from_raw_parts(&session as *const u64 as *const u8, 8)),
        IoVec::from_slice(std::slice::from_raw_parts(&tag as *const u32 as *const u8, 4)),
        IoVec::from_slice(data),
    ] };
    sendmsg(HYPERVISOR_FD, &iovs, &[], MsgFlags::empty(), None).unwrap();
}

pub fn recv_message(recipient: &mut u128, session: &mut u64, tag: &mut u32, data: &mut [u8]) -> Option<usize> {
    let iovs: [IoVec<&mut [u8]>; 4] = unsafe { [
        IoVec::from_mut_slice(std::slice::from_raw_parts_mut(recipient as *mut u128 as *mut u8, 16)),
        IoVec::from_mut_slice(std::slice::from_raw_parts_mut(session as *mut u64 as *mut u8, 8)),
        IoVec::from_mut_slice(std::slice::from_raw_parts_mut(tag as *mut u32 as *mut u8, 4)),
        IoVec::from_mut_slice(data),
    ] };
    match recvmsg(HYPERVISOR_FD, &iovs, None, MsgFlags::empty()) {
        Ok(x) => Some(x.bytes.checked_sub(16 + 8 + 4).expect("invalid message from hypervisor")),
        Err(_) => None,
    }
}

pub fn poll(recipient: &mut u128, session: &mut u64, tag: &mut u32, data: &mut [u8]) -> Option<usize> {
    send_message(0, 0, MessageType::POLL as u32, &[]);
    recv_message(recipient, session, tag, data)
}

pub fn trivial_kernel_request(tag: MessageType, data: &[u8]) -> Result<(), String> {
    send_message(0, 0, tag as u32, data);

    let mut recipient: u128 = 0;
    let mut session: u64 = 0;
    let mut tag: u32 = 0;
    let mut description = vec![0u8; std::mem::size_of::<TrivialResult>()];
    let n_bytes = recv_message(&mut recipient, &mut session, &mut tag, &mut description).expect("Failed to receive response");
    if recipient != 0 || session != 0 {
        panic!("unexpected recipient/session");
    }
    let tag = MessageType::try_from(tag).expect("invalid tag");

    match tag {
        MessageType::TRIVIAL_RESULT => {
            if n_bytes != std::mem::size_of::<TrivialResult>() {
                panic!("invalid message size: {} {}", n_bytes, std::mem::size_of::<TrivialResult>());
            }
            unsafe {
                let tr = &*(description.as_ptr() as *const u8 as *const TrivialResult);
                if tr.code != 0 {
                    Err(std::str::from_utf8(&tr.description[..tr.description_len as usize]).unwrap().to_string())
                } else {
                    Ok(())
                }
            }
        }
        _ => panic!("unexpected tag")
    }
}
