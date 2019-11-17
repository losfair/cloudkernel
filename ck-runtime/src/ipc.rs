use nix::sys::socket::{recvmsg, sendmsg, MsgFlags};
use nix::sys::socket::{CmsgSpace, ControlMessage, ControlMessageOwned};
use nix::sys::uio::IoVec;
use num_enum::TryFromPrimitive;
use std::convert::TryFrom;
use std::os::unix::io::RawFd;

pub const HYPERVISOR_FD: RawFd = 3;
pub const POLL_BUFFER_SIZE: usize = 65536;
pub const TRIVIAL_RESULT_DESCRIPTION_SIZE: usize = 256;

#[repr(u32)]
#[derive(Copy, Clone, Debug, TryFromPrimitive)]
#[allow(non_camel_case_types)]
pub enum KernelMessageType {
    INVALID = 0,
    TRIVIAL_RESULT,
    MODULE_REQUEST,
    MODULE_OFFER,
    PROCESS_CREATE,
    PROCESS_OFFER,
    PROCESS_WAIT,
    POLL,
    PROCESS_COMPLETION,
    IP_QUEUE_OPEN,
    IP_QUEUE_OFFER,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, TryFromPrimitive)]
pub enum RtMessageType {
    Invalid = 0,
    EntangleRequest,
    EntangleOffer,
}

#[repr(packed)]
#[derive(Copy, Clone)]
pub struct TrivialResult {
    pub code: i32,
    pub description: [u8; TRIVIAL_RESULT_DESCRIPTION_SIZE],
    pub description_len: u16,
}

pub fn send_message(recipient: u128, session: u64, tag: u32, data: &[u8]) {
    let iovs: [IoVec<&[u8]>; 4] = unsafe {
        [
            IoVec::from_slice(std::slice::from_raw_parts(
                &recipient as *const u128 as *const u8,
                16,
            )),
            IoVec::from_slice(std::slice::from_raw_parts(
                &session as *const u64 as *const u8,
                8,
            )),
            IoVec::from_slice(std::slice::from_raw_parts(
                &tag as *const u32 as *const u8,
                4,
            )),
            IoVec::from_slice(data),
        ]
    };
    sendmsg(HYPERVISOR_FD, &iovs, &[], MsgFlags::empty(), None).unwrap();
}

pub fn send_message_with_fds(recipient: u128, session: u64, tag: u32, data: &[u8], fds: &[RawFd]) {
    let iovs: [IoVec<&[u8]>; 4] = unsafe {
        [
            IoVec::from_slice(std::slice::from_raw_parts(
                &recipient as *const u128 as *const u8,
                16,
            )),
            IoVec::from_slice(std::slice::from_raw_parts(
                &session as *const u64 as *const u8,
                8,
            )),
            IoVec::from_slice(std::slice::from_raw_parts(
                &tag as *const u32 as *const u8,
                4,
            )),
            IoVec::from_slice(data),
        ]
    };
    sendmsg(
        HYPERVISOR_FD,
        &iovs,
        &[ControlMessage::ScmRights(fds)],
        MsgFlags::empty(),
        None,
    )
    .unwrap();
}

pub fn recv_message(
    recipient: &mut u128,
    session: &mut u64,
    tag: &mut u32,
    data: &mut [u8],
) -> Option<usize> {
    let iovs: [IoVec<&mut [u8]>; 4] = unsafe {
        [
            IoVec::from_mut_slice(std::slice::from_raw_parts_mut(
                recipient as *mut u128 as *mut u8,
                16,
            )),
            IoVec::from_mut_slice(std::slice::from_raw_parts_mut(
                session as *mut u64 as *mut u8,
                8,
            )),
            IoVec::from_mut_slice(std::slice::from_raw_parts_mut(
                tag as *mut u32 as *mut u8,
                4,
            )),
            IoVec::from_mut_slice(data),
        ]
    };
    match recvmsg(HYPERVISOR_FD, &iovs, None, MsgFlags::empty()) {
        Ok(x) => Some(
            x.bytes
                .checked_sub(16 + 8 + 4)
                .expect("invalid message from hypervisor"),
        ),
        Err(_) => None,
    }
}

pub fn recv_message_with_fds(
    sender: &mut u128,
    session: &mut u64,
    tag: &mut u32,
    data: &mut [u8],
) -> Option<(usize, Vec<RawFd>)> {
    let iovs: [IoVec<&mut [u8]>; 4] = unsafe {
        [
            IoVec::from_mut_slice(std::slice::from_raw_parts_mut(
                sender as *mut u128 as *mut u8,
                16,
            )),
            IoVec::from_mut_slice(std::slice::from_raw_parts_mut(
                session as *mut u64 as *mut u8,
                8,
            )),
            IoVec::from_mut_slice(std::slice::from_raw_parts_mut(
                tag as *mut u32 as *mut u8,
                4,
            )),
            IoVec::from_mut_slice(data),
        ]
    };
    let mut cmsg = cmsg_space!([RawFd; 8]);
    match recvmsg(HYPERVISOR_FD, &iovs, Some(&mut cmsg), MsgFlags::empty()) {
        Ok(x) => Some((
            x.bytes
                .checked_sub(16 + 8 + 4)
                .expect("invalid message from hypervisor"),
            x.cmsgs()
                .filter_map(|x| match x {
                    ControlMessageOwned::ScmRights(fds) => Some(fds),
                    _ => None,
                })
                .flatten()
                .collect(),
        )),
        Err(_) => None,
    }
}

pub fn trivial_kernel_request(tag: KernelMessageType, data: &[u8]) -> Result<String, String> {
    send_message(0, 0, tag as u32, data);

    let mut recipient: u128 = 0;
    let mut session: u64 = 0;
    let mut tag: u32 = 0;
    let mut description = vec![0u8; std::mem::size_of::<TrivialResult>()];
    let n_bytes = recv_message(&mut recipient, &mut session, &mut tag, &mut description)
        .expect("Failed to receive response");
    if recipient != 0 || session != 0 {
        panic!("unexpected recipient/session");
    }
    let tag = KernelMessageType::try_from(tag).expect("invalid tag");

    match tag {
        KernelMessageType::TRIVIAL_RESULT => {
            if n_bytes != std::mem::size_of::<TrivialResult>() {
                panic!(
                    "invalid message size: {} {}",
                    n_bytes,
                    std::mem::size_of::<TrivialResult>()
                );
            }
            unsafe {
                let tr = &*(description.as_ptr() as *const u8 as *const TrivialResult);
                let msg = std::str::from_utf8(&tr.description[..tr.description_len as usize])
                    .unwrap()
                    .to_string();
                if tr.code != 0 {
                    Err(msg)
                } else {
                    Ok(msg)
                }
            }
        }
        _ => panic!("unexpected tag"),
    }
}
