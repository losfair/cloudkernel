use crate::crosscall;

pub const MAX_BODY_SIZE: usize = 65536;

#[derive(Default, Copy, Clone, Debug)]
pub struct IncomingMessageMetadata {
    pub sender: u128,
    pub session: u64,
    pub tag: u32,
    pub body_size: usize
}

pub fn poll_once(buffer: &mut [u8]) -> IncomingMessageMetadata {
    let status = unsafe { crosscall::cc_send_message()(
        &0u128, 0u64,
        crosscall::MessageType::POLL as u32,
        core::ptr::null_mut(),
        0,
    ) };
    if status != 0 {
        panic!("failed to send poll request");
    }

    let mut ret = IncomingMessageMetadata::default();
    let status = unsafe {
        crosscall::cc_recv_message()(&mut ret.sender, &mut ret.session, &mut ret.tag, buffer.as_mut_ptr() as *mut u8, buffer.len())
    };
    if status < 0 {
        panic!("failed to receive poll response");
    } else {
        ret.body_size = status as usize;
        ret
    }
}
