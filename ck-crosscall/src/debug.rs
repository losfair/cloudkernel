use crate::crosscall;

pub fn log(text: &str) {
    unsafe {
        let text = text.as_bytes();
        if crosscall::cc_send_message()(&0u128, 0u64, crosscall::MessageType::DEBUG_PRINT as u32, text.as_ptr(), text.len()) < 0 {
            core::intrinsics::abort();
        }

        let mut sender: u128 = 0;
        let mut session: u64 = 0;
        let mut tag: u32 = 0;
        if crosscall::cc_recv_message()(&mut sender, &mut session, &mut tag, core::ptr::null_mut(), 0) < 0 || tag != crosscall::MessageType::OK as u32 {
            core::intrinsics::abort();
        }
    }
}
