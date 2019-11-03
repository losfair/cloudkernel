use crate::crosscall;

pub fn log(text: &str) {
    unsafe {
        let text = text.as_bytes();
        if crosscall::cc_send_message()(&0u128, 0u64, crosscall::MessageType::DEBUG_PRINT as u32, text.as_ptr(), text.len()) < 0 {
            core::intrinsics::abort();
        }

        if crosscall::wait_for_trivial_result_abort_on_error().code != 0 {
            core::intrinsics::abort();
        }
    }
}
