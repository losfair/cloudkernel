use crate::crosscall;
use byteorder::{ByteOrder, LittleEndian};

pub fn log(text: &str) {
    let text = text.as_bytes();

    let mut buf: [u8; 256] = [0; 256];
    LittleEndian::write_u32(&mut buf[..4], crosscall::MessageType::DEBUG_PRINT as u32);

    let copy_len = if buf.len() - 4 < text.len() {
        buf.len() - 4
    } else {
        text.len()
    };
    buf[4..4 + copy_len].copy_from_slice(&text[..copy_len]);
    crosscall::cc_send_message()(buf.as_ptr(), 4 + copy_len);
}
