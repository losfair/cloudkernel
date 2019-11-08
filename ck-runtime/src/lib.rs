#![feature(asm, naked_functions)]

pub mod hook;
pub mod ipc;
pub mod net;
pub mod snapshot;
pub mod process;

pub use nix;

use std::convert::TryFrom;
use ipc::MessageType;

pub fn run_event_loop() {
    let mut data: Vec<u8> = vec![0; 65536];

    loop {
        let mut recipient: u128 = 0;
        let mut session: u64 = 0;
        let mut tag: u32 = 0;

        let n_bytes = match ipc::poll(&mut recipient, &mut session, &mut tag, &mut data) {
            Some(x) => x,
            None => panic!("poll() failed"),
        };
        match recipient {
            0 => handle_kernel_message(session, tag, &mut data[..n_bytes]),
            _ => {}
        }
    }
}

fn handle_kernel_message(session: u64, tag: u32, data: &mut [u8]) {
    let tag = match MessageType::try_from(tag) {
        Ok(x) => x,
        Err(e) => {
            println!("Invalid message type. Error: {:?}", e);
            return;
        }
    };

    match tag {
        MessageType::IP_PACKET => {
            net::ip_input(data);
        }
        _ => {
            println!("Unknown tag: {:?}", tag);
        }
    }
}
