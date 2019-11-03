#![no_std]
#![feature(core_intrinsics)]

extern crate ck_crosscall;
#[macro_use]
extern crate sc;
#[macro_use]
extern crate alloc;

mod linux;

use alloc::vec::Vec;
use ck_crosscall::poll::{poll_once, IncomingMessageMetadata};

#[no_mangle]
pub extern "C" fn ck_main() -> i32 {
    ck_crosscall::debug::log("Cloudkernel init process started.");

    if !ck_crosscall::service::register("init") {
        panic!("Service registration failed.");
    }
    ck_crosscall::debug::log("Service registered.");

    start_unprivileged_service("ck-migration_0.0.0");

    let mut poll_buf: Vec<u8> = vec![0; 65536];
    loop {
        let md = poll_once(&mut poll_buf);
        ck_crosscall::debug::log(format!("Got new message from {:x}: {:?}", md.sender, md).as_str());
    }
}

fn start_unprivileged_service(name: &str) {
    ck_crosscall::debug::log(format!("Starting service in unprivileged mode: {}", name).as_str());

    let result = ck_crosscall::process::ProcessCreationInfo::new(name, false).send();
    match result {
        Ok(x) => {
            unsafe { ck_crosscall::debug::log(format!("Service started as process {:x}.", x.pid).as_str()) };
            /*let result = ck_crosscall::process::wait_process(x.pid);
            unsafe {
                ck_crosscall::debug::log(format!("Process {:x} exited. Code: {} Description: {:?}", x.pid, result.code, result.get_description()).as_str());
            }*/
        }
        Err(e) => {
            unsafe {
                ck_crosscall::debug::log(format!("Unable to create process. Error code: {} Description: {:?}", e.code, e.get_description()).as_str());
            }
        }
    }
}