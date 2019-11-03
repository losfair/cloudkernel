#![no_std]
#![feature(core_intrinsics)]

extern crate ck_crosscall;
#[macro_use]
extern crate alloc;

#[no_mangle]
pub extern "C" fn ck_main() -> i32 {
    ck_crosscall::debug::log("ck-migration loaded");
    let init_pid = ck_crosscall::service::get("init").expect("Init service not found");
    ck_crosscall::debug::log(format!("Init PID: {:x}", init_pid).as_str());

    let msg = "Hello, world!";
    let msg = msg.as_bytes();

    assert_eq!(unsafe { ck_crosscall::crosscall::cc_send_message()(
        &init_pid,
        0u64,
        0u32,
        msg.as_ptr(),
        msg.len(),
    ) }, msg.len() as i32);
    let result = ck_crosscall::crosscall::wait_for_trivial_result();
    unsafe {
        ck_crosscall::debug::log(format!("code = {}, description = {:?}", result.code, result.get_description()).as_str());
    }
    0
}
