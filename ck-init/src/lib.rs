#![no_std]
#![feature(core_intrinsics, alloc_error_handler)]

#[macro_use]
extern crate ck_crosscall;
#[macro_use]
extern crate sc;
extern crate rlibc;
#[macro_use]
extern crate alloc;

mod linux;

use core::ptr::NonNull;
use core::panic::PanicInfo;
use alloc::string::String;
use linux::Timespec;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[no_mangle]
pub extern "C" fn _start() {
    unsafe {
        init_allocator();
    }
    ck_crosscall::debug::log("Cloudkernel init process started.");
    linux::nanosleep(&Timespec {
        tv_sec: 1,
        tv_nsec: 0,
    });
    ck_crosscall::debug::log("After nanosleep.");
}

unsafe fn init_allocator() {
    wee_alloc::MMAP_IMPL = Some(do_alloc)
}

fn do_alloc(bytes: usize) -> Option<NonNull<u8>> {
    let ret = unsafe {
        ck_crosscall::crosscall::cc_map_heap()(bytes)
    };
    if ret == -1isize as usize {
        None
    } else {
        NonNull::new(ret as *mut u8)
    }
}

#[panic_handler]
pub extern fn panic_fmt(_info: &PanicInfo) -> ! {
    loop {}
}

#[alloc_error_handler]
fn on_alloc_error(_: core::alloc::Layout) -> ! {
    ck_crosscall::debug::log("Unable to allocate memory.");
    loop {}
}