#![no_std]
#![feature(naked_functions, asm, core_intrinsics, alloc_error_handler)]

extern crate rlibc;

#[macro_use]
extern crate alloc;

#[macro_use]
pub mod crosscall;
pub mod debug;
pub mod process;
pub mod poll;
pub mod service;
pub mod consts;

use core::ptr::NonNull;
use core::panic::PanicInfo;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

extern "C" {
    fn ck_main() -> i32;
}

#[no_mangle]
pub unsafe extern "C" fn _start() -> i32 {
    init_allocator();
    ck_main()
}

unsafe fn init_allocator() {
    wee_alloc::MMAP_IMPL = Some(do_alloc)
}

fn do_alloc(bytes: usize) -> Option<NonNull<u8>> {
    let ret = unsafe {
        crosscall::cc_map_heap()(bytes)
    };
    if ret == -1isize as usize {
        None
    } else {
        NonNull::new(ret as *mut u8)
    }
}

#[panic_handler]
pub extern fn panic_fmt(info: &PanicInfo) -> ! {
    debug::log(format!("panic: {:?}", info).as_str());
    unsafe { core::intrinsics::abort(); }
}

#[alloc_error_handler]
fn on_alloc_error(_: core::alloc::Layout) -> ! {
    debug::log("Fatal error: unable to allocate memory");
    unsafe { core::intrinsics::abort(); }
}
