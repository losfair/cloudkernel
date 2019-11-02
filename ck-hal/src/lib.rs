#![no_std]
#![feature(lang_items, naked_functions, asm, alloc_error_handler, compiler_builtins_lib)]

#[macro_use]
extern crate alloc;

extern crate rlibc;

#[macro_use]
pub mod crosscall;
pub mod debug;

use core::ptr::NonNull;
use alloc::boxed::Box;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use core::panic::PanicInfo;


#[no_mangle]
pub extern fn _start() -> i32 {
    unsafe {
        init_allocator();
    }
    let a = 42i32;
    let b = Box::new(42i32);
    debug::log(format!("Hello from Rust! {:p} {:p}", &a, &*b).as_str());
    0
}

unsafe fn init_allocator() {
    wee_alloc::MMAP_IMPL = Some(do_alloc)
}

fn do_alloc(bytes: usize) -> Option<NonNull<u8>> {
    let ret = crosscall::cc_map_heap()(bytes);
    if ret == -1isize as usize {
        None
    } else {
        NonNull::new(ret as *mut u8)
    }
}

#[lang = "eh_personality"]
#[no_mangle]
pub extern fn eh_personality() {}

#[panic_handler]
pub extern fn panic_fmt(_info: &PanicInfo) -> ! {
    loop {}
}

#[alloc_error_handler]
fn on_alloc_error(_: core::alloc::Layout) -> ! {
    loop {}
}