use core::ptr::NonNull;

#[macro_export]
macro_rules! define_crosscall_resolver {
    ($func_name:ident, $import_name:expr, $ty:ty) => {
        pub fn $func_name() -> $ty {
            use core::mem::transmute;

            static mut F: Option<$ty> = None;
            unsafe {
                if let Some(x) = F {
                    x
                } else {
                    let x = transmute::<_, $ty>($crate::crosscall::resolve_crosscall_generic($import_name));
                    F = Some(x);
                    x
                }
            }
        }
    };
}

define_crosscall_resolver!(cc_send_message, "kernel_0.0.0/SendMessage", unsafe extern "C" fn (&u128, u64, u32, *const u8, usize) -> i32);
define_crosscall_resolver!(cc_recv_message, "kernel_0.0.0/RecvMessage", unsafe extern "C" fn (&mut u128, &mut u64, &mut u32, *mut u8, usize) -> i32);
define_crosscall_resolver!(cc_map_heap, "user_0.0.0/MapHeap", unsafe extern "C" fn (usize) -> usize);

#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum MessageType {
    INVALID = 0,
    MODULE_REQUEST,
    MODULE_OFFER,
    REJECT,
    PROCESS_CREATE,
    PROCESS_OFFER,
    DEBUG_PRINT,
    OK,
    PROCESS_WAIT,
}

pub enum CrosscallFunc {}

pub fn resolve_crosscall_generic(name: &str) -> NonNull<CrosscallFunc> {
    #[naked]
    #[inline(never)]
    unsafe extern "C" fn do_resolve(_name_c: *const u8) -> NonNull<CrosscallFunc> {
        asm!(
            r#"
               movq $$20000, %rax
               syscall
               ret
            "# :::: "volatile"
        );
        core::intrinsics::abort();
    }

    let mut name_buf: [u8; 256] = [0; 256];
    let name = name.as_bytes();
    if name.len() > name_buf.len() - 1 {
        panic!("name too long");
    }

    name_buf[..name.len()].copy_from_slice(name);
    unsafe {
        do_resolve(name_buf.as_ptr())
    }
}
