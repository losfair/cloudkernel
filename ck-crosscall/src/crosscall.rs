use core::ptr::NonNull;
use core::mem::MaybeUninit;

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
    TRIVIAL_RESULT,
    MODULE_REQUEST,
    MODULE_OFFER,
    PROCESS_CREATE,
    PROCESS_OFFER,
    DEBUG_PRINT,
    PROCESS_WAIT,
    POLL,
    SERVICE_REGISTER,
    SERVICE_GET,
}

#[repr(packed)]
#[derive(Copy, Clone)]
pub struct TrivialResult {
    pub code: i32,
    pub description: [u8; crate::consts::TRIVIAL_RESULT_DESCRIPTION_SIZE],
    pub description_len: u16,
}

impl TrivialResult {
    pub fn get_description(&self) -> Option<&str> {
        let len = if (self.description_len as usize) < self.description.len() {
            self.description_len as usize
        } else {
            self.description.len()
        };
        match core::str::from_utf8(&self.description[..len]) {
            Ok(x) => Some(x),
            Err(_) => None
        }
    }
}

pub fn wait_for_trivial_result() -> TrivialResult {
    _wait_for_trivial_result(false)
}

pub fn wait_for_trivial_result_abort_on_error() -> TrivialResult {
    _wait_for_trivial_result(true)
}

fn _wait_for_trivial_result(abort: bool) -> TrivialResult {
    unsafe {
        let mut sender: u128 = 0;
        let mut session: u64 = 0;
        let mut tag: u32 = 0;
        let mut result: MaybeUninit<TrivialResult> = MaybeUninit::uninit();

        let ret = cc_recv_message()(&mut sender, &mut session, &mut tag, result.as_mut_ptr() as *mut u8, core::mem::size_of::<TrivialResult>());

        if ret < 0 {
            if abort {
                core::intrinsics::abort();
            } else {
                panic!("wait_for_trivial_result: failed to receive message");
            }
        }

        if tag == MessageType::TRIVIAL_RESULT as u32 && ret as usize == core::mem::size_of::<TrivialResult>() {
            result.assume_init()
        } else {
            if abort {
                core::intrinsics::abort();
            } else {
                panic!("wait_for_trivial_result: unexpected result from hypervisor");
            }
        }
    }
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
