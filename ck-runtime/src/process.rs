use std::mem::MaybeUninit;

#[repr(packed)]
#[derive(Copy, Clone)]
pub struct ProcessCreationInfo {
    _api_version: u32,
    pub full_name: [u8; 256],
    pub privileged: i32,
}

#[repr(packed)]
#[derive(Copy, Clone, Debug)]
pub struct ProcessOffer {
    api_version: u32,
    pub pid: u128,
}

#[repr(packed)]
#[derive(Copy, Clone, Debug)]
struct ProcessWait {
    api_version: u32,
    pid: u128,
}

pub fn getpid() -> u128 {
    #[naked]
    #[inline(never)]
    unsafe extern "C" fn do_getpid(out: *mut [u8; 16]) {
        asm!(
            r#"
                movq $$0xffff0309, %rax
                syscall
                ret
            "# :::: "volatile"
        );
    }

    let mut result: u128 = 0;
    unsafe {
        do_getpid(&mut result as *mut u128 as *mut [u8; 16]);
    }
    return result;
}

pub fn wait_process(pid: u128) -> Result<(), String> {
    let payload = ProcessWait {
        api_version: 1,
        pid: pid,
    };
    unsafe { crate::ipc::trivial_kernel_request(
        crate::ipc::MessageType::PROCESS_WAIT,
        std::slice::from_raw_parts(
            &payload as *const ProcessWait as *const u8,
            std::mem::size_of::<ProcessWait>(),
        ),
    ) }
}

impl ProcessCreationInfo {
    pub fn new(full_name: &str, privileged: bool) -> ProcessCreationInfo {
        let mut info = ProcessCreationInfo {
            _api_version: 1,
            full_name: [0; 256],
            privileged: if privileged { 1 } else { 0 },
        };
        let full_name = full_name.as_bytes();
        let copy_len = if full_name.len() < info.full_name.len() {
            full_name.len()
        } else {
            info.full_name.len()
        };
        info.full_name[..copy_len].copy_from_slice(&full_name[..copy_len]);
        info
    }

    pub fn send(&self) -> Result<ProcessOffer, String> {
        unsafe { crate::ipc::trivial_kernel_request(
            crate::ipc::MessageType::PROCESS_CREATE,
            std::slice::from_raw_parts(
                self as *const ProcessCreationInfo as *const u8,
                std::mem::size_of::<ProcessCreationInfo>(),
            ),
        ) }?;

        unsafe {
            let mut sender: u128 = 0;
            let mut session: u64 = 0;
            let mut tag: u32 = 0;
            let mut offer: MaybeUninit<ProcessOffer> = MaybeUninit::uninit();
            let result = crate::ipc::recv_message(&mut sender, &mut session, &mut tag, std::slice::from_raw_parts_mut(
                offer.as_mut_ptr() as *mut u8,
                std::mem::size_of::<ProcessOffer>(),
            ));
            assert_eq!(result, Some(core::mem::size_of::<ProcessOffer>() + 16 + 8 + 4));
            Ok(offer.assume_init())
        }
    }
}

