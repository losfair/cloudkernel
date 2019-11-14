use std::marker::PhantomData;
use std::mem::MaybeUninit;

#[repr(packed)]
#[derive(Copy, Clone)]
pub struct ProcessCreationInfo<'a> {
    _api_version: u32,
    argc: u32,
    argv: *const KString,
    _phantom: PhantomData<&'a ()>,
}

#[repr(packed)]
#[derive(Copy, Clone)]
pub struct KString {
    rptr: *const u8,
    len: u64,
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
                movq $$0x1f0309, %rax
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

pub fn create(_args: &[String]) -> Result<u128, String> {
    let args: Vec<KString> = _args
        .iter()
        .map(|x| {
            let x = x.as_bytes();
            KString {
                rptr: x.as_ptr(),
                len: x.len() as u64,
            }
        })
        .collect();
    let mut info = ProcessCreationInfo {
        _api_version: 1,
        argc: args.len() as u32,
        argv: args.as_ptr(),
        _phantom: PhantomData,
    };

    unsafe {
        crate::ipc::trivial_kernel_request(
            crate::ipc::KernelMessageType::PROCESS_CREATE,
            std::slice::from_raw_parts(
                &info as *const ProcessCreationInfo as *const u8,
                std::mem::size_of::<ProcessCreationInfo>(),
            ),
        )
    }?;

    let offer = unsafe {
        let mut sender: u128 = 0;
        let mut session: u64 = 0;
        let mut tag: u32 = 0;
        let mut offer: MaybeUninit<ProcessOffer> = MaybeUninit::uninit();
        let result = crate::ipc::recv_message(
            &mut sender,
            &mut session,
            &mut tag,
            std::slice::from_raw_parts_mut(
                offer.as_mut_ptr() as *mut u8,
                std::mem::size_of::<ProcessOffer>(),
            ),
        );
        assert_eq!(result, Some(core::mem::size_of::<ProcessOffer>()));
        offer.assume_init()
    };
    Ok(offer.pid)
}
