use std::marker::PhantomData;
use std::mem::MaybeUninit;

#[repr(packed)]
#[derive(Copy, Clone)]
struct ProcessCreationInfo<'a> {
    _api_version: u32,
    argc: u32,
    argv: *const KString<'a>,
    n_capabilities: u32,
    capabilities: *const KString<'a>,
    n_storage_groups: u32,
    storage_groups: *const KString<'a>,
}

#[repr(packed)]
#[derive(Copy, Clone)]
struct KString<'a> {
    rptr: *const u8,
    len: u64,
    _phantom: PhantomData<&'a ()>,
}

#[repr(packed)]
#[derive(Copy, Clone, Debug)]
struct ProcessOffer {
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

fn collect_strings<'a, T: AsRef<str>>(x: &'a [T]) -> Vec<KString<'a>> {
    x.iter()
        .map(|x| {
            let x = x.as_ref().as_bytes();
            KString {
                rptr: x.as_ptr(),
                len: x.len() as u64,
                _phantom: PhantomData,
            }
        })
        .collect()
}

pub fn create(
    _args: &[String],
    _caps: &[String],
    _storage_groups: &[String],
) -> Result<u128, String> {
    let args: Vec<KString> = collect_strings(_args);
    let caps: Vec<KString> = collect_strings(_caps);
    let storage_groups: Vec<KString> = collect_strings(_storage_groups);

    let mut info = ProcessCreationInfo {
        _api_version: 1,
        argc: args.len() as u32,
        argv: args.as_ptr(),
        n_capabilities: caps.len() as u32,
        capabilities: caps.as_ptr(),
        n_storage_groups: storage_groups.len() as u32,
        storage_groups: storage_groups.as_ptr(),
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
