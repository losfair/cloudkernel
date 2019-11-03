use crate::crosscall;
use core::mem::MaybeUninit;

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

pub fn wait_process(pid: u128) -> crosscall::TrivialResult {
    let payload = ProcessWait {
        api_version: 1,
        pid: pid,
    };
    let ret = unsafe { crosscall::cc_send_message()(
        &0u128, 0u64,
        crosscall::MessageType::PROCESS_WAIT as u32,
        &payload as *const ProcessWait as *const u8,
        core::mem::size_of::<ProcessWait>(),
    ) };
    assert!(ret == core::mem::size_of::<ProcessWait>() as i32);
    crosscall::wait_for_trivial_result()
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

    pub fn send(&self) -> Result<ProcessOffer, crosscall::TrivialResult> {
        let ret = unsafe { crosscall::cc_send_message()(
            &0u128, 0u64,
            crosscall::MessageType::PROCESS_CREATE as u32,
            self as *const ProcessCreationInfo as *const u8,
            core::mem::size_of::<ProcessCreationInfo>(),
        ) };
        assert!(ret == core::mem::size_of::<ProcessCreationInfo>() as i32);
        let result = crosscall::wait_for_trivial_result();
        if result.code != 0 {
            return Err(result);
        }

        unsafe {
            let mut sender: u128 = 0;
            let mut session: u64 = 0;
            let mut tag: u32 = 0;
            let mut offer: MaybeUninit<ProcessOffer> = MaybeUninit::uninit();
            let result = crosscall::cc_recv_message()(&mut sender, &mut session, &mut tag, offer.as_mut_ptr() as *mut u8, core::mem::size_of::<ProcessOffer>());
            assert_eq!(result, core::mem::size_of::<ProcessOffer>() as i32);
            Ok(offer.assume_init())
        }
    }
}

