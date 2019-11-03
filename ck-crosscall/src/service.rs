use crate::crosscall;

pub fn register(name: &str) -> bool {
    let name = name.as_bytes();
    if name.len() > crate::consts::MAX_SERVICE_NAME_SIZE {
        return false;
    }

    let ret = unsafe { crosscall::cc_send_message()(
        &0u128, 0u64,
        crosscall::MessageType::SERVICE_REGISTER as u32,
        name.as_ptr(),
        name.len(),
    ) };
    assert!(ret == name.len() as i32);
    let result = crosscall::wait_for_trivial_result();
    if result.code == 0 {
        true
    } else {
        false
    }
}

pub fn get(name: &str) -> Option<u128> {
    let name = name.as_bytes();
    if name.len() > crate::consts::MAX_SERVICE_NAME_SIZE {
        return None;
    }

    let ret = unsafe { crosscall::cc_send_message()(
        &0u128, 0u64,
        crosscall::MessageType::SERVICE_GET as u32,
        name.as_ptr(),
        name.len(),
    ) };
    assert!(ret == name.len() as i32);

    let result = crosscall::wait_for_trivial_result();
    if result.code == 0 {
        let desc = result.get_description().expect("failed to get encoded service pid");
        assert_eq!(desc.as_bytes().len(), 32);

        let pid = u128::from_str_radix(desc, 16).expect("failed to parse service pid");
        Some(pid)
    } else {
        None
    }
}