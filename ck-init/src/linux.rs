#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Timespec {
    pub tv_sec: usize,
    pub tv_nsec: usize,
}

pub fn nanosleep(ts: &Timespec) {
    unsafe {
        let ptr = ts as *const Timespec as usize;
        syscall!(NANOSLEEP, ptr);
    }
}
