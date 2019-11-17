#![feature(link_args)]
#![link_args = "-Wl,-init,ckrt_init"]

extern "C" {
    fn getpid() -> i32;
}

#[no_mangle]
pub unsafe extern "C" fn ckrt_init() {
    if getpid() != 1 {
        return;
    }
    ck_runtime::ip::start();
}
