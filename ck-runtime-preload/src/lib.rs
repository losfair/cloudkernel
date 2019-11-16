#![feature(link_args)]
#![link_args = "-Wl,-init,ckrt_init"]

#[no_mangle]
pub unsafe extern "C" fn ckrt_init() {
    ck_runtime::ip::start();
}
