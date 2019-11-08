pub fn snapshot_me() -> i32 {
    #[naked]
    #[inline(never)]
    #[no_mangle]
    unsafe extern "C" fn do_snapshot() -> i32 {
        asm!(
            r#"
                movq $$0xffff0308, %rax
                syscall
                retq
            "# :::: "volatile"
        );
        loop {}
    }
    unsafe {
        do_snapshot()
    }
}
