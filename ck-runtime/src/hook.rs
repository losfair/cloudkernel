use nix::sys::signal::{sigaction, Signal, SigAction, SigHandler, SaFlags, SigSet};
use sc::nr;
use libc::{c_int, c_void, siginfo_t};

#[naked]
#[inline(never)]
unsafe extern "C" fn enable_syscall_hook() {
    // CK_SYS_NOTIFY_INVALID_SYSCALL
    asm!(
        r#"
            movq $$0xffff0302, %rax
            syscall
            ret
        "# :::: "volatile"
    );
}

extern "C" fn on_sigsys(sig_id: c_int, _siginfo: *mut siginfo_t, ucontext: *mut c_void) {
    use libc::{
        ucontext_t, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15, REG_R8,
        REG_R9, REG_RAX, REG_RBP, REG_RBX, REG_RCX, REG_RDI, REG_RDX, REG_RIP, REG_RSI, REG_RSP,
    };

    unsafe {
        let ucontext = ucontext as *mut ucontext_t;
        let gregs = &mut (*ucontext).uc_mcontext.gregs;
        let sc_nr = gregs[REG_RAX as usize] as usize;
        match sc_nr {
            nr::SOCKET => {
                let family = gregs[REG_RDI as usize] as i32;
                let ty = gregs[REG_RSI as usize] as i32;
                let protocol = gregs[REG_RDX as usize] as i32;
                println!("socket({}, {}, {})", family, ty, protocol);
                std::process::abort();
            }
            _ => {
                println!("Fatal error: Unknown system call: {}", sc_nr);
                std::process::abort();
            }
        }
    }
}

pub unsafe fn register_hooks() {
    sigaction(
        Signal::SIGSYS,
        &SigAction::new(SigHandler::SigAction(on_sigsys), SaFlags::empty(), SigSet::empty())
    ).unwrap();
    enable_syscall_hook();
}
