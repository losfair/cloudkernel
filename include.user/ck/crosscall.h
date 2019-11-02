#pragma once

#define _QUOTE(x) #x
#define _STR(x) _QUOTE(x)

static unsigned long __attribute__((naked)) FixupSyscall(const char *name, void *data) {
    asm(
        "movq $20000, %rax\n"
        "syscall\n"
        "movq %rax, (%rsi)\n"
        "ret\n"
    );
}

#define CROSSCALL0(__funcname__, __sysname__) \
    static inline int __funcname__() { \
        static int (*f)() = 0; \
        return (f ? f : ((int (*) ()) FixupSyscall(__sysname__, (void *) &f)))(); \
    }

#define CROSSCALL1(__funcname__, __sysname__) \
    static inline int __funcname__(unsigned long a) { \
        static int (*f)(unsigned long) = 0; \
        return (f ? f : ((int (*) (unsigned long)) FixupSyscall(__sysname__, (void *) &f)))(a); \
    }

#define CROSSCALL2(__funcname__, __sysname__) \
    static inline int __funcname__(unsigned long a, unsigned long b) { \
        static int (*f)(unsigned long, unsigned long) = 0; \
        return (f ? f : ((int (*) (unsigned long, unsigned long)) FixupSyscall(__sysname__, (void *) &f)))(a, b); \
    }

CROSSCALL2(kSendMessage, "kernel_0.0.0/SendMessage");
CROSSCALL2(kRecvMessage, "kernel_0.0.0/RecvMessage");
