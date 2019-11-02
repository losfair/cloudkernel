#pragma once

#define _QUOTE(x) #x
#define _STR(x) _QUOTE(x)

unsigned long __attribute__((naked)) fixup_syscall(const char *name, void *data) {
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
        return (f ? f : ((int (*) ()) fixup_syscall(__sysname__, (void *) &f)))(); \
    }

#define CROSSCALL1(__funcname__, __sysname__) \
    static inline int __funcname__(unsigned long a) { \
        static int (*f)(unsigned long) = 0; \
        return (f ? f : ((int (*) (unsigned long)) fixup_syscall(__sysname__, (void *) &f)))(a); \
    }

#define CROSSCALL2(__funcname__, __sysname__) \
    static inline int __funcname__(unsigned long a, unsigned long b) { \
        static int (*f)(unsigned long, unsigned long) = 0; \
        return (f ? f : ((int (*) (unsigned long, unsigned long)) fixup_syscall(__sysname__, (void *) &f)))(a, b); \
    }

CROSSCALL2(kDebugLog, "kernel_0.0.0/DebugLog");