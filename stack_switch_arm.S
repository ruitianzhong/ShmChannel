// date: Mar.24, 2025
// aarch64-compatible stack switch implementation

.text
.globl SaveStack
.type SaveStack, @function

// save stack to address pointed to by x0
// WARNING: Since ARM has more registers to save
//          remember to check length of RegSet!
SaveStack:
    // float point callee-saved registers
    stp  d8,  d9,  [x0, #0x00]
    stp  d10, d11, [x0, #0x10]
    stp  d12, d13, [x0, #0x20]
    stp  d14, d15, [x0, #0x30]

    // int callee-saved registers
    stp  x19, x20, [x0, #0x40]
    stp  x21, x22, [x0, #0x50]
    stp  x23, x24, [x0, #0x60]
    stp  x25, x26, [x0, #0x70]
    stp  x27, x28, [x0, #0x80]
    // nb: x30 is the link register
    stp  x29, x30, [x0, #0x90]
    // save stack pointer. Note `bl` does not push anything on stack
    // (arm pass return address by register), so sp is left as is 
    // until local variables are reserved
    // also note sp cannot be used as argument to stp
    mov  x1, sp
    str  x1, [x0, #0xa0]

    // 16*11 = 176 bytes in total

    // return 0 since we are saving
    mov  xzr, x0
    ret

.globl RestoreStack
.type RestoreStack, @function
RestoreStack:
    ldp  d8,  d9,  [x0, #0x00]
    ldp  d10, d11, [x0, #0x10]
    ldp  d12, d13, [x0, #0x20]
    ldp  d14, d15, [x0, #0x30]
    ldp  x19, x20, [x0, #0x40]
    ldp  x21, x22, [x0, #0x50]
    ldp  x23, x24, [x0, #0x60]
    ldp  x25, x26, [x0, #0x70]
    ldp  x27, x28, [x0, #0x80]
    ldp  x29, x30, [x0, #0x90]
    ldr  x1, [x0, #0xa0]
    mov  sp, x1

    mov  x0, #0x1
    // on x86 we cannot directly `ret` since ip is no longer on stack
    // but here, since saved address is again pushed into x30
    // we are safe to do that
    ret

.globl StackSwitchAsm
.type StackSwitchAsm, @function
StackSwitchAsm:
    // x0: src stack | x1: dst stack
    stp  d8,  d9,  [x0, #0x00]
    stp  d10, d11, [x0, #0x10]
    stp  d12, d13, [x0, #0x20]
    stp  d14, d15, [x0, #0x30]
    stp  x19, x20, [x0, #0x40]
    stp  x21, x22, [x0, #0x50]
    stp  x23, x24, [x0, #0x60]
    stp  x25, x26, [x0, #0x70]
    stp  x27, x28, [x0, #0x80]
    stp  x29, x30, [x0, #0x90]
    // remember to not mess with argument register
    mov  x2, sp
    str  x2, [x0, #0xa0]

    ldp  d8,  d9,  [x1, #0x00]
    ldp  d10, d11, [x1, #0x10]
    ldp  d12, d13, [x1, #0x20]
    ldp  d14, d15, [x1, #0x30]
    ldp  x19, x20, [x1, #0x40]
    ldp  x21, x22, [x1, #0x50]
    ldp  x23, x24, [x1, #0x60]
    ldp  x25, x26, [x1, #0x70]
    ldp  x27, x28, [x1, #0x80]
    ldp  x29, x30, [x1, #0x90]
    ldr  x2, [x1, #0xa0]
    mov  sp, x2

    mov x0, #0x1
    ret