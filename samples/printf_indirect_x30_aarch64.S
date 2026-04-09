.text
.align 2

.global indirect_printf_x30
.type indirect_printf_x30, %function
indirect_printf_x30:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    adrp x30, :got:printf
    ldr x30, [x30, #:got_lo12:printf]
    adrp x0, fmt1
    add x0, x0, :lo12:fmt1
    mov x1, #1
    blr x30

    adrp x30, :got:printf
    ldr x30, [x30, #:got_lo12:printf]
    adrp x0, fmt2
    add x0, x0, :lo12:fmt2
    mov x1, #2
    mov x2, #3
    blr x30

    ldp x29, x30, [sp], #16
    ret
.size indirect_printf_x30, .-indirect_printf_x30

.global main
.type main, %function
main:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    bl indirect_printf_x30
    mov w0, #0
    ldp x29, x30, [sp], #16
    ret
.size main, .-main

.section .rodata
fmt1:
    .asciz "indirect printf x30 #1: %d\n"
fmt2:
    .asciz "indirect printf x30 #2: %d %d\n"
