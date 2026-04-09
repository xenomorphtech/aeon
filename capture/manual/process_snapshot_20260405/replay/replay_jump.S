.text
.align 2
.global replay_jump
.type replay_jump, %function
replay_jump:
    mov x17, x0

    ldr x1,  [x17, #(8 * 1)]
    ldr x2,  [x17, #(8 * 2)]
    ldr x3,  [x17, #(8 * 3)]
    ldr x4,  [x17, #(8 * 4)]
    ldr x5,  [x17, #(8 * 5)]
    ldr x6,  [x17, #(8 * 6)]
    ldr x7,  [x17, #(8 * 7)]
    ldr x8,  [x17, #(8 * 8)]
    ldr x9,  [x17, #(8 * 9)]
    ldr x10, [x17, #(8 * 10)]
    ldr x11, [x17, #(8 * 11)]
    ldr x12, [x17, #(8 * 12)]
    ldr x13, [x17, #(8 * 13)]
    ldr x14, [x17, #(8 * 14)]
    ldr x15, [x17, #(8 * 15)]

    ldr x18, [x17, #(8 * 18)]
    ldr x19, [x17, #(8 * 19)]
    ldr x20, [x17, #(8 * 20)]
    ldr x21, [x17, #(8 * 21)]
    ldr x22, [x17, #(8 * 22)]
    ldr x23, [x17, #(8 * 23)]
    ldr x24, [x17, #(8 * 24)]
    ldr x25, [x17, #(8 * 25)]
    ldr x26, [x17, #(8 * 26)]
    ldr x27, [x17, #(8 * 27)]
    ldr x28, [x17, #(8 * 28)]
    ldr x29, [x17, #(8 * 29)]
    ldr x30, [x17, #(8 * 30)]

    ldr x9,  [x17, #(8 * 31)]
    mov sp, x9

    ldr x16, [x17, #(8 * 32)]
    ldr x0,  [x17, #(8 * 0)]
    ldr x17, [x17, #(8 * 17)]

    br x16
.size replay_jump, .-replay_jump
