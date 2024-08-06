from pwn import *
import os
import time
#local file
#p=process('./magic')
p=remote('140.113.24.241',30171)
#p.interactive()

#print(p.recvline()

seed = int(time.time())
random.seed(seed)
p.recvline()

result = subprocess.run(["./random", str(seed)], capture_output=True, text=True)


#print("Python Seed:", seed) # Print the seed
#print("Output:")
output=result.stdout
#print(output)

p.sendline(output.encode('utf-8'))
#print(p.recvline())
p.recvline()
response=p.recvline()
flag= response.decode().split('\n')

for line in flag:
    if line.startswith('FLAG'):
        flag = line
        print(flag)
        break


#numbers = output.split()

# Convert each number to an integer and store it in the secret array
#secret = [int(num) for num in numbers]

#print(secret)

#p.sendline(b'1')

#p.sendlineafter(b'>>', b'1')

#p.recvuntil(b'>>')

#p.sendline(b'2')
#p.send(b'2')
#pause()

