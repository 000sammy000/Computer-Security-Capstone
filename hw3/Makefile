CRACK  = crack_attack
SERVER = attacker_server

CRACK_FILE  = crack_attack.py
SERVER_FILE = attacker_server.py

LS  = ls
ZIP   = ls.xz
ORIG = ../../../bin/ls
WORM = worm.sh

all: $(CRACK) $(SERVER)

$(CRACK): $(CRACK_FILE)
	cp $< $@ && chmod +x $@

$(SERVER): $(SERVER_FILE)
	cp $< $@ && chmod +x $@

clean:
	rm $(CRACK) $(SERVER) $(LS)