# sudo ./sol.sh
#dd if="Matryoshka dolls.jpg" bs=1 skip=31674 of=hidden.zip
dd if="Matryoshka dolls.jpg" bs=1 skip=27358 of=hidden.zip

# Unzip the extracted archive
unzip hidden.zip

rm hidden.zip

mv flag.txt flag.png

# Optional: Display the PNG image
# You may need to install an image viewer like eog for this command to work
eog flag.png &
