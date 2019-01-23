#!/bin/sh
set -eu

rm -f output.*-*

seq 2345 >input.txt
#<input.txt openssl enc -pbkdf2 -aes128 -S 00123456789abcde -pass pass:pass >input.dat
<input.txt tr 0 '\0' >input.dat

gpg --sign                --output output.txt.inline-binary input.txt
gpg --clearsign           --output output.txt.inline-armour input.txt
gpg --detach-sig          --output output.txt.detach-binary input.txt
gpg --detach-sig --armour --output output.txt.detach-armour input.txt

gpg --sign                --output output.dat.inline-binary input.dat
gpg --clearsign           --output output.dat.inline-armour input.dat
gpg --detach-sig          --output output.dat.detach-binary input.dat
gpg --detach-sig --armour --output output.dat.detach-armour input.dat
