rm -rf enctool

gcc -o enctool encmain.c aescrypt.c aeskey.c aes_modes.c aestab.c encrypt.c

echo "done"
