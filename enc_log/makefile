default: all
obj = aes_modes.o aescrypt.o aeskey.o aestab.o encrypt.o

encfile.o: encfile.c
decfile.o: decfile.c
all : $(obj) encfile.o decfile.o
	gcc -g -o encfile encfile.o $(obj)
	gcc -g -o decfile decfile.o $(obj)
	gcc -g -o upenc update_enc_file.c ${obj}

up2:
	gcc -g -o up2 update_enc_file.c encrypt.c aes_modes.c aescrypt.c aeskey.c aestab.c

.PHONY : clean
clean :
	-rm *.o upenc encfile decfile
