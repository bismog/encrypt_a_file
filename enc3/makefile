default: all
obj = aes_modes.o aescrypt.o aeskey.o aestab.o encrypt.o

encfile.o: encfile.c
decfile.o: decfile.c
all : $(obj) encfile.o decfile.o
	gcc -g -o encfile encfile.o $(obj)
	gcc -g -o decfile decfile.o $(obj)

.PHONY : clean
clean :
	-rm edit $(objects)
