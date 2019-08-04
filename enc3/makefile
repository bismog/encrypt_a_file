
obj = aes_modes.o aescrypt.o aeskey.o aestab.o encrypt.o

encfile.o: encfile.c
decfile.o: decfile.c
all : $(obj) encfile.o decfile.o
	cc -o encfile encfile.o $(obj)
	cc -o decfile decfile.o $(obj)

.PHONY : clean
clean :
	-rm edit $(objects)
