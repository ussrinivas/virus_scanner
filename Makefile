all: virus_scanner

CC=gcc

virus_scanner: virus_scanner.c
	$(CC) -g -c virus_scanner.c
	gcc -o virus_scanner virus_scanner.o

clean:
	rm -f *.o virus_scanner *~
