FLAGS=-O2 -Wall

clean:
	rm bin/*

all: daemon

daemon: bin/iwutils.o bin/main.o 
	gcc $(FLAGS) bin/iwutils.o bin/main.o -lm -o bin/rtx
	
bin/main.o: src/main.c src/iwutils.h
	gcc $(FLAGS) -c src/main.c -o bin/main.o

bin/iwutils.o: src/iwutils.c src/iwutils.h
	gcc $(FLAGS) -c src/iwutils.c -o bin/iwutils.o
