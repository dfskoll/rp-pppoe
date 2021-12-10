all: testevent

testevent: testevent.o ../event.o
	gcc -o testevent testevent.o ../event.o

testevent.o: testevent.c
	gcc -c -o testevent.o -g testevent.c
