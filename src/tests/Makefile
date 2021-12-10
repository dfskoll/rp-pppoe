all: testevent

testevent: testevent.o ../libevent/event.o
	gcc -o testevent testevent.o ../libevent/event.o

testevent.o: testevent.c
	gcc -c -I ../libevent -o testevent.o -g testevent.c
