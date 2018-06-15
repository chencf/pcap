all:test.c
	gcc -g -Wall -o test test.c -lpcap
	gcc -g -Wall -o printall printall.c -lpcap

clean:
	rm -rf *.o test printall