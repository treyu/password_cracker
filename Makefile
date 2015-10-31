bf: bruteForce.c
	gcc -Wall -o brute bruteForce.c -lcrypto -lrt

bf2: bruteForce2.c
	gcc -Wall -o brute bruteForce2.c -lcrypto -pthread -lrt

clean:
	rm -rf brute
