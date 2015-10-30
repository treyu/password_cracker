bf: bruteForce.c
	gcc -Wall -o brute bruteForce.c -lcrypto

bf2: bruteForce2.c
	gcc -Wall -o brute bruteForce2.c -lcrypto -pthread

clean:
	rm -rf brute
