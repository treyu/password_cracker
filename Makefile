bf: bruteForce.c
	gcc -Wall -o brute bruteForce.c -lcrypt -lcrypto

bf2: bruteForce2.c
	gcc -Wall -o brute bruteForce2.c -lcrypt -lcrypto

clean:
	rm -rf brute
