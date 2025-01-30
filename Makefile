CC = gcc
CFLAGS = -I/usr/include -O2 -Wall
LDFLAGS = -lssl -lcrypto  # Use OpenSSL

all: prover verifier

prover: prover.c microvisor.c
	$(CC) $(CFLAGS) prover.c microvisor.c -o prover $(LDFLAGS)

verifier: verifier.c microvisor.c  # Include microvisor.c for linking
	$(CC) $(CFLAGS) verifier.c microvisor.c -o verifier $(LDFLAGS)

clean:
	rm -f prover verifier

