CC = gcc
CFLAGS = -O2 -Wall -static

dirtier: dirtier.c
	$(CC) $(CFLAGS) -o $@ $<

busy_cpu: busy_cpu.c
	$(CC) $(CFLAGS) -pthread -o $@ $<

clean:
	rm -f dirtier busy_cpu

.PHONY: clean