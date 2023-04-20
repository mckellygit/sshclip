
CC = gcc
CFLAGS = -Wall -O1 -g
LIBS = -lcrypto -lssl

all: sshclipserver sshclip

sshclip: sshclip.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

sshclipserver: sshclipserver.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

clean:
	rm -f sshclip.o sshclip sshclipserver.o sshclipserver

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

install: sshclip sshclipserver
	./sshclipserver -x || true
	install -m 755 sshclip       $(DESTDIR)$(PREFIX)/bin
	install -m 755 sshclipserver $(DESTDIR)$(PREFIX)/bin

# valgrind --leak-check=full --show-leak-kinds=all ./sshclipserver
# valgrind --leak-check=full --show-leak-kinds=all ./sshclip

