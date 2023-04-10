genseed: genseed.c
	$(CC) $(CFLAGS) -o genseed genseed.c

dgp-simple: dgp-simple.c
	$(CC) $(CFLAGS) -o dgp-simple dgp-simple.c -lcrypto

all: genseed dgp-simple
