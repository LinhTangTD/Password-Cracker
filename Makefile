CC := clang
CFLAGS := -g -Wall -Werror
CFLAGSS := -g -Wall -Werror

# Special settings for macOS users. This assumes you installed openssl with the brew package manager
SYSTEM := $(shell uname -s)
ifeq ($(SYSTEM),Darwin)
  CFLAGS += -I$(shell brew --prefix openssl)/include -L$(shell brew --prefix openssl)/lib
  CFLAGSS += -I$(shell brew --prefix openssl)/include
endif

all: password-cracker

password-cracker: password-cracker.o password.o
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto -lpthread -lm

password-cracker.o: password-cracker.c password.h
	$(CC) $(CFLAGSS) -c $< 

password.o: password.c password.h
	$(CC) $(CFLAGSS) -c $<

clean:
	rm -rf password-cracker password-cracker.dSYM