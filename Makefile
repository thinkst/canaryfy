CC = gcc
CFLAGS = 
LIBS = -lm 
#DEFINES="-DLOWPID"
#DEFINES="-DDEBUG"

all: 
	$(CC) $(CFLAGS) $(DEFINES) -o canaryfy canaryfy.c base32.c $(LIBS)
