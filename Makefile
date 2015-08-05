CFLAGS=-Wall
LIBS=-lev
OBJ = http_parser.c server_eh.c main.c

all: mikita

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

mikita: $(OBJ)
	cc -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f *.o *~ core mikita 