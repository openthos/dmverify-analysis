
CC=	gcc
CPP=	$(CC) -E
CFLAGS = -Wall -D_DEBUG -ggdb3 -ldl
INCLUDES= -I. -I/usr/local/include
LIBS = /usr/local/lib/libcrypto.a
LIBS += /usr/lib/x86_64-linux-gnu/libpthread.so
LIBS += /usr/lib/x86_64-linux-gnu/libdl.so

#LIBS = /usr/lib/x86_64-linux-gnu/libssl3.so
#LIBS += /usr/lib/x86_64-linux-gnu/libcrypt.so

objects = apps.o main.o
sign : $(objects)
	$(CC) $(CFLAGS) -o sign $(objects) $(LIBS)

main.o : main.cpp apps.h xsign.h
	$(CC) -c $(CFLAGS) main.cpp $(INCLUDES)

apps.o : apps.cpp apps.h xsign.h
	$(CC) -c $(CFLAGS) apps.cpp $(INCLUDES)

clean:
	rm sign apps.o main.o
