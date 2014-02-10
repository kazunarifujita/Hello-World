
LD	      = gcc

LDFLAGS	      = -DLinux -m64 -fPIC

LIBS	      = 

INCLUDE	      = -I./
#INCLUDE	      = -I./ -I../islib/include

#ISLIB         = ../islib/src/islib.a

MAKEFILE      = Makefile

#OBJS	      = dfwinterface.o
OBJS	      = islib.o

PROGRAM       = islib

INST_LIB      = DfwExit

#SRCS	      = dfwinterface.c
SRCS	      = islib.c

all:		$(PROGRAM)

$(PROGRAM):     $(OBJS)
		gcc -shared -o $(PROGRAM).a $(OBJS)
#		gcc -shared -o lib$(PROGRAM).sl $(OBJS) $(LIBS)

.c.o:
		$(LD) $(CC_CMD) $(LDFLAGS) $(INCLUDE) -c $(SRCS)

debug:
	make CC_CMD="-DDEBUG -g"

clean:
	rm -f $(OBJS) $(PROGRAM).a
#	rm -f $(OBJS) lib$(PROGRAM).sl core

install:
#	cp -p lib$(PROGRAM).sl ../lib/lib$(INST_LIB).sl
#	rm -f ../lib/lib$(INST_LIB).so
#	ln -s ../lib/lib$(INST_LIB).sl ../lib/lib$(INST_LIB).so

###
#dfwintface.o: ./dfwinterface.h
