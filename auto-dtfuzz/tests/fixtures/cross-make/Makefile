# Simulates a cross-compiled project: the production compiler is ARM GCC.
CC = arm-linux-gnueabihf-gcc
AR = ar

CFLAGS ?= -O2 -g
CFLAGS += -I$(CURDIR)/include -DMSG_PROTO_V2=1 -std=gnu11 \
          -march=armv7-a -mfloat-abi=hard -mfpu=neon

SRCS := src/msg.c
OBJS := $(SRCS:.c=.o)

all: libmsg.a

libmsg.a: $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c include/msg.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) libmsg.a
