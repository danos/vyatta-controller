# Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2012-2016, Vyatta Inc
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only

# binary name
NAME = vplane-snmp

CPPFLAGS += -D_GNU_SOURCE -I ../lib
CFLAGS += -g
CFLAGS += $(shell pkg-config --cflags libczmq json-c)

OBJS  = $(NAME).o
LIBS += -L../lib -lvplaned
LIBS += $(shell pkg-config --libs libczmq json-c)

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $(NAME) $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS) $(NAME)

install: $(NAME)
	install $(NAME) $(DESTDIR)/opt/vyatta/sbin
