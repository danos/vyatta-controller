# Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2012-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only

CPPFLAGS += -D_GNU_SOURCE -I ../lib
CFLAGS += -g
CFLAGS += $(shell pkg-config --cflags libczmq json-c)
CFLAGS += $(shell pkg-config --cflags libedit)
CFLAGS += $(shell pkg-config --cflags libmnl)

         LIBS += -L../lib -lvplaned
         LIBS += $(shell pkg-config --libs libczmq json-c)
   VPLSH_LIBS  = $(LIBS) $(shell pkg-config --libs libedit)
SNAPSHOT_LIBS  = $(LIBS) $(shell pkg-config --libs libmnl)

   VPLSH_OBJS = vplsh.o
SNAPSHOT_OBJS = snapshot.o

all: vplsh snapshot

vplsh: $(VPLSH_OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ \
	      $(VPLSH_OBJS) $(VPLSH_LIBS)

snapshot: $(SNAPSHOT_OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ \
	      $(SNAPSHOT_OBJS) $(SNAPSHOT_LIBS)

clean:
	rm -f $(VPLSH_OBJS) $(SNAPSHOT_OBJS) vplsh snapshot

install: vplsh snapshot
	install vplsh $(DESTDIR)/opt/vyatta/bin
	install snapshot $(DESTDIR)/opt/vyatta/bin
