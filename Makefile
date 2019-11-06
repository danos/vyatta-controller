DESTDIR=
SUBDIRS = lib client daemon snmp test/example
CHECK_SUBDIRS=test/module
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -Wmissing-prototypes -Wredundant-decls

all:
	@set -e; for i in $(SUBDIRS); \
	do $(MAKE) $(MFLAGS) -C $$i; done

check:
	@for i in $(CHECK_SUBDIRS); \
	do $(MAKE) -C $$i; done

install:
	install -m 0755 -d $(DESTDIR)/opt/vyatta/sbin $(DESTDIR)/opt/vyatta/bin
	@set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i install; done

clean:
	@for i in $(SUBDIRS); \
	do $(MAKE) $(MFLAGS) -C $$i clean; done
