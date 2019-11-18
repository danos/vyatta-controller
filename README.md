# DANOS dataplane controller

The controller acts as a conduit between "applications" (configuration,
routing) and the dataplane (__vplane__). The controller daemon
(__vplaned__) consists of a number of connections:

* NETLINK connections into the kernel in order to receive (routing,
IPsec, L2TP & TEAM) updates. Note that only non-unicast routes are
retrived from the kernel, unicast routes are published __directly__ to
the dataplane by RIBd (the route broker).

* A Command Proxy (ZMQ REQUEST-REPLY) connection used to receive
additional configuration information (see Configuration Database)

* A Request (ZMQ ROUTER-DEALER) connection to one or more dataplane
processes. The connection is used by a dataplane to register itself and
its associated local interfaces.

* A Publication (ZMQ PUB-SUB) connection to one or more dataplane
processes. The connection is used to publish ("broadcast") configuration
updates to dataplanes.

* A Query (ZMQ REQUEST-REPLY) connection. The connection allows
applications to request operational state (e.g. list of dataplane
instances) and configuration information (e.g. current IP address) from
the controller.

The control-plane between __vplaned__ and __vplane__ operates
over a series of local IPC channels (the Request and Publication
connections).

## Licensing

The controller is licensed under GNU LGPL-2.1.

## Snapshot Database

The controller maintains a snapshot database that consists of the
netlink messages received from the kernel, arranged as a series of lists
and hash tables.

Each received netlink message is parsed in order to produce a "topic" (a
string representation of the message contents). The combined object
(topic string + netlink data) is inserted into the snapshot database and
published directly to any/all connected dataplane(s).

The object topic is used as the key in an associated hash table.

Following initial contact with the controller a dataplane asks for the
current system configuration - a "__WHATSUP?__" request message. The
controller responds by "dumping" the contents of the database down to
the dataplane. The leading word of the topic string is used by the
dataplane to dispatch the object to the appropriate subsystem.

## Configuration Database

Whilst the majority of the network configuration can be represented
through netlink messages, there are elements of application state that
require additional configuration.

The configuration store (__cstore__) consists of a key-value
database. Applications (YANG backend scripts) use a Perl or Python API
to inject a JSON encoded message into the controller. The message
consists of two parts, a key (or path) and a value. The value part is an
arbitrary string that is passed down (published) to the dataplane for
processing by the control module.

Other than certain parts of the path element, the controller has no
understanding of the message; the message is simply stored and the value
part forwarded to the dataplane. Similar to netlink messages, the
dataplane uses the leading word of the value part to dispatch the
message to the appropriate subsystem.

For example, this is the "raw" JSON as processed by the Controller:

```
{"policy":{"route":{"pbr":{"cust1":{"rule":{"10":{"__SET__":
	"npf-cfg add pbr:cust1 10 action=accept family=inet dst-addr=192.168.102.0/24 rproc=pathmon(cust1,cust1) tag=1 ",
	"__INTERFACE__":"ALL"}
	 }
    }
   }
  }
 }
}
```

And this is the command ("topic" and "value") that is published to the
dataplane:

```
Publish [119] 'npf-cfg add ', 'npf-cfg add pbr:cust1 10 action=accept family=inet dst-addr=192.168.102.0/24 rproc=pathmon(cust1,cust1) tag=1 '
```

The Perl and Python library modules can be found in the
vyatta-cfg-dataplane repository.

As with the Snapshot Database, in response to a "__WHATSUP?__" request,
the controller pushes down the contents of the __cstore__ database to
the dataplane.

## Snapshot utility

The snapshot utility ('/opt/vyatta/bin/snapshot') can be used to dump
the contents of the snapshot database maintained by the controller.

```
vyatta@vyatta:~$ /opt/vyatta/bin/snapshot --help
Usage: snapshot [OPTION...]

vPlaned snapshot.

-d, --debug       Include topic information
-c, --cstore      Dump the cstore database
-i, --ifindex     Dump specified ifindex only
-h, --help        Display help and exit

vyatta@vyatta:~$ 
```

By default the utility will collect the netlink details and feed them
into ip monitor:

```
vyatta@vyatta:~$ /opt/vyatta/bin/snapshot
[LINK]12: lo1: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN group default 
    link/ether d2:ae:37:94:3e:8e brd ff:ff:ff:ff:ff:ff
[LINK]12: lo1: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 state UNKNOWN 
    link/ether d2:ae:37:94:3e:8e
[LINK]7: .spathintf: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default 
    link/none 
[LINK]1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
:
:
[NETCONF]mpls dev lo input off 
[NETCONF]ipv4 dev dp0p1s1.103 forwarding on rp_filter off mc_forwarding off proxy_neigh off ignore_routes_with_linkdown off 
[NETCONF]ipv4 dev lo1 forwarding on rp_filter off mc_forwarding off proxy_neigh off ignore_routes_with_linkdown off 
vyatta@vyatta:~$ 
```

The '--cstore' option will display the contents of the cstore database:

```
vyatta@vyatta:~$ /opt/vyatta/bin/snapshot -c
[32] mpls labeltablesize 0

[33] mpls defaultttl 255

[34] mpls ipttlpropagate enable
[109] ecmp mode hrw
[129] npf-cfg add dscp-group:default-group-high-drop 0 8;10;16;18
[132] npf-cfg add dscp-group:default-group-low-drop 0 0;1;2;3;4;5;6;7;9;11;12;13;14;15;17;19;20;21;22;23;41;42;43;44;45;49;50;
:
:
[2346] qos 11 enable
[2680] THATSALLFOLKS!
vyatta@vyatta:~$ 
```
 
## Dataplane Database

The controller (__vplaned__) derives a core set of attributes from its
configuration file (__/etc/vyatta/controller.conf__). Among the
attributes is the local IP address of the __vplaned__ daemon together
with a list of defined dataplane (__vplane__) instances. For each
instance the file defines the IP address of the __vplane__ together with
its __UUID__.

There is a single defined __vplane__. The IP address of
both controller and __vplane__ is the loopback address (127.0.0.1) and
the __UUID__ is simply zero (00000000-0000-0000-0000-000000000000).

The dataplane makes contact with the controller via the Request
connection.

* The controller establishes its authenticity (UUID match together with
  any ZMQ socket authentication) - "__CONNECT__", "__ACCEPT__" and
  "__CONFQUERY__" messages.

* The dataplane reports on each of its hardware interfaces -
  "__NEWPORT__" messages. The "__NEWPORT__" message is used to create
  the "local" interface representation, e.g. dp0p1s1 or dp2p1s3.

* The dataplane requests the current system configuration - "__WHATSUP?__" message.

## Unit Testing

The unit tests are executed as part of the default package build and
__must__ be kept passing with every commit.

You should consider adding unit tests for any new functionality being added.

The tests are built around the [CppUTest][3] harness and typically
exercise the (external) functions associated with a single module.

## Coding Style

Code conforms to the [linux kernel coding style][1], and [checkpatch][2]
can be used to find common style issues. Probably the easiest way to
check an update is to use the wrapper provided by the dataplane
(`vyatta-dataplane/scripts/checkpatch_wrapper.sh`)

Please fix any warnings it reports, or be prepared to justify the exception
during code review.

[1]: https://www.kernel.org/doc/Documentation/CodingStyle "Linux Kernel Coding Style"
[2]: https://github.com/torvalds/linux/blob/master/scripts/checkpatch.pl "checkpatch script"
[3]: http://cpputest.github.io/ "Cpputest Unit Test Framework"
