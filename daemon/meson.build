# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020, AT&T Intellectual Property.

daemon_sources = files(
        'configcmd.c',
        'configdb.c',
        'configstore.c',
        'devname.c',
        'fsnotify.c',
        'hwbinding.c',
        'main.c',
        'mnlutil.c',
        'mrtstat.c',
        'nlmsg.c',
        'parser.c',
        'port.c',
        'protobuf.c',
        'request.c',
        'snapshot.c',
        'team.c',
        'topic.c',
        'tunnel.c',
        'util.c',
        'vplane.c'
)

executable(
        'vplaned',
        sources: [daemon_sources, controller_protobuf_c],
        dependencies: [
                b64_dep,
                ini_dep,
                czmq_dep,
                json_dep,
                mnl_dep,
                vrfmanager_dep,
                systemd_dep,
                zmq_dep,
                proto_c_dep,
                jemalloc_dep,
        ],
        install: true,
        install_dir : '/opt/vyatta/sbin'
)
