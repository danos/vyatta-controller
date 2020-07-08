# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020, AT&T Intellectual Property.

vplaned_library_sources = files(
        'vplaned_cfg.c',
        'vplaned_cstore.c',
        'vplaned_event.c'
)

dataplane_protobuf_c = custom_target('dataplane_protobuf_c',
        input: '/usr/share/vyatta-dataplane/protobuf/DataplaneEnvelope.proto',
        output: ['DataplaneEnvelope.pb-c.c', 'DataplaneEnvelope.pb-c.h'],
        command: [protoc, '--proto_path=/usr/share/vyatta-dataplane/protobuf/', '--c_out=@OUTDIR@', '@INPUT@'],
)

vplaned_library = library(
        'vplaned',
        sources: [vplaned_library_sources, dataplane_protobuf_c, controller_protobuf_c],
        dependencies: [
                czmq_dep,
                json_dep,
                proto_c_dep,
                b64_dep,
                jemalloc_dep,
        ],
        install: true,
        soversion: 1
)

vplaned_dep = declare_dependency(
   link_with: vplaned_library,
   include_directories: include_directories('.')
)

install_headers(
        'vplaned_cfg.h',
        'vplaned_cstore.h',
        'vplaned_event.h',
        'vplaned.h'
)

pkg = import('pkgconfig')
pkg.generate(vplaned_library, filebase: 'libvplaned')
