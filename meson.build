# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020, AT&T Intellectual Property.

project('vyatta-controller', ['c', 'cpp'],
        default_options: [
                'buildtype=debug',
                'werror=true',
                'warning_level=2',
                'c_std=gnu11'
        ]
)

cc = meson.get_compiler('c')
add_project_arguments(
        '-Wall', '-Wextra', '-Werror',
        '-Wmissing-prototypes', '-Wredundant-decls',
        '-D_GNU_SOURCE',
        cc.get_supported_arguments([
                '-Wno-stringop-overflow',
                '-Wno-stringop-truncation',
                '-Wno-format-truncation'
        ]),
        language: 'c'
)

czmq_dep = dependency('libczmq')
zmq_dep = dependency('libzmq')
json_dep = dependency('json-c')
mnl_dep = dependency('libmnl')
libedit_dep = dependency('libedit')
vrfmanager_dep = dependency('libvrfmanager-vyatta')
systemd_dep = dependency('libsystemd')
proto_c_dep = dependency('libprotobuf-c')
proto_cxx_dep = dependency('protobuf')
jemalloc_dep = dependency('jemalloc', required : get_option('use_jemalloc'))

cc = meson.get_compiler('c')
b64_dep = cc.find_library('b64', required: true)
ini_dep = cc.find_library('inih', required: true)

subdir('protobuf')
subdir('lib')
subdir('daemon')
subdir('client')
subdir('snmp')
subdir('test/example')
subdir('test/module')
