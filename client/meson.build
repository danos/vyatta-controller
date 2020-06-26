# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020, AT&T Intellectual Property.

executable(
        'vplsh',
        sources: ['vplsh.c'],
        dependencies: [
                czmq_dep,
                json_dep,
                libedit_dep,
                vplaned_dep
        ],
        install: true,
        install_dir : '/opt/vyatta/bin'
)

executable(
        'snapshot',
        sources: ['snapshot.c'],
        dependencies: [
                czmq_dep,
                json_dep,
                mnl_dep,
                vplaned_dep
        ],
        install: true,
        install_dir : '/opt/vyatta/bin'
)
