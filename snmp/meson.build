# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020, AT&T Intellectual Property.

executable(
        'vplane-snmp',
        sources: ['vplane-snmp.c'],
        dependencies: [
                czmq_dep,
                json_dep,
                vplaned_dep
        ],
        install: true,
        install_dir: '/opt/vyatta/sbin'
)
