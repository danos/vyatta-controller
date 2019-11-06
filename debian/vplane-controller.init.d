#! /bin/bash

### BEGIN INIT INFO
# Provides:          vplane-controller
# Required-Start:    $syslog $remote_fs $local_fs
# Required-Stop:     $syslog $remote_fs $local_fs
# X-Start-Before:    vyatta-router vyatta-routing
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: dataplane controller
# Description:	vplane controller system setup
### END INIT INFO
#
# Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

DESC="vPlane controller"
NAME=vplaned
PIDFILE=/var/run/vyatta/vplaned.pid
CONFILE=/etc/vyatta/controller.conf
LOGFILE=/var/log/vyatta/$NAME.log

source /etc/default/vyatta

: "${vyatta_prefix:=/opt/vyatta}"
: "${vyatta_sbindir:=${vyatta_prefix}/sbin}"
[[ $PATH == *${vyatta_sbindir}* ]] || PATH+=:${vyatta_sbindir}
export PATH
DAEMON=${vyatta_sbindir}/vplaned

. /lib/lsb/init-functions

[ -d /var/run/vyatta ] || mkdir -p /var/run/vyatta

case "$1" in
    start)
	if [ ! -r $CONFILE ]; then
	    echo "Missing $CONFILE"
	    exit 0
	fi

	log_action_begin_msg "Starting $DESC"

	/lib/vplane/hwbinding /config/config.boot
	start-stop-daemon --start --quiet --pidfile $PIDFILE \
	    --exec "$DAEMON" -- "$DEBUG" --daemon -p $PIDFILE -u vplaned -g adm \
	    -l $LOGFILE
	log_action_end_msg $?
	;;

    stop)

	log_action_begin_msg "Stopping $DESC"
	start-stop-daemon --stop --quiet --retry=TERM/5/KILL/5 \
			  --pidfile=$PIDFILE \
			  --oknodo --exec "$DAEMON"
	rm -f $PIDFILE
	log_action_end_msg $?
	;;

    status)
	status_of_proc -p $PIDFILE "$DAEMON" "$DESC"
	;;

    reload)
	log_action_begin_msg "Reloading $DESC config"
	start-stop-daemon --stop --signal HUP --quiet --pidfile=$PIDFILE \
		--exec "$DAEMON"
	log_action_end_msg $?
	;;

    force-reload|restart)
	$0 stop && $0 start
	;;

    *)	log_failure_msg "action unknown: $1" ;
	false ;;
esac
exit $?
