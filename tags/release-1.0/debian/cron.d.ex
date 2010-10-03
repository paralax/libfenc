#
# Regular cron jobs for the libfenc package
#
0 4	* * *	root	[ -x /usr/bin/libfenc_maintenance ] && /usr/bin/libfenc_maintenance
