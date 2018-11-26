#!/bin/bash

update_jsonc() {
	SRCDIR=$1
	DESTDIR="json-c"
	
	cp $SRCDIR/COPYING $DESTDIR
	cp $SRCDIR/*.c     $DESTDIR
	cp $SRCDIR/*.h     $DESTDIR

	CONFIGFILE="$DESTDIR/config.h"
	echo "// generated file"            >  $CONFIGFILE
	echo "#define STDC_HEADERS       1" >> $CONFIGFILE
	echo "#define HAVE_STDLIB_H      1" >> $CONFIGFILE
	echo "#define HAVE_STDINT_H      1" >> $CONFIGFILE
	echo "#define HAVE_INTTYPES_H    1" >> $CONFIGFILE
	echo "#define HAVE_STDARG_H      1" >> $CONFIGFILE
	echo "#define HAVE_FCNTL_H       1" >> $CONFIGFILE
	echo "#define HAVE_STRDUP        1" >> $CONFIGFILE
	echo "#define HAVE_SNPRINTF      1" >> $CONFIGFILE
	echo "#define HAVE_DECL_INFINITY 1" >> $CONFIGFILE
	echo "#define HAVE_STRNCASECMP   1" >> $CONFIGFILE
}

if [ -n "$1" ]; then 
	update_jsonc $1
else
	echo "usage: update-jsonc <source-path>"
fi
