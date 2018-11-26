#!/bin/bash

stub_header() {
	DESTDIR=$1
	HEADERNAME=$2
	HEADERFILE="$DESTDIR/$HEADERNAME"
	echo "#include \"botan_all.h\"" > $HEADERFILE
}

update_botan() {
	SRCDIR=$1
	OS=$2
	CPU=$3
	DESTDIR="botan/$OS-$CPU/botan"

	pushd .
	cd $SRCDIR
	( ./configure.py --amalgamation --single-amalgamation-file --os=$OS --cpu=$CPU --disable-neon)
	popd
	
	# copy

	rm -r $DESTDIR
	mkdir -p $DESTDIR
	cp $SRCDIR/license*             $DESTDIR/
	cp $SRCDIR/botan_all_internal.h $DESTDIR/
	cp $SRCDIR/botan_all.h          $DESTDIR/
	cp $SRCDIR/botan_all.cpp        $DESTDIR/
	cp $SRCDIR/src/lib/prov/pkcs11/pkcs11*.h $DESTDIR/

	stub_header $DESTDIR "ffi.h"
}

if [ -n "$1" ]; then 
	update_botan $1 "android" "armv7"
else
	echo "usage: update-botan <source-path>"
fi


