#!/bin/bash

cp_sources()
{
	SRCDIR=$1
	CDIR=$2
	mkdir -p               rnp/$CDIR/
	cp $SRCDIR/$CDIR/*.cpp rnp/$CDIR/ 2>/dev/null
	cp $SRCDIR/$CDIR/*.h   rnp/$CDIR/ 2>/dev/null
	cp $SRCDIR/$CDIR/TODO* rnp/$CDIR/ 2>/dev/null

	echo "// generated file" > rnp/$CDIR/config.h
	echo "#error" >> rnp/$CDIR/config.h
}

update_rnp() {
	SRCDIR=$1
	
	# copy misc.

	cp $SRCDIR/LICENSE rnp/

	# copy source
	
	rm -r rnp/src/*
	
	cp_sources $SRCDIR "src/lib"
	cp_sources $SRCDIR "src/lib/crypto"
	cp_sources $SRCDIR "src/librekey"
	cp_sources $SRCDIR "src/librepgp"
	cp_sources $SRCDIR "src/rnp"

	# copy header files

	rm -r rnp/include/*
	
	cp_sources $SRCDIR "include"	
	cp_sources $SRCDIR "include/rekey"	
	cp_sources $SRCDIR "include/repgp"	
	cp_sources $SRCDIR "include/rnp"	
}

if [ -n "$1" ]; then 
	update_rnp $1
else
	echo "usage: update-rnp <source-path>"
fi


