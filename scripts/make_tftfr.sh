#!/bin/bash

if [ "$#" -lt 3 ]; then
	echo "Usage: bash make_tftfr.sh outfile infile1 infile2 ..."
	echo "Example: bash make_tftfr.sh tftfr.bin tftf.bin vm1.bin vm2.bin ..."
	exit 1
fi

OUTFILE="$1"
shift

if [ ! -f "$1" ]; then
	echo "$1 not found"
	exit 1
fi

cp "$1" "$OUTFILE"
shift

while [ "$#" -ge 1 ] ; do
	SIZE=$(stat -c%s "$OUTFILE")
	SIZE=$(expr \( $SIZE - 1 \) / 4096 \* 4096 + 4096)
	truncate -s $SIZE "$OUTFILE"
	cat "$1" >> "$OUTFILE"
	shift
done
