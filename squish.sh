#!/bin/sh

Module() {
	echo "package.preload['$1'] = (function (...)"
	cat "$2";
	echo 'end);'
}

if [ "$1" = "ffi" ]; then
	Module "lunbound" "util.lunbound.lua"
fi

Module "net.adns" "net.unbound.lua"
Module "util.dns" "util.dns.lua"
Module "net.dns" "fakedns.lua"
