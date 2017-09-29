#!/bin/sh

Module() {
	echo "package.preload['$1'] = (function (...)"
	cat "$2";
	echo 'end);'
}

# Guard against being loaded without FFI support or the C modlue
echo 'if pcall(require,"ffi") then'
Module "lunbound" "util.lunbound.lua"
echo 'elseif not pcall(require,"util.lunbound") then return end'

Module "net.adns" "net.unbound.lua"
Module "util.dns" "util.dns.lua"
Module "net.dns" "fakedns.lua"
