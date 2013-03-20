
Module() {
	echo "package.preload['$1'] = (function (...)"
	cat "$2";
	echo 'end);'
}

echo 'if not pcall(require,"ffi") then return end'
Module "net.adns" "net.unbound.lua"
Module "util.dns" "util.dns.lua"
Module "lib.unbound" "lib.unbound.lua"
Module "net.dns" "fakedns.lua"
