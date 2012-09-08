
Module() {
	echo "package.preload['$1'] = (function (...)"
	cat "$2";
	echo 'end);'
}

echo 'if not pcall(require,"ffi") then return end'
Module "net.adns" "net.ldns.lua"
echo 'if pcall(require, "struct") then'
Module "util.dns" "util.dns+struct.lua"
echo 'else'
Module "util.dns" "util.dns.lua"
echo 'end'
Module "lib.unbound" "lib.unbound.lua"
Module "net.dns" "fakedns.lua"
