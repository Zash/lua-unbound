
Module() {
	echo "package.preload['$1'] = (function (...)"
	cat "$2";
	echo 'end);'
}

# Guard against being loaded without FFI support
echo 'if not pcall(require,"ffi") then return end'

# Then insert modules into package.preload
Module "net.adns" "net.unbound.lua"
Module "util.dns" "util.dns.lua"
Module "util.lunbound" "util.lunbound.lua"
Module "net.dns" "fakedns.lua"
