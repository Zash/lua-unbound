<?xml version="1.0"?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:a="http://www.iana.org/assignments" version="1.0">
<output method="text"/>
<template match="/TrustAnchor">
	<text>#define IANA_ROOT_TA &quot;</text>
	<value-of select="./Zone"/>
	<text> IN DS </text>
	<value-of select="./KeyDigest/KeyTag"/>
	<text> </text>
	<value-of select="./KeyDigest/Algorithm"/>
	<text> </text>
	<value-of select="./KeyDigest/DigestType"/>
	<text> </text>
	<value-of select="./KeyDigest/Digest"/>
	<text>&quot;&#10;</text>
</template>
</stylesheet>
