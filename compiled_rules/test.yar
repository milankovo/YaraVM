
rule dummy_cond
{
	condition:
		1 == 1
}

private rule dummy_private
{
	condition:
		1 == 0
}

rule string
{
	strings:
		$s1 = "dummy" ascii
		$s2 = "dummy" wide
	condition:
		all of them
}

rule hexstring
{
	strings:
		$h1 = { 64 75 6d 6d 79 }    // dummy
		$h2 = { 64 75 6d 6d 79 00 } // dummy
	condition:
		any of them
}

rule regex
{
	strings:
		$r1 = /d(a|b|c)um[1-9]{1,11}y/
		$r2 = /dummy/i
	condition:
		all of them and
		not hexstring or
		string
}
