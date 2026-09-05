rule Credential_Access_Patterns
{
    meta:
        description = "Detects strings commonly tied to credential access workflows"
        author = "security-lab"
        date = "2026-08-22"
    strings:
        $a = "lsass" nocase
        $b = "sam" nocase
        $c = "credential" nocase
        $d = "dump" nocase
    condition:
        2 of them
}
