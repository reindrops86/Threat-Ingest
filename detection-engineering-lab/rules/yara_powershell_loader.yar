rule Suspicious_PowerShell_Loader
{
    meta:
        description = "Detects suspicious PowerShell loader patterns"
        author = "security-lab"
        date = "2026-08-22"
    strings:
        $s1 = "FromBase64String" nocase
        $s2 = "IEX" nocase
        $s3 = "DownloadString" nocase
        $s4 = "powershell.exe" nocase
    condition:
        any of them
}
