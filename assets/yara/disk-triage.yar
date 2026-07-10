/*
 * VERDICT bundled disk triage rules — evidence-agnostic generic signatures.
 * Not a full YARA-Forge pack. Operators should set FIND_EVIL_DISK_YARA_RULES
 * to a curated ruleset for production. These close the "no default rules"
 * gap so yara_scan runs when the env override is unset.
 */
rule Verdict_Generic_MZ_HighEntropy_Stub
{
    meta:
        description = "PE MZ header in a non-standard path heuristic stub"
        author = "VERDICT"
        severity = "low"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0 and filesize < 20MB
}

rule Verdict_Generic_Powershell_Encoded
{
    meta:
        description = "Common encoded PowerShell invocation pattern"
        author = "VERDICT"
        severity = "medium"
    strings:
        $a = "powershell" nocase
        $b = "-enc" nocase
        $c = "-EncodedCommand" nocase
        $d = "FromBase64String" nocase
    condition:
        $a and ($b or $c or $d)
}

rule Verdict_Generic_Mimikatz_Strings
{
    meta:
        description = "Common Mimikatz-related strings (lead only)"
        author = "VERDICT"
        severity = "high"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "mimikatz" nocase
        $s3 = "gentilkiwi" nocase
    condition:
        any of them
}
