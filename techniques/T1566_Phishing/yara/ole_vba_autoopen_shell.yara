rule OLE_VBA_AutoOpen_Shell_Heuristic
{
  meta:
    description = "Heuristic: OLE/VBA with AutoOpen + Shell/WScript patterns (T1566 chain)"
    author = "you"
    reference = "ATT&CK T1566"
    confidence = "medium"
  strings:
    $ole_hdr = { D0 CF 11 E0 A1 B1 1A E1 }  // OLE
    $autoopen = /Auto(Open|_Open|Exec|Close)/ nocase ascii
    $shell = "Shell(" nocase ascii
    $wscript = "WScript.Shell" nocase ascii
    $mshta = "mshta.exe" nocase ascii
  condition:
    filesize < 10MB and any of ($ole_hdr) and
    ( $autoopen and ( $shell or $wscript or $mshta ) )
}
