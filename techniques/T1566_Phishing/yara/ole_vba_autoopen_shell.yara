// Input contract: extracted, decompressed VBA source in ASCII-compatible encoding.
// This rule does not unpack raw OLE or OOXML containers.
rule VBA_AutoExec_Shell_Heuristic
{
  meta:
    description = "Extracted VBA source: auto-execution entry point and shell invocation"
    author = "ATT&CK Top-10 project contributors"
    reference = "ATT&CK T1566"
    confidence = "medium"
    input = "Extracted/decompressed VBA source, not raw OLE/OOXML"
    limitations = "Heuristic only: legitimate automation can match and obfuscation can evade it"
  strings:
    $autoopen = /(^|\n)[ \t]*(Private[ \t]+|Public[ \t]+)?Sub[ \t]+(AutoOpen|Auto_Open|AutoExec|Document_Open|Workbook_Open)[ \t]*\(/ nocase ascii
    $shell = /\bShell[ \t]*\(/ nocase ascii
    $wscript = /CreateObject[ \t]*\([ \t]*"WScript\.Shell"[ \t]*\)/ nocase ascii
  condition:
    filesize < 1MB and $autoopen and ($shell or $wscript)
}
