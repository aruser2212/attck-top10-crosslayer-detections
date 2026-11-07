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
    limitations = "Line-start calls or simple assignments only; no VBA parsing or entry-point-to-call control flow. Legitimate automation can match; inline statements and obfuscation can evade it."
  strings:
    $autoopen = /(^|\n)[ \t]*(Private[ \t]+|Public[ \t]+)?Sub[ \t]+(AutoOpen|Auto_Open|AutoExec|Document_Open|Workbook_Open)[ \t]*\(/ nocase ascii
    // Statement form has no parentheses; function/Call forms retain parentheses.
    // Anchoring to source lines keeps ordinary comments and quoted mentions out.
    $shell_statement = /(^|\n)[ \t]*Shell[ \t]+("[^"\r\n]*"|[A-Za-z][A-Za-z0-9_]*)/ nocase ascii
    $shell_parenthesized = /(^|\n)[ \t]*(Call[ \t]+|(Let[ \t]+)?[A-Za-z][A-Za-z0-9_]*[ \t]*=[ \t]*)?Shell[ \t]*\(/ nocase ascii
    $wscript = /(^|\n)[ \t]*((Set[ \t]+)?[A-Za-z][A-Za-z0-9_]*[ \t]*=[ \t]*)?CreateObject[ \t]*\([ \t]*"WScript\.Shell"[ \t]*\)/ nocase ascii
  condition:
    filesize < 1MB and $autoopen and (any of ($shell_*) or $wscript)
}
