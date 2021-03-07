# Introduction

`generate_ord_rename_idc.py` is a Python script that will parse a DEF file for
the mangled export names and ordinals to generate a IDC file
(annotate_ords.idc) to rename those ordinals to the mangled names (IDA Pro will automatically demangle those names by default)

The example used is MFC42.DEF from
https://github.com/ginistein/avdbg/blob/master/Other/exeToc/release/DEF/MFC42.DEF.
