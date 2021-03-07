import csv
import os
import sys

def ida_start(f):
    f.write("#include <idc.idc>\n\n")
    f.write("static main() {\n")

def ida_end(f):
    f.write("}\n")

def ida_rename(f, old_name, new_name):
    f.write("\trename_name(\"" + old_name + ",\"" + new_name + "\");\n")

def generate_idc(dll_name, in_file, out_file):
    with open(out_file, "w") as fo:
        # write prologue
        ida_start(fo)

        exports_start = False
        with open(in_file, "r", newline="") as in_def:
            reader = csv.reader(in_def, delimiter=" ")
            for row in reader:
                # Skip empty rows
                if len(row) == 0:
                    continue

                first_token = row[0]
                # Skip comments
                if first_token == ";":
                    continue
                # If LIBRARY statement is found, we use that for dll_name
                elif first_token == "LIBRARY":
                    dll_name = row[1]
                    print("INFO: Found LIBRARY statement, using " + dll_name + " as DLL name")
                    continue
                elif first_token == "EXPORTS":
                    exports_start = True
                    print("INFO: Found EXPORTS statement, start processing export names")
                    continue

                if exports_start and len(row) == 5:
                    ordinal = row[3]
                    new_name = row[1]

                    old_name = dll_name + "_" + ordinal
                    ida_rename(fo, old_name, new_name)

        # write epilogue
        ida_end(fo)
    print("INFO: Generation done")

def main():
    argv_len = len(sys.argv)
    if argv_len < 2:
        print("Generates IDC to rename ordinal imports to their managed names.")
        print("Usage: generate_ord_rename_idc.py INPUT_DEF OUTPUT_IDC")
        print("- INPUT_DEF is the .DEF file containing the oridinal to mangled export name mapping.")
        print("- OUTPUT_IDC is optional filename of output IDC. Defaults to annotate_ords.idc.")
        exit()

    in_def = sys.argv[1]

    if not os.path.isfile(in_def):
        print("Specified CSV does not exist.")
        exit()

    # Assume the filename is the DLL name until we parse a LIBRARY directive in
    # the DEF file
    dll_name = in_def.upper().rstrip(".DEF")
    print("INFO: DLL name assumed to be " + dll_name + " based on " + in_def + "'s filename")

    out_idc = "annotate_ords.idc"
    if argv_len >=3 and len(sys.argv[2]) != 0:
        out_idc = sys.argv[2]

    generate_idc(dll_name, in_def, out_idc)

if __name__ == '__main__':
    main()

