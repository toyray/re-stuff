from malduck import rc4
import shutil

def patch_file(filename):
    ps = [
            {"o":0xBC4, "l":0x1B, "k":b"\x50\xB0\x0B\xE2\xFB\x57\xCF\x1A"},
            {"o":0xB51, "l":0x4E, "k":b"\x17\x80\x3B\x9B\xBA\x09\x94\x89" },
            {"o":0x92A, "l":0x125, "k":b"\x57\x45\xC3\xD4\xF7\x1A\xAE\x81" },
            {"o":0x853, "l":0x2D, "k":b"\x73\xEA\x87\x80\xAA\xEF\x29\x53" },
            {"o":0xA74, "l":0xB8, "k":b"\x39\x3F\xE6\x71\x87\xAD\xD8\xE7" },
            {"o":0x5F3, "l":0x23B, "k":b"\xF3\x6D\x9F\xC7\x1B\x54\xA5\xD3" },
            {"o":0x8A5, "l":0x60, "k":b"\xF0\x28\xB6\xA6\x6C\xC9\x0C\xE4" },
            {"o":0x4c1, "l":0x10d, "k":b"\xa6\xd2\xd5\x67\x06\xe0\x5e\x39" },
            {"o":0xb9, "l":0x305, "k":b"\x34\x7f\x5c\x96\x37\xb0\xdc\x6d" },
            {"o":0x3e3, "l":0x2b, "k":b"\x82\xd6\x0f\x68\x81\x0f\x0b\xdd" },
            {"o":0x433, "l":0x69, "k":b"\x25\xa7\x14\x44\x0b\x68\xc5\xb7" },
        ]

    nops = b"\x90" * 18

    shutil.copyfile(filename, filename + ".patch")

    # Use r+ so that existing file is opened instead of being
    # truncated
    with open(filename + ".patch", "rb+") as fi:
        for p in ps:
            fi.seek(p["o"])
            data = fi.read(p["l"])
            new_data = rc4(p["k"], data)
            fi.seek(p["o"])

            written = fi.write(new_data)
            if written != p["l"]:
                print("write failed at %x", p["o"])

            # Patch the code encryption "out" instructions after the
            # decrypted code region with nops for easier emulation
            fi.write(nops)

            # Patch the code decryption "in" instructions before the
            # decrypted code region with nops for easier emulation
            fi.seek(p["o"] - 18)
            fi.write(nops)

if __name__ == "__main__":
    patch_file("ch12_code.bin")
