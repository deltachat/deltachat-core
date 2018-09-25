from __future__ import print_function
import sys
import re

def read_event_defines(f):
    rex = re.compile(r'#define\s+(?:DC_EVENT_|DC_STATE_|DC_CONTACT_ID_|DC_GCL|DC_CHAT)\S+\s+([x\d]+).*')
    return filter(rex.match, f)


if __name__ == "__main__":
    with open("deltachat.h") as f:
        event_defines = read_event_defines(f)

    lines = []
    with open("dc_constants.c", "w") as cfile:
        for x in event_defines:
            parts = x.strip().split()
            _, name, int = parts[:3]
            print("const int i_{}={};".format(name, int), file=cfile)
            lines.append("extern const int i_{};".format(name))

    extra_lines = "\n".join(lines)

    with open("deltachat.h") as f:
        content = f.read()

    if content.endswith(extra_lines):
        print ("no changes")
    else:
        i = content.find("// generated constants")
        with open("deltachat.h", "w") as f:
            f.write(content[:i])
            f.write("// generated constants (defined in dc_constants.c)\n")
            f.write(extra_lines)
        print ("wrote new deltachat.h")



