#!/usr/bin/env python3
import pathlib
import sys


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: inject_susfs_selinux_compat.py SUSFS_C COMPAT_C")

    target = pathlib.Path(sys.argv[1])
    fragment_path = pathlib.Path(sys.argv[2])
    text = target.read_text(encoding="utf-8")
    fragment = fragment_path.read_text(encoding="utf-8")

    include = "#include <linux/hash.h>"
    if include not in text:
        anchor = "#include <linux/security.h>"
        if anchor not in text:
            raise SystemExit("missing SUSFS include anchor")
        text = text.replace(anchor, anchor + "\n" + include, 1)

    marker = "/* Compatibility hooks required by SukiSU's SELinux policy editor. */"
    if marker not in text:
        anchor = "/* sus_path */"
        if anchor not in text:
            raise SystemExit("missing SUSFS insertion anchor")
        text = text.replace(anchor, fragment.rstrip() + "\n\n" + anchor, 1)

    target.write_text(text, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
