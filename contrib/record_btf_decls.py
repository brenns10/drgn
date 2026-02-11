# Copyright (c) 2026 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
import argparse
import os
import pkgutil
import runpy
import sys
from typing import Optional

from drgn import FindObjectFlags, Program, Type, TypeKind
from drgn.cli import run_interactive


def record_object_lookups(prog: Program) -> None:
    if "record_object_lookups" in prog.registered_object_finders():
        return

    lookups = set()

    def ofind(prog, name, flags, filename) -> None:
        if flags & FindObjectFlags.VARIABLE:
            lookups.add((name, filename))
        return None

    # Register at index 1 so that we don't observe the "linux_kernel" object
    # finder lookups, but we see everything else.
    prog.register_object_finder("record_object_lookups", ofind, enable_index=1)
    prog.cache["record_object_lookups"] = lookups


def _format_type(tp: Type, name: Optional[str]) -> str:
    if tp.kind in (TypeKind.STRUCT, TypeKind.UNION, TypeKind.ENUM, TypeKind.CLASS):
        if not tp.tag:
            raise ValueError(f"cannot reference anonymous {tp.kind.name.lower()}")
        if name:
            return f"{tp.kind.name.lower()} {tp.tag} {name}"
        else:
            return f"{tp.kind.name.lower()} {tp.tag}"
    elif tp.kind == TypeKind.POINTER:
        if name:
            return _format_type(tp.type, f"*{name}")
        else:
            return _format_type(tp.type, name) + "*"
    elif tp.kind == TypeKind.ARRAY:
        length = "" if tp.length is None else str(tp.length)
        return f"{_format_type(tp.type, name)}[{length}]"
    elif tp.kind == TypeKind.VOID:
        # while void variables cannot be declared, void pointers can, they will
        # have non-None name
        if name:
            return f"void {name}"
        else:
            return "void"
    elif tp.kind == TypeKind.FUNCTION:
        raise NotImplementedError("function declarations are not implemented")
    elif name:
        return f"{tp.name} {name}"
    else:
        return tp.name


def get_object_declarations(prog: Program) -> str:
    # Include the minimum modules + btf_modules for any generated result
    decls = [
        "struct list_head modules, btf_modules;"
    ]
    for name, filename in prog.cache["record_object_lookups"]:
        try:
            result = prog.variable(name, filename)
        except LookupError:
            continue
        try:
            decls.append(_format_type(result.type_,name) + ";")
        except ValueError as e:
            decls.append(f"// {name}: {e}")
    return "\n".join(decls)


def main(prog: Program):
    parser = argparse.ArgumentParser(
        description="run script or interactive, recording variables used"
    )
    parser.add_argument("-o", "--output", type=str, help="file to store declarations")
    args, remainder = parser.parse_known_args()
    record_object_lookups(prog)
    try:
        if remainder:
            sys.argv = remainder
            script_path = sys.argv[0]
            if pkgutil.get_importer(script_path) is None:
                sys.path.insert(0, os.path.dirname(os.path.abspath(script_path)))
            runpy.run_path(
                script_path, init_globals={"prog": prog}, run_name="__main__"
            )
        else:
            run_interactive(prog)
    finally:
        decls = get_object_declarations(prog)
        if args.output:
            with open(args.output, "w") as f:
                f.write(decls)
        else:
            print("==== DECLARATIONS ====")
            print(decls)


if __name__ == "__main__":
    main(prog)  # noqa
