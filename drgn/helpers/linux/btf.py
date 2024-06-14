# Copyright (c) 2026 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
BTF
---

This module contains Python helpers to simplify loading BTF debuginfo and
associated kallsyms symbol info.
"""
import re
from typing import Callable, Optional

from drgn import FindObjectFlags, Object, Program
from drgn.helpers.linux.kallsyms import load_module_kallsyms, load_vmlinux_kallsyms

__all__ = ("build_c_declaration_object_finder", "load_btf")


def build_c_declaration_object_finder(
    prog: Program, decls: str
) -> Callable[[Program, str, FindObjectFlags, Optional[str]], Optional[Object]]:
    """
    Create an object finder from C variable declarations

    For all released Linux kernel versions, in-kernel BTF does not contain a
    mapping of variable names to their types or addresses. To make up for this,
    objects whose types are known ahead of time can be created via their
    kallsyms symbol entry. This function creates an object finder using that
    strategy. All that is necessary is to provide a set of C-style declarations,
    such as::

        struct list_head modules, btf_modules;

    The declarations may contain only variable declarations. Fun ction
    declarations, as well as type declarations, are not allowed. C style line
    comments and blank lines are permitted, though multi-line comments are not.

    The returned object finder can be registered with
    :meth:`Program.register_object_finder` and used to access the declared
    variables.

    :param decls: a string containing C-style variable declarations
    :returns: a corresponding object finder
    """
    name_to_type = {}

    single_decl = "\\*?\\s*[a-zA-Z_]\\w*(?:\\s*\\[\\d*\\])*\\s*"
    declarator_list = re.compile(
        "(?:" + single_decl + ",\\s*)*" + single_decl + ";\\s*$"
    )
    for decl in decls.strip().split("\n"):
        comment_start = decl.find("//")
        if comment_start >= 0:
            decl = decl[:comment_start]
        decl = decl.strip()
        if not decl:
            continue
        m = declarator_list.search(decl)
        if not m:
            raise ValueError("Invalid declaration: {}".format(decl))
        type_string = decl[: -len(m.group(0))]
        for name in m.group(0).rstrip(";").split(","):
            this_type = type_string
            name = name.strip()
            if name.startswith("*"):
                this_type += " *"
                name = name[1:].lstrip()
            start_bracket = name.find("[")
            if start_bracket > 0:
                this_type += " " + name[start_bracket:]
                name = name[:start_bracket]
            name_to_type[name.strip()] = this_type

    def ofind(
        prog: Program, name: str, flags: FindObjectFlags, filename: Optional[str]
    ) -> Optional[Object]:
        if flags & FindObjectFlags.VARIABLE and name in name_to_type:
            return Object(prog, name_to_type[name], address=prog.symbol(name).address)
        return None

    return ofind


def load_btf(prog: Program, declarations: Optional[str] = None) -> None:
    """
    Use BPF Type Format (BTF) data for debugging.

    This searches the current directory and well-known paths for the
    "vmlinux.ctfa" file associated with this kernel version. If found, we load
    the BTF info, and by default, we also load the built-in kallsyms for our
    symbol table.

    :param prog: Program for debugging
    :param declarations: C-style declarations to create a supplemental object
      finder. If not provided, a minimal set of declarations will be provided in
      order to allow drgn to load module BTF. See
      :func:`build_c_declaration_object_finder`
    """
    finder = load_vmlinux_kallsyms(prog)
    prog.register_symbol_finder("vmlinux_kallsyms", finder, enable_index=0)
    kernel = prog.main_module("kernel", create=True)
    kernel.address_range = (
        prog.symbol("_stext").address,
        prog.symbol("_end").address,
    )
    kernel.load_btf()
    if not declarations:
        declarations = "struct list_head modules, btf_modules, slab_caches;"
    ofind = build_c_declaration_object_finder(prog, declarations)
    prog.register_object_finder("btf_manual_globals", ofind, enable_index=1)
    for module, created in prog.loaded_modules():
        if created:
            module.load_btf()
    module_finder = load_module_kallsyms(prog)
    prog.register_symbol_finder("module_kallsyms", module_finder, enable_index=1)
