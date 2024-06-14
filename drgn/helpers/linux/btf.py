#!/usr/bin/env python3
# Copyright (c) 2024 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
BTF
---

This module contains Python helpers to simplify loading BTF debuginfo and
associated kallsyms symbol info.
"""
from typing import Optional, Union

from _drgn import _linux_helper_load_btf
from drgn import FindObjectFlags, Object, Program, Type
from drgn.helpers.linux.kallsyms import load_module_kallsyms, load_vmlinux_kallsyms

__all__ = ("load_btf",)


# Type definitions for some of the types which drgn internally looks up to make
# things work. This is non-exhaustive (feel free to add your own), and it could
# be inaccurate depending on kernel version. There's also no guarantee that the
# BTF actually contains a definition for the named type!
HARDCODED_TYPES = {
    "modules": "struct list_head",
    "jiffies_64": "u64",
    "init_pid_ns": "struct pid_namespace",
    "runqueues": "struct rq",
    "crashing_cpu": "int",
    "panic_cpu": "atomic_t",
    "__per_cpu_offset": "unsigned long[0]",
    "init_task": "struct task_struct",
    "pid_hash": "struct hlist_head *",
}


def var(prog: Program, name: str, type: Union[Type, str]) -> Object:
    """
    Return a variable value, given its type
    """
    return Object(prog, type, address=prog.symbol(name).address)


def btf_variable_finder(
    prog: Program,
    name: str,
    flags: FindObjectFlags,
    filename: Optional[str],
) -> Optional[Object]:
    """
    A finder which supports a few hardcoded variables
    """
    if flags & FindObjectFlags.VARIABLE and name in HARDCODED_TYPES:
        return var(prog, name, HARDCODED_TYPES[name])
    return None


def load_btf(prog: Program) -> None:
    """
    Use Compact Type Format data for debugging.

    This searches the current directory and well-known paths for the
    "vmlinux.ctfa" file associated with this kernel version. If found, we load
    the CTF info, and by default, we also load the built-in kallsyms for our
    symbol table.

    :param prog: Program for debugging
    """
    finder = load_vmlinux_kallsyms(prog)
    prog.register_symbol_finder("vmlinux_kallsyms", finder, enable_index=0)

    _linux_helper_load_btf(prog)
    list(prog.loaded_modules())
    prog.main_module().address_range = (
        prog.symbol("_stext").address,
        prog.symbol("_end").address,
    )

    # Module finder also needs "modules" var
    module_finder = load_module_kallsyms(prog)
    prog.register_symbol_finder("module_kallsyms", module_finder, enable_index=1)
