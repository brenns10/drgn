#!/usr/bin/env python
# Copyright (c) 2024 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

"""GDB wrapper and pstack implementation for stack-only cores."""

import argparse
import os
import subprocess
import sys
import tempfile
from struct import Struct
from typing import BinaryIO, NamedTuple, List, Tuple, TypeVar, Type, Optional


T = TypeVar("T")


def read_struct(cls: Type[T], f: BinaryIO) -> T:
    return cls(*cls.struct.unpack(f.read(cls.struct.size)))


class Ehdr(NamedTuple):
    e_ident: bytes
    e_type: int
    e_machine: int
    e_version: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int

    struct = Struct("=16sHHIQQQIHHHHHH")


class Phdr(NamedTuple):
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int

    struct = Struct("=IIQQQQQQ")


class Shdr(NamedTuple):
    sh_name: int
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int

    struct = Struct("=IIQQQQIIQQ")


class Nhdr(NamedTuple):
    n_namesz: int
    n_descsz: int
    n_type: int

    struct = Struct("=III")


class MappedFiles(NamedTuple):
    count: int
    page_size: int

    struct = Struct("=QQ")


class FileEntry(NamedTuple):
    start: int
    end: int
    file_offset: int

    struct = Struct("=QQQ")


PT_NOTE = 4
NT_FILE = 0x46494C45
SHN_UNDEF = 0
SHN_LORESERVE = 0xff00


def pad4(i: int) -> int:
    if i & 3:
        return i + (4 - (i & 3))
    else:
        return i


def read_nulstr(f: BinaryIO, offset: Optional[int] = None) -> bytes:
    if offset is not None:
        f.seek(offset)
    buf = bytearray()
    while True:
        b = f.read(1)
        if ord(b) == 0:
            return bytes(buf)
        else:
            buf.extend(b)


def get_mapped_files(core_file: str) -> List[Tuple[str, int]]:
    with open(core_file, 'rb') as file:
        ehdr = read_struct(Ehdr, file)

        for i in range(ehdr.e_phnum):
            file.seek(ehdr.e_phoff + i * ehdr.e_phentsize)
            phdr = read_struct(Phdr, file)
            if phdr.p_type == PT_NOTE:
                break
        else:
            sys.exit("error: no PT_NOTE section")

        offset = phdr.p_offset
        end_segment = phdr.p_offset + phdr.p_filesz
        while offset < end_segment:
            file.seek(offset)
            nhdr = read_struct(Nhdr, file)
            offset += Nhdr.struct.size + pad4(nhdr.n_namesz) + pad4(nhdr.n_descsz)
            if nhdr.n_namesz > 0:
                name = file.read(nhdr.n_namesz - 1)
            else:
                name = b""
            file.read(1)
            if nhdr.n_namesz & 3:
                file.read(4 - (nhdr.n_namesz & 3))
            if nhdr.n_type == NT_FILE and name == b"CORE":
                break
        else:
            sys.exit("error: no NT_FILE note")

        files = read_struct(MappedFiles, file)
        entries = []
        for i in range(files.count):
            entries.append(read_struct(FileEntry, file))
        names = []
        for i in range(files.count):
            names.append(read_nulstr(file))
        ret = []
        for i in range(files.count):
            if entries[i].file_offset == 0:
                ret.append((names[i].decode("utf-8"), entries[i].start))
        return ret


def get_text_start(name: str) -> Optional[int]:
    with open(name, 'rb') as file:
        ehdr = read_struct(Ehdr, file)
        if ehdr.e_ident[:4] != b"\x7FELF":
            return None
        sections = []
        for i in range(ehdr.e_shnum):
            file.seek(ehdr.e_shoff + i * ehdr.e_shentsize)
            sections.append(read_struct(Shdr, file))

        if ehdr.e_shstrndx >= SHN_LORESERVE:
            ehdr.e_shstrndx = sections[0].sh_link
        str_offset = sections[ehdr.e_shstrndx].sh_offset
        for sec in sections:
            name = read_nulstr(file, str_offset + sec.sh_name)
            if name == b".text":
                return sec.sh_addr


def main() -> None:
    parser = argparse.ArgumentParser(
        description="outputs stack traces from minimal core dumps"
    )
    parser.add_argument(
        "core",
        help="core dump file created by drgn's gcore.py",
    )
    parser.add_argument(
        "--gdb",
        action="store_true",
        help="just run GDB rather than outputting stack traces",
    )
    args = parser.parse_args()
    gdb_args = [
        "gdb",
        "-core",
        sys.argv[1],
    ]
    if not args.gdb:
        gdb_args.extend(["-nx", "-quiet", "-batch"])

    symbol_file = None
    init_lines = [
        "set confirm off",  # need to avoid confirmation on add-symbol-file
        "set pagination no",  # avoid pagination even in gdb mode
    ]
    if not args.gdb:
        init_lines.extend([
            "set width 0",
            "set height 0",
        ])
    for name, load in get_mapped_files(args.core):
        # Filter out non-files and files which are too small to have ELF
        # headers.
        if not os.path.isfile(name):
            continue
        st = os.stat(name)
        if st.st_size < Ehdr.struct.size:
            continue
        text_start = get_text_start(name)
        if text_start is None:
            # not an ELF file
            continue
        # TODO: we assume the first file is the executable. This may not be
        # always true.
        if symbol_file is None:
            symbol_file = name
        else:
            text_map_addr = load + text_start
            init_lines.append(f"add-symbol-file {name} 0x{text_map_addr:x}")

    if not symbol_file:
        sys.exit("could not identify main program")

    gdb_args.append(symbol_file)
    if args.gdb:
        init_lines.extend([
            "set confirm on",
            "set pagination on",
        ])
    else:
        init_lines.append("thread apply all bt")

    with tempfile.NamedTemporaryFile("wt") as f:
        f.write("\n".join(init_lines))
        f.flush()
        gdb_args += ["-x", f.name]
        if args.gdb:
            print(gdb_args)
            print("\n".join(init_lines))
            subprocess.run(gdb_args)
        else:
            proc = subprocess.Popen(
                gdb_args, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE
            )
            for line in proc.stdout:
                if line.startswith(b"Thread") or line.startswith(b"#"):
                    print(line.decode(), end='')
            proc.wait()


if __name__ == '__main__':
    main()
