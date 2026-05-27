#!/usr/bin/env python3

import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from typing import Iterator
from typing import Self

from drgn import Program
from drgn.helpers.linux import compound_head
from drgn.helpers.linux import pfn_to_page
from drgn.helpers.linux import pfn_to_virt
from drgn.helpers.linux import PageSlab
from zstandard import train_dictionary
from zstandard import ZstdCompressor


KDUMP_SIGNATURE = b"KDUMP   "
DISKDUMP_HEADER_BLOCKS = 1

DUMP_DH_COMPRESSED_ZLIB = 0x1
DUMP_DH_COMPRESSED_LZO = 0x2
DUMP_DH_COMPRESSED_SNAPPY = 0x4
DUMP_DH_COMPRESSED_INCOMPLETE = 0x8
DUMP_DH_EXCLUDED_VMEMMAP = 0x10
DUMP_DH_COMPRESSED_ZSTD = 0x20

COMPRESSION_FLAGS = (
    (DUMP_DH_COMPRESSED_ZLIB, "zlib"),
    (DUMP_DH_COMPRESSED_LZO, "lzo"),
    (DUMP_DH_COMPRESSED_SNAPPY, "snappy"),
    (DUMP_DH_COMPRESSED_ZSTD, "zstd"),
)

DUMP_LEVEL_FLAGS = (
    (0x001, "exclude-zero"),
    (0x002, "exclude-cache"),
    (0x004, "exclude-cache-private"),
    (0x008, "exclude-user-data"),
    (0x010, "exclude-free"),
)


ZSTD_THRESH = 5000


@dataclass(frozen=True)
class Layout:
    name: str
    disk_dump_header: struct.Struct
    kdump_sub_header: struct.Struct
    page_desc: struct.Struct


@dataclass(frozen=True)
class DiskDumpHeader:
    signature: bytes
    header_version: int
    status: int
    block_size: int
    sub_hdr_size: int
    bitmap_blocks: int
    max_mapnr: int
    total_ram_blocks: int
    device_blocks: int
    written_blocks: int
    current_cpu: int
    nr_cpus: int


@dataclass(frozen=True)
class KdumpSubHeader:
    phys_base: int
    dump_level: int
    split: int
    start_pfn: int
    end_pfn: int
    offset_vmcoreinfo: int
    size_vmcoreinfo: int
    offset_note: int
    size_note: int
    offset_eraseinfo: int
    size_eraseinfo: int
    start_pfn_64: int
    end_pfn_64: int
    max_mapnr_64: int


@dataclass(frozen=True)
class PageDesc:
    offset: int
    size: int
    flags: int
    page_flags: int


LAYOUTS = (
    Layout(
        "64-bit little-endian",
        struct.Struct("<8si390s6xqqIiiIIIIIIi"),
        struct.Struct("<QiiQQqQqQqQQQQ"),
        struct.Struct("<qIIQ"),
    ),
    Layout(
        "64-bit big-endian",
        struct.Struct(">8si390s6xqqIiiIIIIIIi"),
        struct.Struct(">QiiQQqQqQqQQQQ"),
        struct.Struct(">qIIQ"),
    ),
    Layout(
        "32-bit little-endian",
        struct.Struct("<8si390s2xllIiiIIIIIIi"),
        struct.Struct("<IiiIIqIqIqIQQQ"),
        struct.Struct("<qIIQ"),
    ),
    Layout(
        "32-bit big-endian",
        struct.Struct(">8si390s2xllIiiIIIIIIi"),
        struct.Struct(">IiiIIqIqIqIQQQ"),
        struct.Struct(">qIIQ"),
    ),
)


def read_at(f: BinaryIO, offset: int, size: int) -> bytes:
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise ValueError(f"short read at offset 0x{offset:x}: wanted {size}, got {len(data)}")
    return data


def parse_disk_dump_header(layout: Layout, data: bytes) -> DiskDumpHeader:
    fields = layout.disk_dump_header.unpack(data)
    (
        signature,
        header_version,
        _utsname,
        _tv_sec,
        _tv_usec,
        status,
        block_size,
        sub_hdr_size,
        bitmap_blocks,
        max_mapnr,
        total_ram_blocks,
        device_blocks,
        written_blocks,
        current_cpu,
        nr_cpus,
    ) = fields
    return DiskDumpHeader(
        signature=signature,
        header_version=header_version,
        status=status,
        block_size=block_size,
        sub_hdr_size=sub_hdr_size,
        bitmap_blocks=bitmap_blocks,
        max_mapnr=max_mapnr,
        total_ram_blocks=total_ram_blocks,
        device_blocks=device_blocks,
        written_blocks=written_blocks,
        current_cpu=current_cpu,
        nr_cpus=nr_cpus,
    )


def parse_kdump_sub_header(layout: Layout, data: bytes) -> KdumpSubHeader:
    return KdumpSubHeader(*layout.kdump_sub_header.unpack(data))


def parse_page_desc(layout: Layout, data: bytes) -> PageDesc:
    return PageDesc(*layout.page_desc.unpack(data))


def is_power_of_two(value: int) -> bool:
    return value > 0 and (value & (value - 1)) == 0


def is_plausible_header(header: DiskDumpHeader, file_size: int, sub_header_size: int) -> bool:
    if header.signature != KDUMP_SIGNATURE:
        return False
    if not (1 <= header.header_version <= 64):
        return False
    if not (512 <= header.block_size <= 1024 * 1024 * 1024):
        return False
    if not is_power_of_two(header.block_size):
        return False
    if header.block_size > file_size:
        return False
    if not (1 <= header.sub_hdr_size <= 1024 * 1024):
        return False
    if header.sub_hdr_size * header.block_size < sub_header_size:
        return False
    if header.bitmap_blocks < 0:
        return False
    page_desc_offset = (
        DISKDUMP_HEADER_BLOCKS + header.sub_hdr_size + header.bitmap_blocks
    ) * header.block_size
    return page_desc_offset <= file_size


def detect_layout(f: BinaryIO, file_size: int) -> tuple[Layout, DiskDumpHeader, KdumpSubHeader]:
    first_read = max(layout.disk_dump_header.size for layout in LAYOUTS)
    data = read_at(f, 0, first_read)

    for layout in LAYOUTS:
        header = parse_disk_dump_header(layout, data[: layout.disk_dump_header.size])
        if is_plausible_header(header, file_size, layout.kdump_sub_header.size):
            sub_data = read_at(f, header.block_size, layout.kdump_sub_header.size)
            sub_header = parse_kdump_sub_header(layout, sub_data)
            return layout, header, sub_header

    signature = data[: len(KDUMP_SIGNATURE)]
    if signature != KDUMP_SIGNATURE:
        raise ValueError(f"not a kdump-compressed dump: signature is {signature!r}")
    raise ValueError("KDUMP signature found, but no supported header layout matched")


@dataclass(frozen=True)
class Dump:
    file: BinaryIO
    path: Path
    layout: Layout
    header: DiskDumpHeader
    subheader: KdumpSubHeader

    @classmethod
    def open(cls, path: str | Path) -> Self:
        path = Path(path)
        stat = path.stat()
        filp = path.open("rb")
        layout, header, subheader = detect_layout(filp, stat.st_size)
        return Dump(filp, path, layout, header, subheader)

    def iter_pages(self) -> Iterator[tuple[int, PageDesc]]:
        #print(f"{self.subheader.start_pfn=}, {self.subheader.start_pfn_64=}")

        # For iterating over bitmap2:
        max_mapnr = self.subheader.max_mapnr_64 or self.header.max_mapnr
        size = (self.header.bitmap_blocks * self.header.block_size) // 2
        offset = size + (DISKDUMP_HEADER_BLOCKS + self.header.sub_hdr_size) * self.header.block_size
        index = 0

        # For caching page_desc structures:
        pd_index = 0
        pd_start = 0
        pd_cache = 4096
        pd_chunk = None
        pd_offset = (
            DISKDUMP_HEADER_BLOCKS + self.header.sub_hdr_size + self.header.bitmap_blocks
        ) * self.header.block_size
        def read_page_desc(index: int) -> PageDesc:
            nonlocal pd_chunk
            nonlocal pd_start
            if not (pd_start <= index < pd_start + pd_cache) or not pd_chunk:
                pd_start = (index // pd_cache) * pd_cache
                pd_chunk = read_at(self.file, pd_offset + pd_start * self.layout.page_desc.size, pd_cache * self.layout.page_desc.size)
            return parse_page_desc(self.layout, pd_chunk[(index - pd_start) * self.layout.page_desc.size:(1 + index - pd_start) * self.layout.page_desc.size])

        while index < size:
            chunk = read_at(self.file, offset + index, min(65536, size - index))
            for i, value in enumerate(chunk):
                if value:
                    for bit in range(8):
                        if value & (1 << bit):
                            pfn = (index + i) * 8 + bit
                            yield pfn, read_page_desc(pd_index)
                            pd_index += 1
                            if max_mapnr and pfn >= max_mapnr:
                                return
            index += len(chunk)


@dataclass(slots=True)
class PageData:
    count_zeros: int
    count_nonzero: int
    size_nonzero: int
    size_trained: int


def is_zeropage(prog: Program, pfn: int, page_desc: PageDesc, page_size: int, zero_offset: list[int]) -> bool:
    # Once we've encountered the singleton zero page offset, we can use a fast
    # path.
    if len(zero_offset) > 0:
        return page_desc.offset == zero_offset[0]

    # Prior to that, check any full-sized, uncompressed page
    if page_desc.size == page_size and page_desc.flags == 0:
        if prog.read(pfn_to_virt(pfn), page_size) == b"\x00" * page_size:
            zero_offset.append(page_desc.offset)
            return True
    return False


def names_from_flags(flags):
    names = [name for bit, name in COMPRESSION_FLAGS if flags & bit]
    return names or ["none"]


def train_zstd(prog: Program, traindat: dict[str, list[int]]) -> dict[str, ZstdCompressor]:
    target = 128 * 1024
    trained = {}
    page_size = prog["PAGE_SIZE"].value_()
    for slab_cache, pfn_list in traindat.items():
        if len(pfn_list) < ZSTD_THRESH:
            continue
        print(f"Training {slab_cache}...")
        examples = [prog.read(pfn_to_virt(prog, pfn), page_size) for pfn in pfn_list]
        zstd_dict = train_dictionary(target, examples, level=1)
        compressor = ZstdCompressor(
            level=1, dict_data=zstd_dict, write_dict_id=False,
        )
        trained[slab_cache] = compressor
        print(f"Done training {slab_cache} (size: {len(zstd_dict)})")
    return trained


def main(prog: Program, argv: list[str] | None = None) -> int:
    dump = Dump.open(prog.core_dump_path)
    page_size = prog["PAGE_SIZE"].value_()
    totals: dict[str, PageData] = {}
    zeropage = []
    training = {}
    print("initial read...")
    for pfn, desc in dump.iter_pages():
        pg = pfn_to_page(prog, pfn).read_()
        head = compound_head(pg)
        if PageSlab(head):
            slab = head.slab_cache.name.string_().decode()
            traindat = training.setdefault(slab, [])
            if len(traindat) < ZSTD_THRESH:
                traindat.append(pfn)
        else:
            slab = "NOT SLAB"
        data = totals.setdefault(slab, PageData(0, 0, 0, 0))
        if is_zeropage(prog, pfn, desc, page_size, zeropage):
            data.count_zeros += 1
        else:
            data.count_nonzero += 1
            data.size_nonzero += desc.size

    trained = train_zstd(prog, training)
    print("redoing compression...")
    for pfn, desc in dump.iter_pages():
        pg = pfn_to_page(prog, pfn).read_()
        head = compound_head(pg)
        if not PageSlab(head):
            continue
        slab = head.slab_cache.name.string_().decode()
        if slab in trained and not is_zeropage(prog, pfn, desc, page_size, zeropage):
            orig = prog.read(pfn_to_virt(prog, pfn), page_size)
            compressed = trained[slab].compress(orig)
            totals[slab].size_trained += len(compressed)

    # For slabs we didn't train, copy the sizes so we can easily compare
    for data in totals.values():
        if data.size_trained == 0:
            data.size_trained = data.size_nonzero

    print(f"{'SLAB':<25}  {'ZEROS':>8s}  {'COUNT':>8s}  {'ORIGSZ':>12s}  {'SZ':>12s}  {'PCT':>5s}  {'TRAINSZ':>12s}  {'TPCT':>5s}")
    nonslab = totals.pop("NOT SLAB", PageData(0, 0, 0, 0))
    total_slab = PageData(0, 0, 0, 0)
    for data in totals.values():
        total_slab.count_zeros += data.count_zeros
        total_slab.count_nonzero += data.count_nonzero
        total_slab.size_nonzero += data.size_nonzero
        total_slab.size_trained += data.size_trained
    report = sorted(totals.items(), key=lambda t: t[1].size_nonzero)
    report.append(("TOTAL", total_slab))
    report.append(("NON-SLAB", nonslab))
    for slab, data in report:
        origsz = data.count_nonzero * page_size
        pct = 100 * data.size_nonzero / origsz if origsz else float("inf")
        tpct = 100 * data.size_trained / origsz if origsz else float("inf")
        print(f"{slab:<25s}  {data.count_zeros: 8d}  {data.count_nonzero: 8d}  {origsz: 12d}  {data.size_nonzero: 12d}  {pct:5.1f}  {data.size_trained: 12d}  {tpct:5.1f}")

    return 0


if __name__ == "__main__":
    sys.exit(main(globals()["prog"]))
