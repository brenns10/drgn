#!/usr/bin/env python3

import subprocess
import sys

from vmtest.resolver import KernelResolver

if __name__ == "__main__":
    with KernelResolver(["5.8.0-rc7-vmtest1"], "build/vmtest") as resolver:
        kernel = next(iter(resolver))
        i = 1
        log = bytearray()
        while True:
            print("Run", i)
            i += 1
            with subprocess.Popen(
                [
                    # fmt: off
                    "qemu-system-x86_64", "-cpu", "host", "-enable-kvm",

                    "-smp", "2", "-m", "2G",

                    "-nodefaults", "-display", "none", "-serial", "mon:stdio",

                    # This along with -append panic=-1 ensures that we exit on a
                    # panic instead of hanging.
                    "-no-reboot",

                    "-kernel", kernel.vmlinuz,
                    "-append", f"console=0,115200 panic=-1",
                    # fmt: on
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
            ) as qemu:
                for line in qemu.stdout:
                    log.extend(line)
                    if b"smp: Brought up" in line:
                        qemu.kill()
                        break
                else:
                    print("QEMU returned", qemu.wait())
                    sys.stdout.buffer.write(log)
                    sys.exit(1)
            log.clear()
