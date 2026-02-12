# QFenix

[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

An enhanced fork of [linux-msm/qdl](https://github.com/linux-msm/qdl) with improved
compatibility for Quectel firmware and maybe other Qualcomm firmware.

## Download/Install/Run

Static binaries are avalible for download under [Releases](https://github.com/iamromulan/qfenix/releases)

These are all static/standalone binaries with the exeption of the macOS binaries. The macOS ones are semi-static, 
3rd party libs are bundled but still needs dynamic system frameworks that should exist on every Mac.

## What's New in QFenix

This fork adds several features while maintaining full backwards compatibility with
the original QDL:

- **Automatic Firmware Detection** (`-F` / `--firmware-dir`) - Point to a Quectel format firmware
  directory and QFenix auto-detects the programmer, XML files, and storage type
- **DIAG to EDL Auto-Switching** - Automatically switches devices from DIAG mode to
  EDL mode (can be disabled with `--no-auto-edl`)
- **MD5 Verification** - Verifies firmware file integrity before flashing when MD5
  checksums are present in the XML (can be skipped with `--skip-md5`)
- **Improved NAND Support** - Fixes for NAND device flashing (last_sector handling)
- **Relaxed XML Parsing** - Optional attributes (label, sparse) no longer cause failures

### Quick Start with Firmware Directory

```bash
# Auto-detect everything from a firmware directory
qfenix -F /path/to/firmware/

# Dry run to see what would be flashed
qfenix --dry-run -F /path/to/firmware/

# Traditional usage still works
qfenix prog_firehose_ddr.elf rawprogram*.xml patch*.xml
```

### New Command Line Options

| Option | Description |
|--------|-------------|
| `-F, --firmware-dir=PATH` | Auto-detect and load firmware from directory |
| `-E, --no-auto-edl` | Disable automatic DIAG to EDL mode switching |
| `-M, --skip-md5` | Skip MD5 verification of firmware files |

---

## Usage

### EDL mode

The device intended for flashing must be booted into **Emergency Download (EDL)**
mode. EDL is a special boot mode available on Qualcomm-based devices that provides
low-level access for firmware flashing and recovery.

**With QFenix's auto-switching feature**, if your device is in DIAG mode, it will
automatically be switched to EDL mode. Use `--no-auto-edl` to disable this behavior.

### Flash device

Run with the `--help` option to view detailed usage information.

**Firmware directory mode (recommended for Quectel firmware):**

```bash
# Automatically detects programmer, XMLs, and storage type
qfenix -F /path/to/extracted/firmware/
```

**Traditional mode:**

```bash
qfenix prog_firehose_ddr.elf rawprogram*.xml patch*.xml
```

If you have multiple boards connected, provide the serial number:

```bash
qfenix --serial=0AA94EFD -F /path/to/firmware/
```

### Reading and writing raw binaries

In addition to flashing builds using their XML-based descriptions, QFenix supports
reading and writing binaries directly.

```bash
qfenix prog_firehose_ddr.elf [read | write] [address specifier] <binary>...
```

Multiple read and write commands can be specified at once. The ***address
specifier*** can take the forms:

- N - single number, specifies the physical partition number N to write the
  ***binary** into, starting at sector 0 (currently reading a whole physical
  partition is not supported).

- N/S - two numbers, specifies the physical partition number N, and the start
  sector S, to write the ***binary*** into (reading with an offset is not
  supported)

- N/S+L - three numbers, specified the physical partition number N, the start
  sector S and the number of sectors L, that ***binary*** should be written to,
  or which should be read into ***binary***.

- partition name - a string, will match against partition names across the GPT
  partition tables on all physical partitions.

- N/partition_name - single number, followed by string - will match against
  partition names of the GPT partition table in the specified physical
  partition N.

### Validated Image Programming (VIP)

QFenix supports **Validated Image Programming (VIP)** mode, which is activated
when Secure Boot is enabled on the target. VIP controls which packets are allowed
to be issued to the target through hash verification.

To generate a digest table:

```bash
mkdir vip
qfenix --create-digests=./vip prog_firehose_ddr.elf rawprogram*.xml patch*.xml
```

To flash using VIP mode:

```bash
qfenix --vip-table-path=./vip prog_firehose_ddr.elf rawprogram*.xml patch*.xml
```

### Multi-programmer targets

On some targets multiple files need to be loaded in order to reach the
Firehose programmer. Three mechanisms are provided:

#### Command line argument

```bash
qfenix 13:prog_firehose_ddr.elf,42:the-answer rawprogram.xml
```

#### Sahara configuration XML file

```bash
qfenix sahara_programmer.xml rawprogram.xml
```

#### Programmer archive

```bash
ls | cpio -o -H newc > ../programmer.cpio
qfenix programmer.cpio rawprogram.xml
```

## Run tests

```bash
make tests
```

## Build/Compile yourself

### Linux

```bash
sudo apt install libxml2-dev libusb-1.0-0-dev help2man
make
```

### MacOS

For Homebrew users,

```bash
brew install libxml2 pkg-config libusb help2man
make
```

For MacPorts users

```bash
sudo port install libxml2 pkgconfig libusb help2man
make
```

### Windows

First, install the [MSYS2 environment](https://www.msys2.org/). Then, run the
MSYS2 MinGW64 terminal (located at `<msys2-installation-path>\mingw64.exe`) and
install additional packages needed for compilation using the `pacman` tool:

```bash
pacman -S base-devel --needed
pacman -S git
pacman -S help2man
pacman -S mingw-w64-x86_64-gcc
pacman -S mingw-w64-x86_64-make
pacman -S mingw-w64-x86_64-pkg-config
pacman -S mingw-w64-x86_64-libusb
pacman -S mingw-w64-x86_64-libxml2
```

Then use the `make` tool to build:

```bash
make
```

## Upstream

This project is a fork of [linux-msm/qdl](https://github.com/linux-msm/qdl).
Thanks to the original authors and contributors.

## License

This tool is licensed under the BSD 3-Clause license. See [LICENSE](LICENSE)
for details.
