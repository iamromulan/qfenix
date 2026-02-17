# QFenix

[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

An enhanced fork of [linux-msm/qdl](https://github.com/linux-msm/qdl) — a Swiss Army knife
for Qualcomm-based modems and devices. Flash firmware, read/write NV items, browse EFS,
inspect GPT partitions, and more — all from a single binary.

## Download/Install/Run

Static binaries are available for download under [Releases](https://github.com/iamromulan/qfenix/releases).
A single `qfenix` binary provides all functionality via subcommands.

These are all static/standalone binaries with the exception of the macOS binaries. The macOS ones are semi-static,
3rd party libs are bundled but still need dynamic system frameworks that should exist on every Mac.

## What's New in QFenix

This fork adds several features while maintaining full backwards compatibility with
the original QDL:

- **Automatic Firmware Detection** (`-F` / `--firmware-dir`) - Point to any firmware
  directory and QFenix recursively searches for the programmer, rawprogram/patch/rawread
  XMLs, and auto-detects the storage type. Works with any directory layout.
- **Document-Order XML Execution** - Erase, program, and read commands execute in the
  exact order they appear in the XML files. The original QDL groups all erases first,
  then all programs, losing the intended sequence. QFenix preserves it, enabling
  workflows like backup-then-erase-then-flash within a single XML.
- **DIAG to EDL Auto-Switching** - Automatically switches devices from DIAG mode to
  EDL mode (can be disabled with `--no-auto-edl`). Works on both Linux and Windows.
- **PCIe/MHI Transport** - Flash PCIe-connected modems (T99W175,
  T99W373, T99W640, etc.) via MHI BHI on Linux or COM ports on Windows.
  Auto-detected when `/dev/mhi_*` devices are present (`--pcie` flag optional).
- **DIAG Protocol** - NV item read/write, full EFS filesystem management (list, pull,
  push, stat, mkdir, chmod, symlink, delete), factory image dump, EFS backup/restore
  to TAR archives or QPST-compatible XQCN format (with NV item scanning and
  provisioning path probing for coverage exceeding QPST) — all over the DIAG serial port.
- **Partition Erase** - Erase individual partitions by label (`erase`) or wipe all
  partitions at once (`eraseall`). The `flash -e` flag provides an atomic
  backup-erase-flash workflow: reads first, then erases all, then programs.
- **Comprehensive Device Listing** - `qfenix list` shows USB EDL devices, DIAG serial
  ports, and PCIe MHI devices across all transports.
- **GPT Inspection & A/B Slots** - Print partition tables, query/set the active A/B
  slot, and dump all partitions without XML files.
- **Wide Modem Support** - Centralized VID/PID database covering Quectel, Sierra
  Wireless, Telit, Fibocom, Simcom, MeiG, Foxconn/Dell, and more.
- **Multi-Device Targeting** - Use `--serial` with COM port names on Windows
  (e.g. `--serial COM49`) to target a specific modem when multiple are connected.
- **MD5 Verification** - Verifies firmware file integrity before flashing when MD5
  checksums are present in the XML (can be skipped with `--skip-md5`)
- **Partition Backup** - Read one or more partitions by label (`read`) or dump all
  at once (`readall`). Supports full-storage single-file dumps for complete
  backup/restore via `--single-file`. Auto-detects file extensions from partition
  content (`.elf`, `.ubi`, `.img`, etc.). Automatic retry on read failures.
- **XML Generation** - `printgpt --make-xml=read` and `--make-xml=program` generate
  rawread/rawprogram XML files from the live partition layout.
- **Improved NAND Support** - Fixes for NAND device flashing (last_sector handling),
  MIBIB/SMEM partition table support for backup and inspection.
- **Relaxed XML Parsing** - Optional attributes (label, sparse) no longer cause failures
- **Single Binary** - All tools consolidated into one `qfenix` binary with subcommands

### Quick Start

```bash
# Auto-detect everything from a firmware directory
qfenix -F /path/to/firmware/

# Flash a PCIe modem
qfenix --pcie -F /path/to/firmware/

# Dry run to see what would be flashed
qfenix --dry-run -F /path/to/firmware/

# Traditional usage still works
qfenix prog_firehose_ddr.elf rawprogram*.xml patch*.xml
```

---

## Usage

### Subcommands

**Flashing & Storage:**

| Subcommand | Description |
|------------|-------------|
| *(default)* | Flash firmware (Firehose protocol) |
| `flash` | Flash firmware (explicit subcommand, same as default) |
| `printgpt` | Print GPT partition tables from a live device |
| `storageinfo` | Query storage hardware information |
| `reset` | Reset/power-off/EDL-reboot a device |
| `getslot` | Show the active A/B slot |
| `setslot` | Set the active A/B slot |
| `read` | Read one or more partitions by label |
| `readall` | Dump all partitions to files |
| `erase` | Erase one or more partitions by label |
| `eraseall` | Erase all partitions on the device |

**DIAG Operations** (work directly on DIAG port, no programmer needed):

| Subcommand | Description |
|------------|-------------|
| `diag2edl` | Switch a device from DIAG mode to EDL mode |
| `nvread` | Read an NV item via DIAG |
| `nvwrite` | Write an NV item via DIAG |
| `efsls` | List an EFS directory |
| `efspull` | Download a file from EFS |
| `efspush` | Upload a file to EFS |
| `efsrm` | Delete a file or directory from EFS (`-r` for recursive) |
| `efsstat` | Show EFS file/directory information |
| `efsmkdir` | Create a directory on EFS |
| `efschmod` | Change EFS file/directory permissions |
| `efsln` | Create a symlink on EFS |
| `efsrl` | Read a symlink target on EFS |
| `efsdump` | Dump the EFS factory image |
| `efsbackup` | Backup EFS filesystem to TAR or XQCN format |
| `efsrestore` | Restore EFS filesystem from TAR or XQCN file |
| `xqcn2tar` | Convert XQCN backup to TAR archive (offline) |
| `tar2xqcn` | Convert TAR archive to XQCN format (offline) |

**Other:**

| Subcommand | Description |
|------------|-------------|
| `list` | List connected EDL, DIAG, and PCIe devices |
| `ramdump` | Extract RAM dumps via Sahara |
| `ks` | Keystore/Sahara over serial device nodes |

### Flash Options

| Option | Description |
|--------|-------------|
| `-F, --firmware-dir=PATH` | Recursively auto-detect and load firmware from directory |
| `-e, --erase-all` | Erase all partitions before programming (reads first, then erase, then flash) |
| `-E, --no-auto-edl` | Disable automatic DIAG to EDL mode switching |
| `-M, --skip-md5` | Skip MD5 verification of firmware files |
| `-P, --pcie` | Force PCIe/MHI transport (auto-detected on Linux) |
| `-S, --serial=T` | Target device by serial number or COM port name |

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
# Recursively finds programmer, XMLs, and detects storage type
qfenix -F /path/to/extracted/firmware/
```

**Traditional mode:**

```bash
qfenix prog_firehose_ddr.elf rawprogram*.xml patch*.xml
```

If you have multiple boards connected, provide the serial number:

```bash
qfenix --serial=0AA94EFD -F /path/to/firmware/

# On Windows, target a specific COM port
qfenix --serial=COM49 -F /path/to/firmware/
```

### List connected devices

Shows USB EDL devices, DIAG serial ports, and PCIe MHI devices:

```bash
qfenix list
```

Example output:
```
EDL devices (USB):
  05c6:9008  SN:0AA94EFD

DIAG devices:
  /dev/ttyUSB0  2c7c:0800  iface 0  USB

PCIe MHI devices:
  /dev/mhi_BHI          port 0
  /dev/mhi_DIAG         port 0
```

### DIAG operations

Read and write NV items on a device in DIAG mode:

```bash
# Read NV item 0 (ESN)
qfenix nvread 0

# Read NV item with subscription index
qfenix nvread 6828 --index=0

# Write NV item (hex data)
qfenix nvwrite 6828 0102030405

# Target a specific device
qfenix nvread 0 --serial COM49
```

Browse and manage files on the modem's EFS filesystem:

```bash
# List EFS root directory
qfenix efsls /

# Download a file from EFS
qfenix efspull /nv/item_files/modem/mmode/band_pref.bin ./band_pref.bin

# Upload a file to EFS
qfenix efspush ./band_pref.bin /nv/item_files/modem/mmode/band_pref.bin

# Show file information
qfenix efsstat /nv/item_files/modem/mmode/band_pref.bin

# Create a directory
qfenix efsmkdir /custapp/mydir

# Change permissions
qfenix efschmod 0755 /custapp/mydir

# Create a symlink
qfenix efsln /target/path /link/path

# Read a symlink target
qfenix efsrl /link/path

# Delete a file
qfenix efsrm /custapp/mydir/file.bin

# Recursively delete a directory
qfenix efsrm -r /custapp/mydir

# Dump factory EFS image (binary format)
qfenix efsdump efs_backup.bin
```

### EFS backup and restore

Backup and restore the entire EFS filesystem. Default TAR backup probes known
provisioning paths for comprehensive coverage beyond what directory walking finds:

```bash
# Backup EFS to TAR (tree walk + probe for maximum coverage)
qfenix efsbackup -o efs_backup.tar

# Quick backup (tree walk only, faster but fewer files)
qfenix efsbackup --quick -o efs_backup.tar

# Backup a specific EFS subtree
qfenix efsbackup -o nv_backup.tar /nv/item_files

# Force manual tree walk (if modem TAR generation fails)
qfenix efsbackup --manual -o efs_backup.tar

# Restore EFS from a TAR archive
qfenix efsrestore efs_backup.tar
```

### XQCN backup (QPST-compatible)

Generate XQCN backups that exceed QPST's coverage. XQCN format includes NV
numbered items, RF calibration data, and provisioning files in a single file:

```bash
# Backup to XQCN format (includes NV item scan + EFS files)
qfenix efsbackup -x -o backup.xqcn

# Restore from XQCN (auto-detected)
qfenix efsrestore backup.xqcn

# Offline format conversion (no device needed)
qfenix xqcn2tar backup.xqcn output.tar
qfenix tar2xqcn backup.tar output.xqcn
```

### GPT and partition operations

Inspect partition tables and A/B slot status on a live device in EDL mode:

```bash
# Print GPT partition tables
qfenix printgpt prog_firehose_ddr.elf

# Generate rawread/rawprogram XML files from the partition layout
qfenix printgpt -L /path/to/firmware/ --make-xml=read -o ./backup/
qfenix printgpt -L /path/to/firmware/ --make-xml=program -o ./backup/

# Get active A/B slot
qfenix getslot prog_firehose_ddr.elf

# Set active slot
qfenix setslot a prog_firehose_ddr.elf

# Query storage info
qfenix storageinfo prog_firehose_ddr.elf

# Dump all partitions to a directory
qfenix readall prog_firehose_ddr.elf -o /path/to/output/

# Or use auto-detected loader
qfenix readall -L /path/to/firmware/ -o /path/to/output/

# Dump entire storage as a single file (for full backup/restore)
qfenix readall -L /path/to/firmware/ --single-file=/path/to/full_backup.bin

# Read a single partition by label
qfenix read efs2 -L /path/to/firmware/ -o /path/to/efs2_backup.bin

# Read multiple partitions at once (auto-named with detected extensions)
qfenix read efs2 modem system -L /path/to/firmware/ -o /path/to/backups/

# If -o is omitted, output goes to the loader directory
qfenix read modem -L /path/to/firmware/

# Erase a specific partition
qfenix erase efs2 -L /path/to/firmware/

# Erase multiple partitions
qfenix erase efs2 efs3 modemst1 modemst2 -L /path/to/firmware/

# Erase raw sectors by address (start sector + count)
qfenix erase -L /path/to/firmware/ --start-sector=0 --num-sectors=1024

# Erase all partitions on the device
qfenix eraseall -L /path/to/firmware/

# Flash with erase-all: reads first, then erases everything, then programs
qfenix flash -e -F /path/to/firmware/
```

### PCIe modem flashing

Flash PCIe-connected modems (Dell DW5930e/DW5931e/DW5934e, Foxconn T99W175/T99W373/T99W640, etc.):

```bash
# Linux: auto-detected when /dev/mhi_* devices are present
qfenix -F /path/to/firmware/

# Or explicitly specify PCIe transport
qfenix --pcie -F /path/to/firmware/

# Windows: uses COM port (auto-detected or specified)
qfenix --pcie --serial=COM51 -F /path/to/firmware/
```

### Switch from DIAG to EDL mode

Switch a device from DIAG mode to EDL mode without flashing:

```bash
qfenix diag2edl

# Target a specific device
qfenix diag2edl --serial COM49
```

### Reset device

```bash
# Reset (reboot)
qfenix reset prog_firehose_ddr.elf

# Power off
qfenix reset prog_firehose_ddr.elf --mode=off

# Reboot into EDL
qfenix reset prog_firehose_ddr.elf --mode=edl
```

### RAM dump extraction

```bash
qfenix ramdump [-o /path/to/output] [segment-filter]
```

### Keystore / Sahara over serial device

```bash
qfenix ks -p /dev/mhi0_QAIC_SAHARA -s 1:/opt/qti-aic/firmware/fw1.bin -s 2:/opt/qti-aic/firmware/fw2.bin
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

## Supported Devices

QFenix includes a comprehensive VID/PID database for automatic detection of:

- **Qualcomm** reference designs (SDX55, SDX65, SDX72)
- **Quectel** (EM05, EM06, EM12, EM060K, EM120K, RM520N, RM255C, RG650V, etc.)
- **Sierra Wireless** (EM74xx, EM9190, EM9191, EM9291)
- **Telit** (LM960, FN980, FN990, FM990, LE910C4)
- **Fibocom** (FM150, FM160)
- **Foxconn/Dell** (DW5820e, DW5930e, DW5931e, DW5934e / T99W175, T99W373, T99W640)
- **Simcom** (SIM8200EA, SIM8380G)
- **MeiG Smart** (SRM825, SRM930)
- **Sony, ZTE, LG, Netgear, Huawei** EDL/DIAG devices

PCIe modems (MHI-based) are detected via friendly name matching on Windows.

## Upstream

This project is a fork of [linux-msm/qdl](https://github.com/linux-msm/qdl).
Thanks to the original authors and contributors.

## License

This tool is licensed under the BSD 3-Clause license. See [LICENSE](LICENSE)
for details.
