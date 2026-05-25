# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**QFenix** is an enhanced fork of [linux-msm/qdl](https://github.com/linux-msm/qdl) — a Swiss Army knife for Qualcomm-based modems and devices. Communicates with USB (EDL mode) and PCIe (MHI) devices to upload flash loaders and flash firmware, plus DIAG protocol support for NV/EFS operations.

This fork adds improved compatibility for Quectel, Sierra Wireless, Telit, Fibocom, Foxconn/Dell, Simcom, MeiG, and other Qualcomm-based devices while maintaining full backwards compatibility with the original QDL.

**Repository**: https://github.com/iamromulan/qfenix (renamed from qdl)

## Build Commands

```bash
# Install dependencies (Linux)
sudo apt install libxml2-dev libusb-1.0-0-dev help2man

# Build the qfenix binary
make

# Clean build artifacts
make clean

# Install to /usr/local/bin
make install

# Generate man pages
make manpages

# Generate compile_commands.json for LSP
make compile_commands.json
```

## Testing

```bash
# Run the test suite
make tests

# Individual test scripts are in tests/
./tests/test_vip_generation.sh
```

## Code Style

This project follows Linux kernel coding style (v6.15). Before committing:

```bash
# Check staged changes for style violations
make check-cached

# Check all source files
make check
```

The `checkpatch.pl` script is auto-downloaded on first use. Excluded from checks: sha2.c, sha2.h, md5.c, md5.h, version.h, list.h.

## Architecture

### Single Binary with Subcommands
All functionality is consolidated into one binary (`qfenix`), with subcommands:

**Flashing & Storage (require programmer + EDL mode):**
- **`qfenix [flash args]`** - Main flashing tool (default) (firehose.c, firehose_op.c, qdl.c, program.c, patch.c, read.c, vip.c, sparse.c, gpt.c, diag_switch.c, md5.c). Supports `-e`/`--erase-all` for phased execution (reads → eraseall → programs → patches).
- **`qfenix printgpt`** - Print GPT partition tables from live device
- **`qfenix storageinfo`** - Query storage hardware information
- **`qfenix reset`** - Reset/power-off/EDL-reboot device
- **`qfenix getslot`** - Show active A/B slot
- **`qfenix setslot`** - Set active A/B slot
- **`qfenix read`** - Read partition(s) by label
- **`qfenix readall`** - Dump all partitions to files (supports `--single-file` for full storage dump)
- **`qfenix erase`** - Erase partition(s) by label or raw sectors (`--start-sector`/`--num-sectors`)
- **`qfenix eraseall`** - Erase all partitions on device

**DIAG operations (require DIAG mode, no programmer needed):**
- **`qfenix diag2edl`** - Switch device from DIAG to EDL mode
- **`qfenix nvread`** - Read NV item via DIAG protocol
- **`qfenix nvwrite`** - Write NV item via DIAG protocol
- **`qfenix efsls`** - List EFS directory contents
- **`qfenix efspull`** - Download file from EFS
- **`qfenix efspush`** - Upload file to EFS
- **`qfenix efsrm`** - Delete file or directory from EFS (`-r` for recursive)
- **`qfenix efsstat`** - Show EFS file/directory metadata
- **`qfenix efsmkdir`** - Create directory on EFS
- **`qfenix efschmod`** - Change EFS file/directory permissions
- **`qfenix efsln`** - Create symlink on EFS
- **`qfenix efsrl`** - Read symlink target on EFS
- **`qfenix efsdump`** - Dump EFS factory image
- **`qfenix efsbackup`** - Backup EFS to TAR or XQCN format (`-x` for XQCN, `--quick` to skip probe walk)
- **`qfenix efsrestore`** - Restore EFS from TAR or XQCN (auto-detected)
- **`qfenix xqcn2tar`** - Convert XQCN backup to TAR archive (offline, no device)
- **`qfenix tar2xqcn`** - Convert TAR archive to XQCN format (offline, no device)

**Other:**
- **`qfenix list`** - List connected EDL, DIAG, and PCIe devices across all transports
- **`qfenix ramdump`** - RAM dump extraction
- **`qfenix ks`** - Keystore/Sahara utility (serial device nodes)

### Protocol Layers
- **Sahara** (sahara.c) - Bootloader loading protocol, handles multi-programmer targets
- **Firehose** (firehose.c) - Main programming protocol for flashing operations, storage info, power control
- **DIAG** (diag.c) - Qualcomm DIAG protocol for NV items and EFS filesystem operations. Key internals: `diag_send()` filters unsolicited messages (accepts DIAG error codes 0x13-0x18), `diag_nv_write()` returns NV status (0=DONE, >0=status code, -1=protocol error), `nv_excluded_ids[]` blocklist for problematic NV items, EFS open flags are POSIX (O_CREAT=0x0040), `efs_write_file()` 2-tier fallback with ENOSPC retry (PUT v2 → open/write/close + sync). EFS2_DIAG_WRITE (opcode 5) request has NO length field — format is `[header(4)][fd(4)][offset(4)][data...]`, length implicit from packet size (ref: libopenpst QcdmEfsWriteFileRequest). EFS2_DIAG_READ (opcode 4) DOES have a size field — the two are asymmetric. `efs_sync()` flushes EFS2 journal via SYNC_NO_WAIT/SYNC_GET_STATUS (opcodes 48/49). XQCN restore ends with DIAG_MODE_RESET (full reboot) for modem to reload EFS config.
- **HDLC** (hdlc.c) - HDLC framing and CRC for DIAG protocol
- **USB** (usb.c) - libusb-based device communication
- **PCIe** (pcie.c) - MHI BHI transport on Linux, COM port serial transport on Windows
- **Simulator** (sim.c) - Testing without physical device

### EFS Provisioning Database (efs_paths.h)
Built-in database of ~560 known EFS provisioning paths for probe-based backup. Covers paths across SDX55/65/72/75 chipsets. Files are classified into 3 XQCN sections via `efs_path_xqcn_section()`: `XQCN_SECTION_PROV` (provisioning), `XQCN_SECTION_BACKUP` (rfnv items), `XQCN_SECTION_NVITEMS` (rfc/calibration). rfnv items (20000-32000) are probed dynamically via `efs_stat()` rather than hardcoded by ID.

### XQCN Format (QPST-compatible)
XQCN files contain 4 data sections in XML: `NV_NUMBERED_ITEMS` (NV_ITEM_ARRAY: 136 bytes/record with `{uint16 size=0x88, uint16 sub, uint32 id, uint8[128] data}`), `EFS_Backup` (8-byte header `{01 00 01 01}` + 4-byte attrs + path, NO null terminator), `Provisioning_Item_Files` (raw path WITH null terminator), `NV_Items` (raw path, NO null terminator). `/rfc/` paths are duplicated in both EFS_Backup (attrs=0x00000000) and NV_Items for cross-firmware restore redundancy. rfnv paths go in EFS_Backup only (attrs=0x12D53D80). SIM_1 subscription NV items use sub=0x02 in NV_ITEM_ARRAY.

### Device Abstraction
The `struct qdl_device` in qdl.h provides a unified interface with function pointers for device operations (open/read/write/close). Supports USB devices (`QDL_DEVICE_USB`), PCIe/MHI devices (`QDL_DEVICE_PCIE`), and a simulator (`QDL_DEVICE_SIM`) for testing.

### Device Detection
- **usb_ids.h** - Centralized VID/PID database for EDL and DIAG devices. Contains `edl_ids[]` (EDL mode devices from Qualcomm, Sony, Sierra, Netgear, ZTE, LG), `diag_vids[]` (DIAG-capable vendor IDs), and `diag_iface_maps[]` (per-model DIAG USB interface number mapping).
- **USB detection**: Matches VID/PID from `edl_ids[]` and `diag_vids[]` tables
- **PCIe detection (Windows)**: Falls back to friendly name matching when no USB VID/PID is present. Uses `is_qualcomm_modem_name()` helper to recognize PCIe/MHI modems (T99W175, T99W373, T99W640, DW59xx, EM91xx, etc.)
- **PCIe detection (Linux)**: Scans `/dev/mhi_BHI*`, `/dev/mhi_DIAG*`, `/dev/mhi_EDL*`
- **Multi-device**: `--serial` accepts USB serial numbers or Windows COM port names (e.g. `--serial COM49`) for targeting specific devices

### Storage Types
Supports eMMC, NAND, UFS, NVMe, and SPI-NOR flash storage.

### Key Features (QFenix additions marked with *)
- **\*Document-Order XML Execution** - Operations execute in the exact order they appear in XML files via a unified operation queue (firehose_op.c), not grouped by type. Enables workflows like backup→erase→flash in a single XML.
- **\*Universal XML Tag Handling** - Any XML file can contain any tag type (erase, program, read, patch). Tags are dispatched to the correct handler regardless of which file they appear in.
- **\*Recursive Firmware Detection** - `-F` flag recursively searches for programmer ELF, rawprogram/patch/rawread XMLs from the specified directory (depth limit 10), instead of only checking a hardcoded `update/firehose/` path.
- **\*Windows Path Normalization** - Backslash path separators in XML (e.g. `.\dump\file.elf`) are converted to forward slashes. Parent directories are auto-created for read output files (mkpath in util.c).
- **\*Auto DIAG-to-EDL Switching** - Automatically detects devices in DIAG mode and switches them to EDL mode (diag_switch.c). Disable with `--no-auto-edl`.
- **\*PCIe/MHI Transport** - `--pcie` flag for flashing PCIe-connected modems. Linux uses BHI ioctl for programmer upload; Windows uses Sahara over COM port. `pcie_prepare()` returns 0 (Linux: BHI done) or 1 (Windows: Sahara needed).
- **\*DIAG Protocol** - Full NV read/write (standard and indexed), NV item scanning with configurable blocklist (`nv_excluded_ids[]`), complete EFS filesystem management (list, pull, push, stat, mkdir, chmod, symlink, readlink, delete, recursive delete), factory image dump, EFS backup/restore to TAR or XQCN format (QPST-compatible). EFS write uses 2-tier fallback with ENOSPC retry: PUT v2 (opcode 38, files ≤6KB) → open/write/close with O_ITEMFILE for item paths (files >6KB or PUT failure), journal sync between retries. EFS open flags are POSIX (O_CREAT=0x0040). Probe-based backup discovers virtual NV item files invisible to readdir. XQCN restore phases: NV items → sync → Provisioning_Item_Files → EFS_Backup → NV_Items → device reset. XQCN↔TAR offline conversion with QPST-compatible attrs (0x12D53D80 for rfnv, 0x00000000 for rfc). HDLC framing with CRC-16. Verbose restore logging with `-d` flag (QPST-style per-item status). Works on both Linux (ttyUSB/ttyACM) and Windows (COM ports via SetupAPI).
- **\*GPT Operations** - Print partition tables, query/set A/B slots, dump all partitions, erase partitions by label or erase all via Firehose commands.
- **\*Partition Erase** - `erase` and `eraseall` subcommands for GPT and NAND devices. `erase` supports raw sector ranges (`--start-sector`/`--num-sectors`). The `flash -e` flag provides phased execution: reads (backup) → erase all → programs (flash) → patches.
- **\*Comprehensive Device Listing** - `qfenix list` scans USB (libusb), Windows COM ports (SetupAPI), and Linux MHI devices. Classifies ports as EDL or DIAG by VID/PID or friendly name.
- **\*Multi-Device Support** - `--serial COMnn` passthrough bypasses auto-detection on Windows, allowing targeting of specific COM ports.
- **\*MD5 Verification** - Verifies firmware file integrity via md5 attribute in program XML (md5.c). Skip with `--skip-md5`.
- **\*Relaxed XML Parsing** - Optional attributes (label, sparse) no longer cause failures.
- **\*NAND Fixes** - Proper handling of last_sector attribute.
- **VIP (Validated Image Programming)** - Secure boot support with hash-based packet validation (vip.c)
- **Sparse Images** - Efficient sparse image format handling (sparse.c)
- **GPT Support** - GUID Partition Table operations (gpt.c)
- **XML Parsing** - rawprogram*.xml and patch*.xml via libxml2

### Unified Operation Queue (firehose_op.c)
All erase, program, read, and patch operations are registered in a single ordered list as they are parsed from XML. `firehose_op_execute()` iterates this list in document order, dispatching each operation to the appropriate callback. This replaces the original 4-pass approach (all erases → all programs → all patches → all reads).

- `firehose_op_add_program()` - called from program.c after every list_add to programs list
- `firehose_op_add_read()` - called from read.c after every list_add to read_ops list
- `firehose_op_add_patch()` - called from patch.c after every list_add to patches list
- Per-type lists (programs, read_ops, patches) are retained for GPT deferral, bootable partition search, etc.
- `firehose_op_execute_phased()` - alternative executor for `flash -e`: runs reads first (phase 1), then erases all partitions (phase 2), then programs (phase 3), then patches (phase 4). Skips individual OP_ERASE entries since eraseall replaces them.

### Shared Utilities (util.c)
- `normalize_path()` - converts `\` to `/` in-place, used by program.c, read.c, patch.c
- `mkpath()` - creates parent directories for a file path (mkdir -p equivalent)
- `attr_as_string()`, `attr_as_unsigned()`, `attr_as_bool()` - XML attribute parsing
- `parse_storage_address()` - parses partition/sector address specifiers
- `load_sahara_image()` - loads a file into a sahara_image struct

### Firehose Session Helpers (qdl.c)
`firehose_session_open()` provides a unified entry point for subcommands that need a Firehose connection. Handles USB vs PCIe transport selection, Sahara programmer upload, and Firehose configuration. Used by printgpt, storageinfo, reset, getslot, setslot, read, readall, erase, eraseall. `firehose_session_close()` handles optional reset and cleanup.

### PCIe Transport (pcie.c)
- **Linux**: `pcie_open()` scans `/dev/mhi_EDL*` then `/dev/mhi_QMI*` then `/dev/mhi_SAHARA*`. `pcie_prepare()` sends programmer via BHI ioctl, returns 0 (no Sahara needed).
- **Windows**: `pcie_open_win()` scans COM ports via SetupAPI for EDL-mode friendly names, or accepts `--serial COMnn`. Uses CreateFile/DCB serial. `pcie_prepare()` sends DIAG-to-EDL switch + Sleep(3000), returns 1 (Sahara still needed over COM).
- **macOS**: Stub returning error (no MHI support).

## CI/CD

### Static Release Builds (.github/workflows/static-release.yml)
Triggered on `v*` tags only. Builds fully static binaries for 8 platforms:
- Linux: x86_64, aarch64, armv7l
- macOS: x86_64, arm64
- Windows: x86_64, x86, arm64

Linux uses musl via Alpine. macOS builds libxml2/libusb from source. Windows uses MSYS2 with Enigma Virtual Box for single-EXE bundling. Releases are created as pre-releases by default.

## Dependencies

- libxml2 - XML parsing
- libusb-1.0 - USB device communication
- pkg-config - Dependency resolution
- help2man - Man page generation

## Version

Version is derived from git tags via `git describe --dirty --always --tags`, with fallback to "unknown-version" when not in a git repo.
