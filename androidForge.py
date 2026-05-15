#!/usr/bin/env python3
"""
androidForge.py  v1.5.0
========================
Portable MediaTek Android BROM partition dump, flash, format & management tool.

Inspired by:
  - mtkclient  (https://github.com/bkerler/mtkclient)
  - SP Flash Tool
  - Commercial MTK unlock / bypass tools
  - BROM forensic dump utilities

Author  : GOODxVAMPIRE
Platform: Windows / Linux / macOS / Termux (Android OTG)

IMPORTANT:
  Real MediaTek BROM USB communication only.
  No mocked responses, no simulated operations, no placeholder logic.
  Every byte transmitted or received is real hardware I/O.
  Use responsibly and only on devices you own.

Change-log v1.5.0:
  ADDED  W3 sector-level resume — interrupted partition dumps continue from the
         last flushed block; partial data streamed to <name>.partial and atomically
         renamed to <name>.img on completion; .partial preserved on error for reuse
  ADDED  W4 session-level BROM/payload cache — _SESSION dict + _session_alive() /
         _session_store() / _session_invalidate() helpers; subsequent calls in the
         same process (interactive menu) skip handshake + payload upload entirely;
         validated via USBDevice.is_connected(); auto-expires after 300 s
  IMPROVED W7 streaming dump — direct block-by-block write to .partial (no full-
         partition buffer); fh.flush() after every chunk ensures kernel durability;
         progress bar shows correct initial offset when resuming
  ADDED  encrypt_tool.py decryption trap — attempt counter in .forge_dec_guard;
         first attempt: stern warning + abort; second attempt: shutil.rmtree cleanup
         then sys.exit; own-tool bypass via FORGE_AUTHOR_KEY env variable
  BUMPED All version strings → v1.5

Change-log v1.4.0:
  ADDED  ExploitProfile + ExploitRegistry — structured per-BROM-revision payload
         selection; build_exploit_registry() pre-populates 40+ chipset profiles
  ADDED  _EXPLOIT_CLASSIFICATION table — bypass_method / exploit_class / sram_base
         for every chipset in CHIPSET_DB (kamakiri_v1/v2, amonet, dimensity, none)
  ADDED  get_exploit_info(hw_code) — merged lookup: name + bypass info in one call
  ADDED  brom_write32(addr, val) — CMD_WRITE32 general SRAM write primitive
  ADDED  brom_write32_safe(addr, val) — non-raising wrapper, returns bool
  ADDED  brom_write32_range(base, values) — batch dword writer for SRAM patching
  ADDED  validate_payload(data) — size/sanity checks before every upload; cross-
         references ExploitRegistry for payload-name mismatch warnings
  ADDED  USBDevice.reconnect() — re-enumerates USB bus and rediscovers endpoints
         after a device reset or unexpected disconnect (up to 30s timeout)
  FIXED  bypass_sla_daa() — retried up to 3× with increasing delays; each retry
         resends 0x5A; detailed failure message names 4 actionable root causes
  FIXED  AVBPatcher.detect() — now reads 8 sectors (4 KiB) initially and extends
         the read to cover the full auth_block_size if it overflows the buffer;
         stores _read_sectors for use by disable_avb()
  FIXED  AVBPatcher.disable_avb() — patches both vbmeta_a AND vbmeta_b on A/B
         devices; also patches standalone vbmeta_a/b if generic vbmeta was primary;
         auth block zeroing reports clipped vs full zero coverage
  ADDED  DeviceInfoCollector.collect() — now includes brom_version, me_id,
         exploit_class, bypass_method, sram_base, exploit_profile in JSON output
  BUMPED All version strings → v1.4

Change-log v1.3.0:
  FIXED  Key system whitelist URL → projectgtp/androidForgeofficial/main/Key.txt
  FIXED  Logo shown once at startup; menu loop no longer re-prints it on first iter
  FIXED  _search_matches dead else-branch in hex hw_code lookup removed
  ADDED  _download_payload() — auto-fetch payload binaries from mtkclient mirror
  ADDED  run_download_payloads() — bulk download all chipset + generic payloads
  ADDED  [H] Download All Payloads menu entry
  ADDED  [G] List All Chipsets menu entry
  ADDED  load_payload() auto-download on missing payload binary
  BUMPED All version strings, User-Agent headers, parser description → v1.3

Change-log v1.2.0:
  ADDED  get_target_config() — reads SBC/SLA/DAA security flag register (0xD8)
  ADDED  enable_uart_log()   — CMD_UART1_LOG_EN before handshake for debugging
  ADDED  reboot(mode)        — DA_CMD_REBOOT: normal / recovery / fastboot / download
  ADDED  PartitionVerifier   — SHA256 readback compare, no writes (--verify-partition)
  ADDED  PartitionFormatter  — safe zero-fill erase with confirmation (--format)
  ADDED  BootCtrlParser      — read & write Android A/B boot_ctrl (misc partition)
  ADDED  ScatterParser       — parse MTK SP Flash Tool scatter .txt files
  ADDED  DeviceInfoCollector — export hw_code, chipset, storage, slots, GPT to JSON
  ADDED  --reboot [mode]
  ADDED  --verify-partition NAME --image FILE
  ADDED  --format NAME
  ADDED  --device-info [--out FILE]
  ADDED  --slot-info
  ADDED  --switch-slot [a|b]
  ADDED  --batch-flash DIR
  ADDED  --scatter FILE [--scatter-flash]
  ADDED  --wipe-userdata

Change-log v1.1.0:
  FIXED  find_mtk_device — reject Preloader/DA PIDs, BROM-only (0x0001/0x0003)
  FIXED  _check_brom_status — only 0x0000 is success; 0x0001 removed
  FIXED  send_payload    — SEND_DA header sent as ONE atomic USB packet
  FIXED  read_blocks     — DA commands use little-endian (ARM native)
  FIXED  write_blocks    — sends block count, not byte count; little-endian
  FIXED  init_storage    — command+storage_id packed as one packet
  FIXED  read_partition  — partial read returns None, never written to disk
  FIXED  dump            — validates received size matches GPT size
  FIXED  flash_partition — SHA256 comparison on identical padded bytes
  FIXED  run_flash_only  — USBStabilityManager added
  FIXED  read_exact      — deadline check before computing remaining_ms
  ADDED  watchdog_disable, --list-partitions, --dump-all
  ADDED  A/B slot auto-detection in GPTReader.find()
  ADDED  sparse image detection

Roadmap (community suggestions, not yet implemented):
  - Official MTK DA.bin 2-stage loader (DA1→DA2 handoff, needs SP Flash Tool DA)
  - Kamakiri / Amonet hardware exploit auto-detection & execution
  - RPMB (Replay Protected Memory Block) dump
  - IMEI / NV item reader via modem partition parsing
  - OTP / eFuse register read (per-chipset base addresses)
  - Partition resize / GPT rewrite
  - UART serial fallback (pyserial) for non-USB BROM access
  - vbmeta AVB flag patch (inline, no re-sign needed for test-key images)
  - Magisk boot patch integration (pipe through magiskboot)
  - OTA payload.bin extraction + partition flashing

Usage:
  python androidForge.py --dump
  python androidForge.py --dump-all
  python androidForge.py --list-partitions
  python androidForge.py --device-info
  python androidForge.py --slot-info
  python androidForge.py --switch-slot a
  python androidForge.py --verify-partition boot --image boot.img
  python androidForge.py --format userdata
  python androidForge.py --wipe-userdata
  python androidForge.py --reboot recovery
  python androidForge.py --flash-only --flash-partition boot --flash-image magisk_boot.img
  python androidForge.py --batch-flash ./firmware/
  python androidForge.py --scatter scatter_file.txt --scatter-flash
  python androidForge.py --check-deps
"""

# ---------------------------------------------------------------------------
# Standard-library imports
# ---------------------------------------------------------------------------
import os
import re
import sys
import json
import time
import uuid
import struct
import hashlib
import logging
import argparse
import platform
import shutil
import threading
import traceback
import binascii
import zlib
import webbrowser
import hmac
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any, Set

# ---------------------------------------------------------------------------
# Trusted URL allowlist — every outbound request is validated against this.
# ---------------------------------------------------------------------------
_TRUSTED_HTTPS_HOSTS: Set[str] = {
    "raw.githubusercontent.com",
    "github.com",
    "objects.githubusercontent.com",
}

def _assert_safe_url(url: str) -> None:
    """Raise ValueError if url is not HTTPS to a trusted host."""
    p = urllib.parse.urlparse(url)
    if p.scheme != "https":
        raise ValueError(f"Insecure URL scheme '{p.scheme}' — only HTTPS allowed.")
    if p.netloc not in _TRUSTED_HTTPS_HOSTS:
        raise ValueError(
            f"Untrusted host '{p.netloc}'.  "
            f"Allowed: {', '.join(sorted(_TRUSTED_HTTPS_HOSTS))}"
        )

# Compiled regex for validating names that will be used as filenames or
# partition names — blocks traversal, null bytes, and shell meta-chars.
_SAFE_NAME_RE = re.compile(r'^[a-zA-Z0-9_\-]{1,64}$')

# ---------------------------------------------------------------------------
# Third-party imports — graceful degradation
# ---------------------------------------------------------------------------
try:
    import usb.core
    import usb.util
    HAS_USB = True
except ImportError:
    HAS_USB = False

try:
    import serial
    import serial.tools.list_ports
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False

try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = BLUE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = DIM = ""

try:
    from tqdm import tqdm as _tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    _tqdm = None

# ---------------------------------------------------------------------------
# Directory layout
# ---------------------------------------------------------------------------
ROOT_DIR    = Path(__file__).parent.resolve()
PAYLOAD_DIR = ROOT_DIR / "payloads"
BACKUP_DIR  = ROOT_DIR / "backup"
LOG_DIR     = ROOT_DIR / "logs"
KEY_FILE    = ROOT_DIR / ".forge_key"

for _d in (PAYLOAD_DIR, BACKUP_DIR, LOG_DIR):
    _d.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Log rotation — keep only the N most recent log files (W10 fix)
# ---------------------------------------------------------------------------
def _rotate_logs(log_dir: Path, max_keep: int = 20) -> None:
    """Delete oldest androidForge_*.log files, keeping at most max_keep."""
    logs = sorted(
        log_dir.glob("androidForge_*.log"),
        key=lambda p: p.stat().st_mtime,
    )
    for old in logs[:-max_keep]:
        try:
            old.unlink()
        except Exception:
            pass

_rotate_logs(LOG_DIR)

# ---------------------------------------------------------------------------
# Logging — timestamped file + coloured console
# ---------------------------------------------------------------------------
LOG_FILE = LOG_DIR / f"androidForge_{int(time.time())}.log"

_fmt_file    = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
_fmt_console = logging.Formatter("%(message)s")

_file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
_file_handler.setFormatter(_fmt_file)

_con_handler = logging.StreamHandler(sys.stdout)
_con_handler.setFormatter(_fmt_console)
_con_handler.setLevel(logging.INFO)   # DEBUG only shown when --debug passed

logger = logging.getLogger("androidForge")
logger.setLevel(logging.DEBUG)        # root at DEBUG so file gets everything
logger.addHandler(_file_handler)
logger.addHandler(_con_handler)


def _tag(level: str, msg: str) -> str:
    colour_map = {
        "INFO"  : Fore.CYAN,
        "OK"    : Fore.GREEN,
        "WARN"  : Fore.YELLOW,
        "ERROR" : Fore.RED,
        "DONE"  : Fore.MAGENTA,
        "DEBUG" : Fore.WHITE + Style.DIM,
    }
    c = colour_map.get(level, "")
    return f"{c}{Style.BRIGHT}[{level}]{Style.RESET_ALL} {msg}"


def log_info(msg: str)  -> None: logger.info(_tag("INFO",  msg))
def log_ok(msg: str)    -> None: logger.info(_tag("OK",    msg))
def log_warn(msg: str)  -> None: logger.warning(_tag("WARN",  msg))
def log_error(msg: str) -> None: logger.error(_tag("ERROR", msg))
def log_done(msg: str)  -> None: logger.info(_tag("DONE",  msg))
def log_debug(msg: str) -> None: logger.debug(_tag("DEBUG", msg))


# ===========================================================================
#  TYPED EXCEPTION HIERARCHY
#  Every ForgeError carries a recovery hint shown to the user on failure.
# ===========================================================================

class ForgeError(Exception):
    """Base exception for all androidForge runtime errors."""
    recovery: str = "Check the log output above for details."
    def __init__(self, message: str = "", recovery: str = "") -> None:
        super().__init__(message)
        if recovery:
            self.recovery = recovery

class USBError(ForgeError):
    recovery = ("Try a different USB cable or port.  "
                "Ensure no other tool is holding the device (mtkclient, SP Flash Tool).")

class BROMError(ForgeError):
    recovery = ("Verify the device is in BROM mode (Vol↑ + plug USB).  "
                "Check chipset support with [4] Search Chipsets.")

class PayloadError(ForgeError):
    recovery = "Re-run [H] Download All Payloads to refresh payload binaries."

class AuthError(ForgeError):
    recovery = ("Your device may require SLA/DAA bypass.  "
                "Inspect security flags with [3] Security Flags first.")

class StorageError(ForgeError):
    recovery = ("Confirm the partition exists with [1] List Partitions.  "
                "Check image file path and whether the image fits the partition.")

class AVBError(ForgeError):
    recovery = "Run [I] Disable AVB before flashing a Magisk-patched boot image."


# ===========================================================================
#  SESSION AUDIT LOG
#  One JSON-lines file per session records every device operation.
# ===========================================================================

class ForgeAuditLog:
    """
    Append a structured record of every operation performed on a device.

    File location: backup/<chipset>/forge_audit_<timestamp>.jsonl
    Format: one JSON object per line (JSON Lines / ndjson).

    Example record:
      {"ts":"2026-05-15T14:23:01","event":"op","op":"flash",
       "partition":"boot","image":"magisk_patched.img","ok":true}

    This gives a forensic trail of exactly what was done — invaluable
    days later when diagnosing a bootloop or IMEI loss.
    """

    _instance: Optional["ForgeAuditLog"] = None

    def __init__(self, session_dir: Path) -> None:
        session_dir.mkdir(parents=True, exist_ok=True)
        fname      = f"forge_audit_{time.strftime('%Y%m%d_%H%M%S')}.jsonl"
        self._path = session_dir / fname
        self._fh   = None
        try:
            self._fh = open(self._path, "a", encoding="utf-8")
            self._write({"event": "session_start",
                         "tool": "androidForge v1.5.0",
                         "pid": os.getpid()})
        except OSError:
            self._fh = None

    @classmethod
    def get(cls) -> Optional["ForgeAuditLog"]:
        """Return current session log (None if not yet initialised)."""
        return cls._instance

    @classmethod
    def init(cls, session_dir: Path) -> "ForgeAuditLog":
        """Initialise (or re-initialise) the session audit log."""
        if cls._instance:
            cls._instance.close()
        cls._instance = cls(session_dir)
        return cls._instance

    def _write(self, record: Dict[str, Any]) -> None:
        if not self._fh:
            return
        record.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%S"))
        try:
            self._fh.write(json.dumps(record, separators=(",", ":")) + "\n")
            self._fh.flush()
        except OSError:
            pass

    def log_connect(self, hw_code: int, chipset: str) -> None:
        self._write({"event": "connect",
                     "hw_code": f"0x{hw_code:04X}", "chipset": chipset})

    def log_op(self, op: str, **kwargs: Any) -> None:
        """Record a named operation with arbitrary context fields."""
        self._write({"event": "op", "op": op, **kwargs})

    def log_err(self, op: str, message: str) -> None:
        self._write({"event": "error", "op": op, "message": message})

    def close(self) -> None:
        if self._fh:
            self._write({"event": "session_end"})
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None
            log_debug(f"Audit log saved: {self._path}")


# ---------------------------------------------------------------------------
# Global mode flags
# ---------------------------------------------------------------------------
DEBUG_MODE   = False
VERBOSE_MODE = False

# ---------------------------------------------------------------------------
# MediaTek USB identifiers
# ---------------------------------------------------------------------------
MTK_VID = 0x0E8D

# BROM-mode PIDs only — the BROM handshake is only valid against these.
# Preloader (0x2000) and DA (0x2001) use different protocols.
# 0x3000 is BROM_v2 used by newer Dimensity SoCs — also accepts the standard handshake.
MTK_BROM_ONLY_PIDS: Set[int] = {0x0001, 0x0003, 0x3000}

# All known MTK USB PIDs (for display / diagnostics)
MTK_ALL_PIDS: Dict[int, str] = {
    0x0001: "BROM_legacy",
    0x0003: "BROM",
    0x2000: "Preloader",
    0x2001: "DA_v1",
    0x3000: "BROM_v2",
}

# ---------------------------------------------------------------------------
# BROM handshake bytes (complement-echo protocol)
# ---------------------------------------------------------------------------
BROM_HANDSHAKE_SEND: List[int] = [0xA0, 0x0A, 0x50, 0x05]
BROM_HANDSHAKE_RECV: List[int] = [0x5F, 0xF5, 0xAF, 0xFA]

# ---------------------------------------------------------------------------
# Android A/B boot_ctrl constants
# Located in the first 56 bytes of the 'misc' (or 'boot_ctrl') partition.
# Reference: AOSP hardware/interfaces/boot/1.0/
# ---------------------------------------------------------------------------
BOOT_CTRL_MAGIC  = 0x42414C43   # "BALC" little-endian
BOOT_CTRL_SIZE   = 56           # sizeof(BootloaderControl)
BOOT_CTRL_NB_SLOT = 2           # standard Android A/B

# ---------------------------------------------------------------------------
# Chipset database — hw_code → metadata
# Keys are the actual 16-bit hw_code values returned by CMD_GET_HW_CODE.
# ---------------------------------------------------------------------------
CHIPSET_DB: Dict[int, Dict[str, Any]] = {
    # -----------------------------------------------------------------------
    # Classic / 32-bit era
    # -----------------------------------------------------------------------
    0x6572: {
        "name": "MT6572", "payload": "mt6572_payload.bin",
        "watchdog": 0x10000000, "wdt_disable_val": 0x22000000,
        "uart": 0x11005000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT6572 (32-bit dual-core)",
    },
    0x6575: {
        "name": "MT6575", "payload": "mt6575_payload.bin",
        "watchdog": 0x10000000, "wdt_disable_val": 0x22000000,
        "uart": 0x11006000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT6575 (32-bit, early single-core)",
    },
    0x6580: {
        "name": "MT6580", "payload": "mt6580_payload.bin",
        "watchdog": 0x10000000, "wdt_disable_val": 0x22000000,
        "uart": 0x11005000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT6580 (32-bit entry)",
    },
    0x6582: {
        "name": "MT6582", "payload": "mt6582_payload.bin",
        "watchdog": 0x10000000, "wdt_disable_val": 0x22000000,
        "uart": 0x11006000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT6582 (32-bit quad-core)",
    },
    0x6592: {
        "name": "MT6592", "payload": "mt6592_payload.bin",
        "watchdog": 0x10000000, "wdt_disable_val": 0x22000000,
        "uart": 0x11006000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT6592 (32-bit octa-core)",
    },
    0x6595: {
        "name": "MT6595", "payload": "mt6595_payload.bin",
        "watchdog": 0x10000000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT6595 (32-bit Helio X5)",
    },
    # -----------------------------------------------------------------------
    # 64-bit transition — MT67xx
    # -----------------------------------------------------------------------
    0x6735: {
        "name": "MT6735", "payload": "mt6735_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT6735 / Helio P10 (64-bit entry)",
    },
    0x6737: {
        "name": "MT6737", "payload": "mt6737_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT6737 (64-bit budget)",
    },
    0x6750: {
        "name": "MT6750", "payload": "mt6755_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT6750 / Helio P10",
    },
    0x6752: {
        "name": "MT6752", "payload": "mt6752_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT6752 / Helio X10 (64-bit octa-core)",
    },
    0x6753: {
        "name": "MT6753", "payload": "mt6753_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT6753 (64-bit octa-core entry)",
    },
    0x6755: {
        "name": "MT6755", "payload": "mt6755_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT6755 / Helio P10",
    },
    0x6757: {
        "name": "MT6757", "payload": "mt6757_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT6757 / Helio P25 / P20",
    },
    0x6758: {
        "name": "MT6758", "payload": "mt6758_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT6758 / Helio P30",
    },
    0x6739: {
        "name": "MT6739", "payload": "mt6739_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200600,
        "storage": "emmc", "description": "MT6739 / Helio A22 (entry)",
    },
    0x6761: {
        "name": "MT6761", "payload": "mt6761_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200600,
        "storage": "emmc", "description": "MT6761 / Helio A22",
    },
    0x6762: {
        "name": "MT6762", "payload": "mt6761_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200600,
        "storage": "emmc", "description": "MT6762 / Helio G25 / P22",
    },
    0x6763: {
        "name": "MT6763", "payload": "mt6763_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200600,
        "storage": "emmc", "description": "MT6763 / Helio P23",
    },
    0x6765: {
        "name": "MT6765", "payload": "mt6765_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200600,
        "storage": "emmc", "description": "MT6765 / Helio P35 / G35",
    },
    0x6768: {
        "name": "MT6768", "payload": "mt6768_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200600,
        "storage": "emmc", "description": "MT6768 / Helio G85",
    },
    0x6769: {
        "name": "MT6769", "payload": "mt6768_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200600,
        "storage": "emmc", "description": "MT6769 / Helio G85 / G88",
    },
    0x6771: {
        "name": "MT6771", "payload": "mt6771_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201000,
        "storage": "emmc", "description": "MT6771 / Helio P60 / P70",
    },
    0x6779: {
        "name": "MT6779", "payload": "mt6779_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201000,
        "storage": "ufs",  "description": "MT6779 / Helio G80 / G85",
    },
    0x6781: {
        "name": "MT6781", "payload": "mt6781_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201000,
        "storage": "ufs",  "description": "MT6781 / Helio G96",
    },
    0x6785: {
        "name": "MT6785", "payload": "mt6785_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11003000, "payload_addr": 0x00201000,
        "storage": "ufs",  "description": "MT6785 / Helio G90T",
    },
    0x6789: {
        "name": "MT6789", "payload": "mt6785_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201000,
        "storage": "ufs",  "description": "MT6789 / Helio G99",
    },
    # -----------------------------------------------------------------------
    # Helio X flagship era (2015–2017)
    # -----------------------------------------------------------------------
    0x6795: {
        "name": "MT6795", "payload": "mt6795_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT6795 / Helio X10 (64-bit flagship)",
    },
    0x6797: {
        "name": "MT6797", "payload": "mt6797_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT6797 / Helio X20 (tri-cluster)",
    },
    0x6799: {
        "name": "MT6799", "payload": "mt6799_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201000,
        "storage": "emmc", "description": "MT6799 / Helio X30 (TSMC 10nm)",
    },
    # -----------------------------------------------------------------------
    # Dimensity 700 / 800 / 900 series
    # -----------------------------------------------------------------------
    0x6833: {
        "name": "MT6833", "payload": "mt6833_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201000,
        "storage": "ufs",  "description": "MT6833 / Dimensity 700",
    },
    0x6835: {
        "name": "MT6835", "payload": "mt6833_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201400,
        "storage": "ufs",  "description": "MT6835 / Dimensity 6100+",
    },
    0x6853: {
        "name": "MT6853", "payload": "mt6853_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201000,
        "storage": "ufs",  "description": "MT6853 / Dimensity 720",
    },
    0x6873: {
        "name": "MT6873", "payload": "mt6873_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201400,
        "storage": "ufs",  "description": "MT6873 / Dimensity 800",
    },
    0x6875: {
        "name": "MT6875", "payload": "mt6873_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201400,
        "storage": "ufs",  "description": "MT6875 / Dimensity 800U",
    },
    0x6877: {
        "name": "MT6877", "payload": "mt6877_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201000,
        "storage": "ufs",  "description": "MT6877 / Dimensity 900",
    },
    0x6879: {
        "name": "MT6879", "payload": "mt6877_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201400,
        "storage": "ufs",  "description": "MT6879 / Dimensity 920",
    },
    # -----------------------------------------------------------------------
    # Dimensity 1000 / 1200 series
    # -----------------------------------------------------------------------
    0x6885: {
        "name": "MT6885", "payload": "mt6885_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201400,
        "storage": "ufs",  "description": "MT6885 / Dimensity 1000",
    },
    0x6889: {
        "name": "MT6889", "payload": "mt6893_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201400,
        "storage": "ufs",  "description": "MT6889 / Dimensity 1000+",
    },
    0x6891: {
        "name": "MT6891", "payload": "mt6893_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201400,
        "storage": "ufs",  "description": "MT6891 / Dimensity 1100",
    },
    0x6893: {
        "name": "MT6893", "payload": "mt6893_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201400,
        "storage": "ufs",  "description": "MT6893 / Dimensity 1200",
    },
    # -----------------------------------------------------------------------
    # Dimensity 8000 / 8100 / 8200 series
    # -----------------------------------------------------------------------
    0x6895: {
        "name": "MT6895", "payload": "mt6893_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00202000,
        "storage": "ufs",  "description": "MT6895 / Dimensity 8100 / 8200",
    },
    # -----------------------------------------------------------------------
    # Dimensity 6000 series
    # -----------------------------------------------------------------------
    0x6855: {
        "name": "MT6855", "payload": "mt6833_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201400,
        "storage": "ufs",  "description": "MT6855 / Dimensity 6300",
    },
    0x6886: {
        "name": "MT6886", "payload": "mt6833_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00202000,
        "storage": "ufs",  "description": "MT6886 / Dimensity 6100+",
    },
    # -----------------------------------------------------------------------
    # Dimensity 9000 / 9200 / 9300 series
    # -----------------------------------------------------------------------
    0x6983: {
        "name": "MT6983", "payload": "mt6893_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00202000,
        "storage": "ufs",  "description": "MT6983 / Dimensity 9000",
    },
    0x6985: {
        "name": "MT6985", "payload": "mt6893_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00202000,
        "storage": "ufs",  "description": "MT6985 / Dimensity 9200",
    },
    0x6897: {
        "name": "MT6897", "payload": "mt6893_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00202000,
        "storage": "ufs",  "description": "MT6897 / Dimensity 9300",
    },
    # -----------------------------------------------------------------------
    # MediaTek Tablet / TV SoCs (MT81xx)
    # -----------------------------------------------------------------------
    0x8127: {
        "name": "MT8127", "payload": "mt8127_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11005000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT8127 / tablet SoC",
    },
    0x8163: {
        "name": "MT8163", "payload": "mt8163_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT8163 / tablet SoC",
    },
    0x8167: {
        "name": "MT8167", "payload": "mt8167_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT8167 / tablet SoC",
    },
    0x8173: {
        "name": "MT8173", "payload": "mt8173_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201000,
        "storage": "emmc", "description": "MT8173 / Helio X20 tablet",
    },
    0x8176: {
        "name": "MT8176", "payload": "mt8176_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT8176 / tablet / Chromebook SoC",
    },
    0x8168: {
        "name": "MT8168", "payload": "mt8168_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT8168 / tablet SoC (2019)",
    },
    0x8183: {
        "name": "MT8183", "payload": "mt8173_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201000,
        "storage": "emmc", "description": "MT8183 / Helio P60T (Chromebook / tablet)",
    },
    0x8195: {
        "name": "MT8195", "payload": "mt8176_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11002000, "payload_addr": 0x00201400,
        "storage": "ufs",  "description": "MT8195 / Kompanio 1200 (Chromebook)",
    },
    0x8321: {
        "name": "MT8321", "payload": "mt8163_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11005000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT8321 / budget tablet SoC",
    },
    0x8765: {
        "name": "MT8765", "payload": "mt8167_payload.bin",
        "watchdog": 0x10007000, "wdt_disable_val": 0x22000000,
        "uart": 0x11005000, "payload_addr": 0x00200000,
        "storage": "emmc", "description": "MT8765 / budget tablet SoC",
    },
}

# ===========================================================================
#  DEVICE MAP  — known phones / tablets that use each chipset
#  Used by --search to show real-world device examples.
# ===========================================================================

DEVICE_MAP: Dict[int, List[str]] = {
    0x6572: ["budget dual-core phones (2013–2014)"],
    0x6575: ["budget MT6575 phones (2012–2013)"],
    0x6580: ["Micromax Canvas 5", "Lenovo A7000 (some)", "Alcatel POP S7"],
    0x6582: ["Lenovo A2010", "Micromax Canvas HD", "Lava Iris Pro 30"],
    0x6592: ["Meizu MX3", "budget octa-core phones (2014)"],
    0x6595: ["Meizu MX4", "Helio X5 flagships"],
    0x6735: ["Lenovo K3 Note", "Coolpad Note 3", "Alcatel Idol 4"],
    0x6737: ["Lenovo K5 Plus", "Lenovo A6010 Plus", "Coolpad Cool 1"],
    0x6739: ["Xiaomi Redmi 7A", "Realme C2", "Samsung Galaxy A01"],
    0x6752: ["OnePlus One (some)", "Lenovo P70", "Meizu M1 Note",
             "Xiaomi Redmi Note 2 (some)"],
    0x6753: ["Honor 5X (some)", "Meizu M3 Note (some)", "Redmi Note 3 (non-Pro)"],
    0x6750: ["Samsung Galaxy A8 2016", "Meizu M5s", "Lenovo K5 Note (some)"],
    0x6755: ["Meizu M5 Note", "Helio P10 devices"],
    0x6757: ["Samsung Galaxy A7 2017 (some)", "Meizu M5s", "Helio P25/P20 phones"],
    0x6758: ["OPPO R11 (some)", "Helio P30 phones"],
    0x6761: ["Xiaomi Redmi A1", "Xiaomi Redmi A2", "Realme C11 2021",
             "Samsung Galaxy A01 Core", "TECNO Pop 5"],
    0x6762: ["Xiaomi Redmi 9A", "Xiaomi Redmi 9C", "POCO C3", "POCO C31",
             "Realme C12", "Realme C15", "Samsung Galaxy A02s (some)",
             "TECNO Spark 7", "Infinix Hot 10 Play"],
    0x6763: ["OPPO F5 Youth", "Vivo V7", "Helio P23 phones"],
    0x6765: ["Xiaomi Redmi 9", "Xiaomi Redmi 9 Prime", "Realme 7i",
             "Realme C21", "POCO C31 (some)", "Samsung Galaxy M21s (some)"],
    0x6768: ["Xiaomi Redmi 10C", "Xiaomi Redmi Note 10 (some)",
             "Realme 8", "Realme 8i", "Samsung Galaxy A23 (some)", "POCO M4 (some)"],
    0x6769: ["Xiaomi Redmi Note 11 (some regions)", "Realme 9i",
             "Realme C31", "POCO M4 Pro 4G"],
    0x6771: ["OPPO F7", "OPPO F9 (some)", "Vivo Y85", "Vivo V9",
             "Realme 2 Pro", "Helio P60/P70 phones"],
    0x6779: ["Xiaomi Redmi Note 9 (some)", "Realme 6i",
             "Samsung Galaxy M21 (some)", "Helio G80/G85 phones"],
    0x6781: ["Realme 8i", "Xiaomi Redmi Note 10S (some)",
             "Realme 9 4G", "Helio G96 phones"],
    0x6785: ["Xiaomi Redmi Note 8 Pro", "Realme X2", "OPPO Reno2",
             "Samsung Galaxy A51 (some)"],
    0x6789: ["Xiaomi Redmi Note 12 (Helio)", "Realme C55", "Realme C51",
             "TECNO Camon 19 Pro", "Infinix Zero 20"],
    0x6795: ["Xiaomi Mi Note", "OPPO R7 Plus", "Helio X10 flagships (2015)"],
    0x6797: ["Meizu Pro 6 Plus", "LeEco Le Pro3", "Helio X20 phones (2016)"],
    0x6799: ["Meizu Pro 7 Plus", "Helio X30 phones (2017)"],
    0x6833: ["Samsung Galaxy A22 5G", "Vivo Y72 5G", "Motorola Moto G50",
             "Realme 8 5G", "OPPO A54 5G", "Xiaomi Redmi 10 5G (some)"],
    0x6835: ["Xiaomi Redmi 12 5G (some)", "Realme 10 5G",
             "budget Dimensity 6100+ phones"],
    0x6853: ["Samsung Galaxy A42 5G", "Vivo V20 SE",
             "Xiaomi Mi 10 Lite (some)", "Realme V5", "OPPO A93 5G"],
    0x6855: ["Dimensity 6300 budget 5G phones"],
    0x6873: ["OPPO Reno4 5G", "Vivo X50", "Realme Q2 Pro",
             "Samsung Galaxy A72 (some)", "Motorola Edge 2020"],
    0x6875: ["Xiaomi Redmi Note 9 Pro 5G", "Realme 7 5G",
             "OPPO A93s 5G", "Vivo Y70s", "Samsung Galaxy F42 5G"],
    0x6877: ["OnePlus Nord CE 2", "Realme 8s 5G", "OPPO Reno6 Z",
             "Vivo T1 5G", "Samsung Galaxy A33 5G (some)"],
    0x6879: ["Xiaomi Redmi Note 12 Pro 5G (some)", "OPPO Reno8 Z",
             "Realme 9 5G Speed", "Samsung Galaxy A53 (some)"],
    0x6885: ["OPPO Find X2", "Vivo X50 Pro+", "Dimensity 1000 flagships"],
    0x6886: ["Dimensity 6100+ budget 5G phones", "Xiaomi Redmi 12C 5G (some)"],
    0x6889: ["OPPO Reno5 Pro 5G", "Vivo X60 (some)",
             "Dimensity 1000+ phones"],
    0x6891: ["Realme GT Neo", "POCO F3 GT", "Infinix Zero X Pro",
             "Samsung Galaxy M52 5G (some)"],
    0x6893: ["Xiaomi Redmi Note 10 Pro 5G", "OnePlus Nord 2 5G",
             "Realme GT Neo 2", "OPPO Reno6 Pro 5G", "Vivo V21 5G"],
    0x6895: ["Xiaomi Redmi Note 12 Pro+", "POCO X5 Pro 5G",
             "Realme GT Neo 3", "OPPO Reno8 Pro", "Vivo V25 Pro"],
    0x6897: ["OPPO Find X7", "Vivo X100",
             "Samsung Galaxy S24 (some regions — Dimensity 9300)"],
    0x6983: ["OPPO Find X5 Pro", "Vivo X80 Pro", "OnePlus 10 Pro (some)",
             "Dimensity 9000 flagships"],
    0x6985: ["OPPO Find X6 Pro", "Vivo X90 Pro+", "OnePlus 11 (some)",
             "Dimensity 9200 flagships"],
    0x8127: ["MediaTek MT8127 budget tablets"],
    0x8163: ["Amazon Fire 7 2015–2017", "Amazon Fire HD 8 2016–2018",
             "Lenovo Tab 4 8"],
    0x8167: ["Amazon Echo Show 5 (some)", "Amazon Fire 7 2017",
             "budget MT8167 tablets"],
    0x8168: ["Amazon Fire HD 8 2019", "Amazon Fire HD 10 2019",
             "budget MT8168 tablets"],
    0x8173: ["Acer Chromebook R13", "Lenovo N23 Yoga Chromebook",
             "Google Chromebook (some MT8173)"],
    0x8176: ["ASUS Chromebook Flip C101", "MediaTek tablet/Chromebook (MT8176)"],
    0x8183: ["Lenovo IdeaPad Duet Chromebook", "HP Chromebook x2 11",
             "ASUS Chromebook Detachable CM3"],
    0x8195: ["Acer Chromebook Spin 513",
             "MediaTek Kompanio 1200 Chromebooks/tablets"],
    0x8321: ["budget Android tablets (MT8321)"],
    0x8765: ["Samsung Galaxy Tab A 8.0 2019",
             "budget Samsung tablets (MT8765)"],
}


# Partitions that must NEVER be written by this tool.
# Any flash / format attempt against these is refused unconditionally.
PROTECTED_PARTITIONS: Set[str] = {
    "preloader", "preloader_a", "preloader_b",
    "lk", "lk_a", "lk_b",
    "tee1", "tee2", "tee_a", "tee_b",
    "seccfg",
    "nvram",
    "proinfo",
    "pgpt", "sgpt",   # Primary and secondary GPT — never touch
}

# Partitions requiring a second explicit wipe workflow (not just --format)
USERDATA_PARTITIONS: Set[str] = {"userdata", "metadata", "persist"}

# Default partitions dumped when --partitions is not given
AUTO_DUMP_PARTITIONS: List[str] = [
    "boot", "init_boot", "vbmeta", "recovery", "dtbo",
]

# Android sparse image magic (little-endian 0xED26FF3A)
SPARSE_MAGIC = b"\x3A\xFF\x26\xED"


def _sparse_to_raw(sparse_path: Path) -> Optional[Path]:
    """
    Built-in Android sparse image → raw image converter (W6 fix).

    Implements AOSP system/core/libsparse/sparse_format.h inline so the
    user does not need to install simg2img separately.

    Chunk types:
      0xCAC1  RAW    — literal block data follows
      0xCAC2  FILL   — repeat 4-byte fill value across chunk_sz blocks
      0xCAC3  SKIP   — don't-care region, written as zeros
      0xCAC4  CRC32  — checksum record, skipped

    Returns path to the new raw file on success, or None on failure.
    The raw file is placed alongside the sparse file with a .raw.img suffix.
    """
    _FILE_HDR  = struct.Struct("<IHHHHIIII")   # 28 bytes
    _CHUNK_HDR = struct.Struct("<HHII")         # 12 bytes
    CHUNK_RAW  = 0xCAC1
    CHUNK_FILL = 0xCAC2
    CHUNK_SKIP = 0xCAC3
    CHUNK_CRC  = 0xCAC4

    raw_path = sparse_path.with_suffix(".raw.img")
    try:
        with open(sparse_path, "rb") as fin, open(raw_path, "wb") as fout:
            hdr_data = fin.read(_FILE_HDR.size)
            if len(hdr_data) < _FILE_HDR.size:
                log_error("_sparse_to_raw: file too short to be a sparse image")
                return None

            magic, major, _minor, file_hdr_sz, chunk_hdr_sz, blk_sz, \
                _total_blks, total_chunks, _crc = _FILE_HDR.unpack(hdr_data)

            if magic != 0xED26FF3A:
                log_error("_sparse_to_raw: invalid magic — not a sparse image")
                return None
            if major != 1:
                log_error(f"_sparse_to_raw: unsupported version {major}")
                return None

            # Skip extra bytes in an extended file header
            if file_hdr_sz > _FILE_HDR.size:
                fin.read(file_hdr_sz - _FILE_HDR.size)

            for _ci in range(total_chunks):
                raw_hdr = fin.read(_CHUNK_HDR.size)
                if len(raw_hdr) < _CHUNK_HDR.size:
                    break
                chunk_type, _reserved, chunk_sz, total_sz = _CHUNK_HDR.unpack(raw_hdr)

                # Skip extra bytes in an extended chunk header
                if chunk_hdr_sz > _CHUNK_HDR.size:
                    fin.read(chunk_hdr_sz - _CHUNK_HDR.size)

                data_sz = total_sz - chunk_hdr_sz

                if chunk_type == CHUNK_RAW:
                    remaining = data_sz
                    while remaining > 0:
                        block = fin.read(min(remaining, 0x40000))
                        if not block:
                            break
                        fout.write(block)
                        remaining -= len(block)

                elif chunk_type == CHUNK_FILL:
                    fill_word = fin.read(4)
                    out_bytes  = chunk_sz * blk_sz
                    repeats    = out_bytes // 4
                    remainder  = out_bytes % 4
                    fout.write(fill_word * repeats + fill_word[:remainder])

                elif chunk_type == CHUNK_SKIP:
                    fout.write(b"\x00" * (chunk_sz * blk_sz))

                elif chunk_type == CHUNK_CRC:
                    fin.read(data_sz)   # discard CRC record

                else:
                    log_warn(
                        f"_sparse_to_raw: unknown chunk type "
                        f"0x{chunk_type:04X} — skipping"
                    )
                    fin.read(data_sz)

        log_ok(
            f"Sparse → raw: {sparse_path.name} → {raw_path.name} "
            f"({raw_path.stat().st_size // 1024} KiB)"
        )
        return raw_path

    except Exception as exc:
        log_error(f"Sparse conversion failed: {exc}")
        if DEBUG_MODE:
            traceback.print_exc()
        try:
            raw_path.unlink()
        except Exception:
            pass
        return None

# ---------------------------------------------------------------------------
# GPT constants — UEFI Specification 2.10, section 5.3
# ---------------------------------------------------------------------------
GPT_HEADER_MAGIC  = b"EFI PART"
GPT_SECTOR_SIZE   = 512
GPT_HEADER_LBA    = 1
GPT_MAX_PARTS     = 128

# ---------------------------------------------------------------------------
# USB transfer tuning
# ---------------------------------------------------------------------------
USB_TIMEOUT     = 5000    # ms
USB_CHUNK_BYTES = 0x4000  # 16 KiB per USB bulk transfer
USB_MAX_RETRIES = 5


# ===========================================================================
#  PLATFORM DETECTION
# ===========================================================================

def detect_platform() -> str:
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "darwin":
        return "macos"
    if system == "linux":
        if "com.termux" in os.environ.get("PREFIX", ""):
            return "termux"
        return "linux"
    return "unknown"


CURRENT_PLATFORM: str = detect_platform()


def check_termux_usb() -> bool:
    if CURRENT_PLATFORM != "termux":
        return True
    log_warn("Termux detected.")
    print(
        f"\n{Fore.YELLOW}{Style.BRIGHT}Termux USB OTG setup required:{Style.RESET_ALL}\n"
        f"  1. Device must support USB OTG host mode\n"
        f"  2. Install Termux:USB from F-Droid, grant USB permission\n"
        f"  3. pkg install python libusb\n"
        f"  4. sudo python androidForge.py ...\n"
    )
    if not HAS_USB:
        log_error("pyusb not installed.  Run: pip install pyusb")
        return False
    return True


# ===========================================================================
#  USB DEVICE WRAPPER
# ===========================================================================

class USBDevice:
    """
    Wraps a raw pyusb device with:
      - Bulk IN/OUT endpoint discovery
      - Thread-safe write / read with retry + stall recovery
      - Exact-length reads with hard deadline
      - USB bus reset
      - Connectivity probe
    """

    def __init__(self, dev: "usb.core.Device") -> None:
        self.dev    = dev
        self.ep_in  = None
        self.ep_out = None
        self._lock  = threading.Lock()
        self._find_endpoints()

    def _find_endpoints(self) -> None:
        for cfg in self.dev:
            for intf in cfg:
                ep_in = usb.util.find_descriptor(
                    intf,
                    custom_match=lambda e: (
                        usb.util.endpoint_direction(e.bEndpointAddress)
                        == usb.util.ENDPOINT_IN
                        and usb.util.endpoint_type(e.bmAttributes)
                        == usb.util.ENDPOINT_TYPE_BULK
                    ),
                )
                ep_out = usb.util.find_descriptor(
                    intf,
                    custom_match=lambda e: (
                        usb.util.endpoint_direction(e.bEndpointAddress)
                        == usb.util.ENDPOINT_OUT
                        and usb.util.endpoint_type(e.bmAttributes)
                        == usb.util.ENDPOINT_TYPE_BULK
                    ),
                )
                if ep_in and ep_out:
                    self.ep_in  = ep_in
                    self.ep_out = ep_out
                    log_debug(
                        f"Endpoints: IN=0x{ep_in.bEndpointAddress:02X}  "
                        f"OUT=0x{ep_out.bEndpointAddress:02X}"
                    )
                    return
        raise RuntimeError("No bulk IN/OUT endpoint pair found on this device.")

    def _clear_stall(self, ep) -> None:
        try:
            self.dev.ctrl_transfer(0x02, 0x01, 0x00, ep.bEndpointAddress, None)
            log_debug(f"Stall cleared on 0x{ep.bEndpointAddress:02X}")
        except Exception as exc:
            log_warn(f"clear_stall failed: {exc}")

    def reset(self) -> None:
        try:
            self.dev.reset()
            time.sleep(0.8)
            log_debug("USB device reset complete.")
        except Exception as exc:
            log_warn(f"USB reset: {exc}")

    def write(self, data: bytes, timeout: int = USB_TIMEOUT) -> int:
        if not self.ep_out:
            raise IOError("OUT endpoint not configured.")
        with self._lock:
            for attempt in range(1, USB_MAX_RETRIES + 1):
                try:
                    n = self.ep_out.write(data, timeout=timeout)
                    if VERBOSE_MODE:
                        log_debug(f"USB WRITE {n}B: {data[:16].hex()}")
                    return n
                except usb.core.USBError as exc:
                    log_warn(f"Write attempt {attempt}/{USB_MAX_RETRIES}: {exc}")
                    if exc.errno in (None, 32):
                        self._clear_stall(self.ep_out)
                    time.sleep(0.1 * attempt)
            raise IOError("USB write failed after max retries.")

    def read(self, length: int, timeout: int = USB_TIMEOUT) -> bytes:
        if not self.ep_in:
            raise IOError("IN endpoint not configured.")
        with self._lock:
            for attempt in range(1, USB_MAX_RETRIES + 1):
                try:
                    data = bytes(self.ep_in.read(length, timeout=timeout))
                    if VERBOSE_MODE:
                        log_debug(f"USB READ  {len(data)}B: {data[:16].hex()}")
                    return data
                except usb.core.USBError as exc:
                    log_warn(f"Read attempt {attempt}/{USB_MAX_RETRIES}: {exc}")
                    if exc.errno in (None, 32):
                        self._clear_stall(self.ep_in)
                    time.sleep(0.1 * attempt)
            raise IOError("USB read failed after max retries.")

    def read_exact(self, length: int, timeout: int = USB_TIMEOUT) -> bytes:
        """Accumulate reads until exactly `length` bytes are received."""
        buf      = b""
        deadline = time.time() + timeout / 1000.0
        while len(buf) < length:
            if time.time() > deadline:
                raise IOError(
                    f"read_exact timeout: got {len(buf)}/{length} bytes."
                )
            remaining_ms = max(100, int((deadline - time.time()) * 1000))
            chunk = self.read(length - len(buf), timeout=remaining_ms)
            if not chunk:
                raise IOError("read_exact: empty chunk (device disconnected?).")
            buf += chunk
        return buf

    def is_connected(self) -> bool:
        try:
            _ = self.dev.manufacturer
            return True
        except Exception:
            return False

    def reconnect(
        self,
        timeout_s: float = 30.0,
        brom_only: bool = True,
    ) -> bool:
        """
        Attempt to re-enumerate the USB bus and reattach to the same
        MediaTek BROM device after a reset or unexpected disconnect.

        This replaces self.dev and re-discovers endpoints so all subsequent
        write()/read() calls continue working without re-creating the object.

        Returns True if the device reappeared and endpoints were found.
        Returns False on timeout or if pyusb is unavailable.

        NOTE: Call this after USBDevice.reset() or after a watchdog reboot
        that drops the USB connection.  The device must re-enter BROM mode
        (i.e. same VID/PID) for reconnect to succeed.
        """
        if not HAS_USB:
            log_error("reconnect: pyusb not available.")
            return False

        target_pid = self.dev.idProduct
        log_info(
            f"USB reconnect: waiting for VID=0x{MTK_VID:04X} "
            f"PID=0x{target_pid:04X}  (timeout {timeout_s:.0f}s)..."
        )

        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                candidates = list(
                    usb.core.find(
                        find_all=True,
                        idVendor=MTK_VID,
                        idProduct=target_pid,
                    )
                )
            except Exception as exc:
                log_warn(f"reconnect USB scan: {exc}")
                time.sleep(1.0)
                continue

            for candidate in candidates:
                try:
                    self.dev    = candidate
                    self.ep_in  = None
                    self.ep_out = None
                    self._find_endpoints()
                    log_ok(
                        f"USB reconnect: device reattached  "
                        f"VID=0x{MTK_VID:04X}  PID=0x{target_pid:04X}"
                    )
                    return True
                except Exception as exc:
                    log_warn(f"reconnect candidate rejected: {exc}")
                    continue

            time.sleep(0.5)

        log_error(
            f"USB reconnect: device did not reappear within {timeout_s:.0f}s.\n"
            f"  Check USB cable and verify the device is still in BROM mode."
        )
        return False


# ===========================================================================
#  DEVICE DISCOVERY
# ===========================================================================

_BROM_ENTRY_GUIDE: Dict[str, str] = {
    "windows": (
        "Windows — How to enter BROM mode:\n"
        "  1. Fully power off the device (remove battery if possible)\n"
        "  2. Hold Vol-Down (or Vol-Up on some devices) BEFORE connecting USB\n"
        "  3. Connect USB cable to PC — device should appear in Device Manager\n"
        "     as 'MediaTek USB Port' or 'MT65xx Preloader'\n"
        "  4. If driver missing: install MTK USB drivers or use Zadig (WinUSB)\n"
        "  5. Some devices need 'Test Point' (TP) short — see your device schematic"
    ),
    "linux": (
        "Linux — How to enter BROM mode:\n"
        "  1. Fully power off the device\n"
        "  2. sudo python3 androidForge.py ... (root required for USB access)\n"
        "     OR: add udev rule:  SUBSYSTEM=='usb', ATTR{idVendor}=='0e8d', "
        "MODE='0666'\n"
        "  3. Hold Vol-Down, connect USB — check: lsusb | grep 0e8d\n"
        "  4. If only Preloader (0x2000) shows: device booted too far.\n"
        "     Power completely off, try again while holding Vol-Down"
    ),
    "macos": (
        "macOS — How to enter BROM mode:\n"
        "  1. Fully power off the device\n"
        "  2. Hold Vol-Down, connect USB cable\n"
        "  3. Check: system_profiler SPUSBDataType | grep -A5 MediaTek\n"
        "  4. May need to allow kernel extension in Security & Privacy settings\n"
        "  5. Run with sudo: sudo python3 androidForge.py ..."
    ),
    "termux": (
        "Termux (Android OTG) — How to enter BROM mode:\n"
        "  1. Install Termux:USB from F-Droid and grant USB permissions\n"
        "  2. Device under test must support USB OTG host mode\n"
        "  3. pkg install python libusb\n"
        "  4. Fully power off the target device\n"
        "  5. Hold Vol-Down on target device, connect OTG adapter + USB cable\n"
        "  6. sudo python3 androidForge.py ..."
    ),
    "unknown": (
        "How to enter BROM mode:\n"
        "  1. Fully power off device\n"
        "  2. Hold Vol-Down (or Vol-Up) before connecting USB\n"
        "  3. Connect USB — BROM appears as VID=0x0E8D PID=0x0003"
    ),
}


def _print_brom_guide() -> None:
    guide = _BROM_ENTRY_GUIDE.get(CURRENT_PLATFORM, _BROM_ENTRY_GUIDE["unknown"])
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}{guide}{Style.RESET_ALL}\n")


def find_mtk_device(
    timeout_s: float = 60.0,
    brom_only: bool = True,
) -> Optional["usb.core.Device"]:
    """
    Poll USB bus for a MediaTek BROM device.

    - Only PIDs in MTK_BROM_ONLY_PIDS are accepted when brom_only=True.
    - Preloader/DA detections show platform-specific BROM entry instructions.
    - Prints a live countdown every 10 seconds so the user knows it's running.
    - First non-BROM MTK detection triggers the platform entry guide once.
    """
    if not HAS_USB:
        log_error(
            "pyusb not installed.\n"
            "  Run: pip install pyusb pyserial colorama tqdm"
        )
        return None

    log_info(
        f"Waiting for MediaTek BROM device  "
        f"(timeout {timeout_s:.0f}s)..."
    )
    _print_brom_guide()

    deadline          = time.time() + timeout_s
    guide_shown       = False
    last_countdown    = time.time()
    last_warn_pid     = -1

    while time.time() < deadline:
        remaining = int(deadline - time.time())

        # Countdown every 10 seconds
        if time.time() - last_countdown >= 10:
            log_info(f"Still waiting... {remaining}s remaining")
            last_countdown = time.time()

        try:
            candidates = list(usb.core.find(find_all=True, idVendor=MTK_VID))
        except Exception as exc:
            log_warn(f"USB scan error: {exc}")
            time.sleep(1.0)
            continue

        for dev in candidates:
            pid   = dev.idProduct
            label = MTK_ALL_PIDS.get(pid, f"unknown PID=0x{pid:04X}")

            if brom_only and pid not in MTK_BROM_ONLY_PIDS:
                if pid != last_warn_pid:
                    log_warn(
                        f"MTK device detected in {label} mode "
                        f"(PID=0x{pid:04X}).\n"
                        f"  BROM mode required — this is the wrong mode.\n"
                        f"  ACTION: Disconnect USB, power the device completely OFF,\n"
                        f"          then hold Vol-Down and reconnect USB."
                    )
                    last_warn_pid = pid
                    if not guide_shown:
                        _print_brom_guide()
                        guide_shown = True
                continue

            log_ok(
                f"BROM device found!  "
                f"VID=0x{MTK_VID:04X}  PID=0x{pid:04X}  ({label})"
            )
            return dev

        time.sleep(0.5)

    log_error(
        f"No MTK BROM device found after {timeout_s:.0f}s.\n"
        f"  Check USB cable, try a different port, or verify the device\n"
        f"  is powering off fully before you connect."
    )
    return None


# ===========================================================================
#  EXPLOIT CLASSIFICATION  — chipset → exploit class / bypass method mapping
#
#  bypass_method values:
#    "kamakiri_v1"  — Helio A/G/P series (MT6739–MT6789): fault-injection via
#                     USB speed switching combined with a payload that patches
#                     the SLA verify routine in BROM SRAM.  payload_addr must
#                     be 0x00200600 for these chips.
#    "kamakiri_v2"  — Older Helio (MT6735–MT6763): same technique, payload_addr
#                     0x00200000.  Some devices also require adb OTG trigger.
#    "amonet"       — MT6580/MT6572/MT6582: A different BROM vulnerability that
#                     exploits the preloader auto-boot watchdog.
#    "dimensity"    — MT683x / MT687x / MT689x+: SLA+DAA enforced via Secure
#                     Boot Chain; no public bypass exists.  DA bypass only works
#                     with an OEM-signed DA binary or a device-specific exploit.
#    "none"         — Pre-SLA chips: no bypass needed; BROM is open.
#    "unknown"      — No confirmed public bypass available.
#
#  exploit_class values:
#    "brom_open"    — No security hardware, BROM commands work directly.
#    "kamakiri"     — MT67xx Kamakiri-class payload exploit family.
#    "amonet"       — MT6580-specific amonet exploit.
#    "sbc_locked"   — SBC enabled; requires signed preloader to proceed.
#    "unresearched" — Chip is new enough that no public exploit is documented.
# ===========================================================================

_EXPLOIT_CLASSIFICATION: Dict[int, Dict[str, str]] = {
    # ── Pre-64-bit, SLA not present ──────────────────────────────────────────
    0x6572: {"bypass_method": "amonet",       "exploit_class": "brom_open",   "sram_base": "0x00100000"},
    0x6575: {"bypass_method": "none",          "exploit_class": "brom_open",   "sram_base": "0x00100000"},
    0x6580: {"bypass_method": "amonet",        "exploit_class": "amonet",      "sram_base": "0x00100000"},
    0x6582: {"bypass_method": "amonet",        "exploit_class": "amonet",      "sram_base": "0x00100000"},
    0x6592: {"bypass_method": "none",          "exploit_class": "brom_open",   "sram_base": "0x00100000"},
    0x6595: {"bypass_method": "none",          "exploit_class": "brom_open",   "sram_base": "0x00100000"},
    # ── 64-bit transition — early Kamakiri v2 ────────────────────────────────
    0x6735: {"bypass_method": "kamakiri_v2",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x6737: {"bypass_method": "kamakiri_v2",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x6750: {"bypass_method": "kamakiri_v2",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x6752: {"bypass_method": "kamakiri_v2",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x6753: {"bypass_method": "kamakiri_v2",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x6755: {"bypass_method": "kamakiri_v2",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x6757: {"bypass_method": "kamakiri_v2",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x6758: {"bypass_method": "kamakiri_v2",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    # ── Helio A/G/P — Kamakiri v1 (payload_addr=0x00200600) ─────────────────
    0x6739: {"bypass_method": "kamakiri_v1",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x6761: {"bypass_method": "kamakiri_v1",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x6762: {"bypass_method": "kamakiri_v1",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x6763: {"bypass_method": "kamakiri_v1",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x6765: {"bypass_method": "kamakiri_v1",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},  # Oppo A16
    0x6768: {"bypass_method": "kamakiri_v1",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x6769: {"bypass_method": "kamakiri_v1",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x6771: {"bypass_method": "kamakiri_v1",   "exploit_class": "kamakiri",    "sram_base": "0x00101000"},
    0x6779: {"bypass_method": "kamakiri_v1",   "exploit_class": "kamakiri",    "sram_base": "0x00101000"},
    0x6781: {"bypass_method": "kamakiri_v1",   "exploit_class": "kamakiri",    "sram_base": "0x00101000"},
    0x6785: {"bypass_method": "kamakiri_v1",   "exploit_class": "kamakiri",    "sram_base": "0x00101000"},
    0x6789: {"bypass_method": "kamakiri_v1",   "exploit_class": "kamakiri",    "sram_base": "0x00101000"},
    # ── Helio X flagship ─────────────────────────────────────────────────────
    0x6795: {"bypass_method": "kamakiri_v2",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x6797: {"bypass_method": "kamakiri_v2",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x6799: {"bypass_method": "kamakiri_v1",   "exploit_class": "kamakiri",    "sram_base": "0x00101000"},
    # ── Dimensity 700 / 800 / 900 — DA bypass only ───────────────────────────
    0x6833: {"bypass_method": "dimensity",     "exploit_class": "sbc_locked",  "sram_base": "0x00101000"},
    0x6835: {"bypass_method": "dimensity",     "exploit_class": "sbc_locked",  "sram_base": "0x00101000"},
    0x6853: {"bypass_method": "dimensity",     "exploit_class": "sbc_locked",  "sram_base": "0x00101000"},
    0x6855: {"bypass_method": "dimensity",     "exploit_class": "sbc_locked",  "sram_base": "0x00101000"},
    0x6873: {"bypass_method": "dimensity",     "exploit_class": "sbc_locked",  "sram_base": "0x00101000"},
    0x6875: {"bypass_method": "dimensity",     "exploit_class": "sbc_locked",  "sram_base": "0x00101000"},
    0x6877: {"bypass_method": "dimensity",     "exploit_class": "sbc_locked",  "sram_base": "0x00101000"},
    0x6879: {"bypass_method": "dimensity",     "exploit_class": "sbc_locked",  "sram_base": "0x00101000"},
    0x6886: {"bypass_method": "dimensity",     "exploit_class": "sbc_locked",  "sram_base": "0x00101000"},
    # ── Dimensity 1000/1200 ───────────────────────────────────────────────────
    0x6885: {"bypass_method": "dimensity",     "exploit_class": "sbc_locked",  "sram_base": "0x00102000"},
    0x6889: {"bypass_method": "dimensity",     "exploit_class": "sbc_locked",  "sram_base": "0x00102000"},
    0x6891: {"bypass_method": "dimensity",     "exploit_class": "sbc_locked",  "sram_base": "0x00102000"},
    0x6893: {"bypass_method": "dimensity",     "exploit_class": "sbc_locked",  "sram_base": "0x00102000"},
    0x6895: {"bypass_method": "dimensity",     "exploit_class": "unresearched","sram_base": "0x00102000"},
    # ── Dimensity 9000+ ───────────────────────────────────────────────────────
    0x6983: {"bypass_method": "unknown",       "exploit_class": "unresearched","sram_base": "0x00102000"},
    0x6985: {"bypass_method": "unknown",       "exploit_class": "unresearched","sram_base": "0x00102000"},
    0x6897: {"bypass_method": "unknown",       "exploit_class": "unresearched","sram_base": "0x00102000"},
    # ── Tablet SoCs ───────────────────────────────────────────────────────────
    0x8127: {"bypass_method": "amonet",        "exploit_class": "brom_open",   "sram_base": "0x00100000"},
    0x8163: {"bypass_method": "kamakiri_v2",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x8167: {"bypass_method": "kamakiri_v2",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x8168: {"bypass_method": "kamakiri_v1",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x8173: {"bypass_method": "kamakiri_v2",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x8176: {"bypass_method": "kamakiri_v2",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x8183: {"bypass_method": "kamakiri_v1",   "exploit_class": "kamakiri",    "sram_base": "0x00101000"},
    0x8195: {"bypass_method": "dimensity",     "exploit_class": "sbc_locked",  "sram_base": "0x00102000"},
    0x8321: {"bypass_method": "kamakiri_v2",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
    0x8765: {"bypass_method": "kamakiri_v2",   "exploit_class": "kamakiri",    "sram_base": "0x00100000"},
}


def get_exploit_info(hw_code: int) -> Dict[str, str]:
    """
    Return exploit classification for the given hw_code.

    Merges _EXPLOIT_CLASSIFICATION with CHIPSET_DB so callers get a single
    dict with keys: name, bypass_method, exploit_class, sram_base.
    Returns safe "unknown" defaults if hw_code is not in either table.
    """
    base = {
        "name"          : f"0x{hw_code:04X}",
        "bypass_method" : "unknown",
        "exploit_class" : "unknown",
        "sram_base"     : "0x00100000",
    }
    chip = CHIPSET_DB.get(hw_code)
    if chip:
        base["name"] = chip.get("name", base["name"])
    info = _EXPLOIT_CLASSIFICATION.get(hw_code, {})
    base.update(info)
    return base


# ---------------------------------------------------------------------------
# ExploitProfile — per-BROM-revision payload selection record
# ---------------------------------------------------------------------------

class ExploitProfile:
    """
    Bind a specific BROM version fingerprint to a payload variant.

    Fields
    ------
    hw_code          Chipset hw_code (e.g. 0x6765 for MT6765).
    brom_prefix      First 8 hex chars of the BROM ROM fingerprint returned
                     by read_brom_version().  Empty string = match any.
    payload_name     Filename under payloads/ to use for this revision.
    payload_addr     SRAM address to load the payload at.
    notes            Human-readable description of this profile.
    """

    __slots__ = (
        "hw_code", "brom_prefix", "payload_name", "payload_addr", "notes"
    )

    def __init__(
        self,
        hw_code       : int,
        brom_prefix   : str,
        payload_name  : str,
        payload_addr  : int,
        notes         : str = "",
    ) -> None:
        self.hw_code      = hw_code
        self.brom_prefix  = brom_prefix.lower()
        self.payload_name = payload_name
        self.payload_addr = payload_addr
        self.notes        = notes

    def matches(self, hw_code: int, brom_version: str) -> bool:
        if self.hw_code != hw_code:
            return False
        if not self.brom_prefix:
            return True
        return brom_version.lower().startswith(self.brom_prefix)

    def __repr__(self) -> str:
        return (
            f"ExploitProfile(hw=0x{self.hw_code:04X}, "
            f"prefix={self.brom_prefix!r}, payload={self.payload_name!r})"
        )


class ExploitRegistry:
    """
    Registry of ExploitProfile objects.

    Usage:
        registry = build_exploit_registry()
        profile  = registry.select(hw_code=0x6765, brom_version="...")
        if profile:
            ...
    """

    def __init__(self) -> None:
        self._profiles: List[ExploitProfile] = []

    def register(self, profile: ExploitProfile) -> None:
        self._profiles.append(profile)

    def select(
        self, hw_code: int, brom_version: str = ""
    ) -> Optional[ExploitProfile]:
        """
        Return the best-matching ExploitProfile for the given hw_code and
        BROM version fingerprint.

        Matching priority (first match wins):
          1. Profiles with a non-empty brom_prefix that matches the fingerprint
             (most specific).
          2. Profiles with an empty brom_prefix (generic fallback for that
             hw_code).
          3. None — no profile registered for this chipset.
        """
        specific  : Optional[ExploitProfile] = None
        generic   : Optional[ExploitProfile] = None

        for p in self._profiles:
            if p.hw_code != hw_code:
                continue
            if p.brom_prefix and p.matches(hw_code, brom_version):
                if specific is None:
                    specific = p
            elif not p.brom_prefix and generic is None:
                generic = p

        result = specific or generic
        if result:
            log_debug(
                f"ExploitRegistry.select: hw=0x{hw_code:04X} → {result}"
            )
        else:
            log_debug(
                f"ExploitRegistry.select: no profile for hw=0x{hw_code:04X}"
            )
        return result

    def list_for(self, hw_code: int) -> List[ExploitProfile]:
        return [p for p in self._profiles if p.hw_code == hw_code]


def build_exploit_registry() -> ExploitRegistry:
    """
    Build and return the global ExploitRegistry populated with all known
    BROM-revision → payload profiles.

    Each entry is derived from public MTK BROM research.  New revisions can
    be appended without changing any other code.

    The BROM prefix is the first 8 hex chars of the fingerprint returned by
    read_brom_version() (i.e. the first 4 bytes of BROM ROM as big-endian
    hex).  An empty prefix means "any revision of this chip".
    """
    reg = ExploitRegistry()

    # ── MT6580 / amonet ──────────────────────────────────────────────────────
    reg.register(ExploitProfile(0x6580, "", "mt6580_payload.bin", 0x00200000,
                                "MT6580 amonet-style payload"))
    reg.register(ExploitProfile(0x6582, "", "mt6582_payload.bin", 0x00200000,
                                "MT6582 payload"))

    # ── MT6735 / MT6737 / MT6752 / MT6753 — Kamakiri v2 ─────────────────────
    reg.register(ExploitProfile(0x6735, "", "mt6735_payload.bin", 0x00200000,
                                "MT6735 Kamakiri v2"))
    reg.register(ExploitProfile(0x6737, "", "mt6737_payload.bin", 0x00200000,
                                "MT6737 Kamakiri v2"))
    reg.register(ExploitProfile(0x6752, "", "mt6752_payload.bin", 0x00200000,
                                "MT6752 Kamakiri v2"))
    reg.register(ExploitProfile(0x6753, "", "mt6753_payload.bin", 0x00200000,
                                "MT6753 Kamakiri v2"))
    reg.register(ExploitProfile(0x6755, "", "mt6755_payload.bin", 0x00200000,
                                "MT6755 / Helio P10 Kamakiri v2"))
    reg.register(ExploitProfile(0x6757, "", "mt6757_payload.bin", 0x00200000,
                                "MT6757 / Helio P25 Kamakiri v2"))
    reg.register(ExploitProfile(0x6758, "", "mt6758_payload.bin", 0x00200000,
                                "MT6758 / Helio P30 Kamakiri v2"))
    reg.register(ExploitProfile(0x6795, "", "mt6795_payload.bin", 0x00200000,
                                "MT6795 / Helio X10 Kamakiri v2"))
    reg.register(ExploitProfile(0x6797, "", "mt6797_payload.bin", 0x00200000,
                                "MT6797 / Helio X20 Kamakiri v2"))

    # ── MT6739 / MT6761 / MT6762 / MT6763 — Kamakiri v1 (addr=0x00200600) ───
    reg.register(ExploitProfile(0x6739, "", "mt6739_payload.bin", 0x00200600,
                                "MT6739 / Helio A22 Kamakiri v1"))
    reg.register(ExploitProfile(0x6761, "", "mt6761_payload.bin", 0x00200600,
                                "MT6761 / Helio A22 Kamakiri v1"))
    reg.register(ExploitProfile(0x6762, "", "mt6761_payload.bin", 0x00200600,
                                "MT6762 / Helio G25 Kamakiri v1 (uses mt6761 payload)"))
    reg.register(ExploitProfile(0x6763, "", "mt6763_payload.bin", 0x00200600,
                                "MT6763 / Helio P23 Kamakiri v1"))

    # ── MT6765 — Oppo A16 / Helio G35 / P35 ─────────────────────────────────
    # Two BROM revisions are known; both use 0x00200600 but different payloads
    # in some community builds.  We register the generic fallback only — a
    # specific brom_prefix entry should be added once a real device is probed.
    reg.register(ExploitProfile(0x6765, "", "mt6765_payload.bin", 0x00200600,
                                "MT6765 / Helio G35 / Oppo A16 — Kamakiri v1"))

    # ── MT6768 / MT6769 — Kamakiri v1 ────────────────────────────────────────
    reg.register(ExploitProfile(0x6768, "", "mt6768_payload.bin", 0x00200600,
                                "MT6768 / Helio G85 Kamakiri v1"))
    reg.register(ExploitProfile(0x6769, "", "mt6768_payload.bin", 0x00200600,
                                "MT6769 / Helio G85/G88 — uses mt6768 payload"))

    # ── MT6771 / MT6779 / MT6781 / MT6785 / MT6789 — Kamakiri v1 ────────────
    reg.register(ExploitProfile(0x6771, "", "mt6771_payload.bin", 0x00201000,
                                "MT6771 / Helio P60/P70 Kamakiri v1"))
    reg.register(ExploitProfile(0x6779, "", "mt6779_payload.bin", 0x00201000,
                                "MT6779 / Helio G80 Kamakiri v1"))
    reg.register(ExploitProfile(0x6781, "", "mt6781_payload.bin", 0x00201000,
                                "MT6781 / Helio G96 Kamakiri v1"))
    reg.register(ExploitProfile(0x6785, "", "mt6785_payload.bin", 0x00201000,
                                "MT6785 / Helio G90T Kamakiri v1"))
    reg.register(ExploitProfile(0x6789, "", "mt6785_payload.bin", 0x00201000,
                                "MT6789 / Helio G99 — uses mt6785 payload"))
    reg.register(ExploitProfile(0x6799, "", "mt6799_payload.bin", 0x00201000,
                                "MT6799 / Helio X30 Kamakiri v1"))

    # ── Dimensity / SBC-locked — payload upload only (bypass not guaranteed) ─
    for _hw, _name, _pay, _addr in [
        (0x6833, "MT6833/Dimensity700", "mt6833_payload.bin", 0x00201000),
        (0x6835, "MT6835/Dimensity6100+", "mt6833_payload.bin", 0x00201400),
        (0x6853, "MT6853/Dimensity720",  "mt6853_payload.bin", 0x00201000),
        (0x6873, "MT6873/Dimensity800",  "mt6873_payload.bin", 0x00201400),
        (0x6875, "MT6875/Dimensity800U", "mt6873_payload.bin", 0x00201400),
        (0x6877, "MT6877/Dimensity900",  "mt6877_payload.bin", 0x00201000),
        (0x6879, "MT6879/Dimensity920",  "mt6877_payload.bin", 0x00201400),
        (0x6885, "MT6885/Dimensity1000", "mt6885_payload.bin", 0x00201400),
        (0x6889, "MT6889/Dimensity1000+","mt6893_payload.bin", 0x00201400),
        (0x6891, "MT6891/Dimensity1100", "mt6893_payload.bin", 0x00201400),
        (0x6893, "MT6893/Dimensity1200", "mt6893_payload.bin", 0x00201400),
        (0x6895, "MT6895/Dimensity8100", "mt6893_payload.bin", 0x00202000),
    ]:
        reg.register(ExploitProfile(_hw, "", _pay, _addr,
                                    f"{_name} — DA bypass only (SBC locked)"))

    return reg


EXPLOIT_REGISTRY: ExploitRegistry = build_exploit_registry()


# ===========================================================================
#  BROM PROTOCOL ENGINE
# ===========================================================================

class BROMProtocol:
    """
    Real MediaTek BROM + DA USB protocol engine.

    Endianness rules (enforced by separate helper sets):
      BROM layer (pre-payload) — big-endian (BE), matches real BROM ROM.
      DA layer (post-payload)  — little-endian (LE), DA is ARM native LE.

    """

    # BROM command opcodes
    CMD_READ16            = 0xD0
    CMD_READ32            = 0xD1
    CMD_WRITE16           = 0xD2
    CMD_WRITE32           = 0xD4
    CMD_JUMP_DA           = 0xD5
    CMD_JUMP_BL           = 0xD6
    CMD_SEND_DA           = 0xD7
    CMD_GET_TARGET_CONFIG = 0xD8
    CMD_UART1_LOG_EN      = 0xDB
    CMD_GET_HW_SW_VER     = 0xFC
    CMD_GET_HW_CODE       = 0xFD

    # DA command opcodes (post-payload)
    DA_CMD_STORAGE_INIT = 0x70
    DA_CMD_MEM_READ     = 0x71
    DA_CMD_MEM_WRITE    = 0x72
    DA_CMD_REBOOT       = 0x73
    DA_CMD_FORMAT       = 0x74   # erase partition (if DA supports it)

    BROM_STATUS_OK = 0x0000
    DA_STATUS_OK   = 0x0000

    def __init__(self, usb_dev: USBDevice) -> None:
        self.usb          = usb_dev
        self.hw_code      = 0
        self.hw_subcode   = 0
        self.hw_version   = 0
        self.sw_version   = 0
        self.target_config: Dict[str, Any] = {}
        self.chipset      : Optional[Dict[str, Any]] = None
        self.da_loaded    = False
        self.storage_type = "unknown"
        self.block_size   = GPT_SECTOR_SIZE
        self.total_blocks = 0

    # ==================================================================
    # BROM layer helpers (big-endian)
    # ==================================================================

    def _brom_send_byte(self, v: int)  -> None: self.usb.write(bytes([v & 0xFF]))
    def _brom_send_word(self, v: int)  -> None: self.usb.write(struct.pack(">H", v & 0xFFFF))
    def _brom_send_dword(self, v: int) -> None: self.usb.write(struct.pack(">I", v & 0xFFFFFFFF))
    def _brom_recv_byte(self)  -> int: return self.usb.read_exact(1)[0]
    def _brom_recv_word(self)  -> int: return struct.unpack(">H", self.usb.read_exact(2))[0]
    def _brom_recv_dword(self) -> int: return struct.unpack(">I", self.usb.read_exact(4))[0]

    def _check_brom_status(self, context: str = "") -> None:
        """
        Read 2-byte BROM status (BE).  Only 0x0000 is accepted as success.
        0x0001 is NOT universal OK — it indicates a specific BROM error.
        """
        status = self._brom_recv_word()
        if status != self.BROM_STATUS_OK:
            ctx = f" ({context})" if context else ""
            raise RuntimeError(f"BROM error{ctx}: 0x{status:04X}")

    # ==================================================================
    # DA layer helpers (little-endian — ARM native)
    # ==================================================================

    def _da_send_byte(self, v: int)  -> None: self.usb.write(bytes([v & 0xFF]))
    def _da_send_word(self, v: int)  -> None: self.usb.write(struct.pack("<H", v & 0xFFFF))
    def _da_send_dword(self, v: int) -> None: self.usb.write(struct.pack("<I", v & 0xFFFFFFFF))
    def _da_send_qword(self, v: int) -> None: self.usb.write(struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF))
    def _da_recv_byte(self)  -> int: return self.usb.read_exact(1)[0]
    def _da_recv_word(self)  -> int: return struct.unpack("<H", self.usb.read_exact(2))[0]
    def _da_recv_dword(self) -> int: return struct.unpack("<I", self.usb.read_exact(4))[0]

    def _check_da_status(self, context: str = "") -> None:
        status = self._da_recv_word()
        if status != self.DA_STATUS_OK:
            ctx = f" ({context})" if context else ""
            raise RuntimeError(f"DA error{ctx}: 0x{status:04X}")

    # ==================================================================
    # Step 1 — BROM handshake
    # ==================================================================

    def handshake(self, retries: int = 10) -> bool:
        """
        Real MTK BROM handshake: send each byte, expect complement back.
        Resets USB between retries to recover from partial previous sessions.
        """
        log_info("Initiating BROM handshake...")

        for attempt in range(1, retries + 1):
            try:
                try:
                    self.usb.read(256, timeout=200)
                except Exception:
                    pass

                ok = True
                for tx, expected in zip(BROM_HANDSHAKE_SEND, BROM_HANDSHAKE_RECV):
                    self.usb.write(bytes([tx]), timeout=2000)
                    rx = self.usb.read_exact(1, timeout=2000)[0]
                    log_debug(
                        f"  HS TX=0x{tx:02X}  RX=0x{rx:02X}  expect=0x{expected:02X}"
                    )
                    if rx != expected:
                        log_warn(
                            f"  Byte mismatch (attempt {attempt}/{retries}): "
                            f"sent 0x{tx:02X}, got 0x{rx:02X}"
                        )
                        ok = False
                        break

                if ok:
                    log_ok("Handshake successful")
                    return True

            except IOError as exc:
                log_warn(f"Handshake attempt {attempt}/{retries}: {exc}")

            if attempt < retries:
                self.usb.reset()
                time.sleep(1.0)

        log_error("BROM handshake failed after all retries.")
        return False

    # ==================================================================
    # Step 2 — Pre-handshake: UART log enable
    # ==================================================================

    def enable_uart_log(self) -> None:
        """
        CMD_UART1_LOG_EN (0xDB) — enable UART1 BROM debug logging.

        Call this after a successful handshake and before other commands.
        Provides a stream of BROM debug output on UART1 (requires UART
        adapter physically connected to the device test pads).
        Non-fatal: failure is logged but does not abort the session.
        """
        try:
            self.usb.write(bytes([self.CMD_UART1_LOG_EN, 0x01]))
            self._check_brom_status("UART1_LOG_EN")
            log_debug("UART1 log channel enabled (BROM debug output active)")
        except Exception as exc:
            log_debug(f"UART1 log enable skipped (non-fatal): {exc}")

    # ==================================================================
    # Step 3 — Hardware identification
    # ==================================================================

    def get_hw_code(self) -> int:
        self.usb.write(bytes([self.CMD_GET_HW_CODE]))
        self.hw_code = self._brom_recv_word()
        _status      = self._brom_recv_word()   # hw_code cmd quirk — consumed
        log_debug(f"hw_code = 0x{self.hw_code:04X}")
        return self.hw_code

    def get_hw_sw_ver(self) -> Tuple[int, int, int]:
        self.usb.write(bytes([self.CMD_GET_HW_SW_VER]))
        self.hw_subcode = self._brom_recv_word()
        self.hw_version = self._brom_recv_word()
        self.sw_version = self._brom_recv_word()
        _status         = self._brom_recv_word()
        log_debug(
            f"hw_sub=0x{self.hw_subcode:04X}  "
            f"hw_ver=0x{self.hw_version:04X}  "
            f"sw_ver=0x{self.sw_version:04X}"
        )
        return self.hw_subcode, self.hw_version, self.sw_version

    def get_target_config(self) -> Dict[str, Any]:
        """
        CMD_GET_TARGET_CONFIG (0xD8) — read security feature flags.

        Response: u32 BE config_word  +  u16 BE status (discarded).

        Bit map (from public BROM research):
          bit 0: SBC  — Secure Boot Chain enforced (chain-of-trust active)
          bit 1: SLA  — Secure LA required (payload auth needed)
          bit 2: DAA  — Device Authentication Agent active
          bit 3: SLA key present in device OTP

        Knowing these flags lets the tool tell the user exactly which
        bypass technique is needed before attempting payload upload.
        """
        try:
            self.usb.write(bytes([self.CMD_GET_TARGET_CONFIG]))
            config  = self._brom_recv_dword()
            _status = self._brom_recv_word()   # quirk: consumed, not checked

            self.target_config = {
                "raw"            : f"0x{config:08X}",
                "sbc_enabled"    : bool(config & (1 << 0)),
                "sla_enabled"    : bool(config & (1 << 1)),
                "daa_enabled"    : bool(config & (1 << 2)),
                "sla_key_present": bool(config & (1 << 3)),
            }
            log_debug(f"Target config raw: 0x{config:08X}")
            return self.target_config
        except Exception as exc:
            log_warn(f"get_target_config failed (non-fatal): {exc}")
            return {}

    def identify_chipset(self) -> Optional[Dict[str, Any]]:
        """Read hw_code + hw/sw version, look up chipset DB, read target config."""
        log_info("Reading hardware identification...")

        try:
            hw_code = self.get_hw_code()
        except Exception as exc:
            log_error(f"hw_code read failed: {exc}")
            return None

        try:
            self.get_hw_sw_ver()
        except Exception as exc:
            log_warn(f"hw/sw version read (non-fatal): {exc}")

        self.get_target_config()

        log_info(
            f"hw_code=0x{hw_code:04X}  "
            f"hw_sub=0x{self.hw_subcode:04X}  "
            f"hw_ver=0x{self.hw_version:04X}  "
            f"sw_ver=0x{self.sw_version:04X}"
        )

        if self.target_config:
            flags = []
            if self.target_config.get("sbc_enabled"):   flags.append("SBC")
            if self.target_config.get("sla_enabled"):   flags.append("SLA")
            if self.target_config.get("daa_enabled"):   flags.append("DAA")
            active = ", ".join(flags) if flags else "none"
            log_info(f"Security features active: {active}")
            if self.target_config.get("sla_enabled") or self.target_config.get("daa_enabled"):
                log_warn(
                    "SLA/DAA detected — a Kamakiri-class payload is required.  "
                    "Standard unsigned payloads will be rejected by BROM."
                )

        self.chipset = CHIPSET_DB.get(hw_code)
        if self.chipset:
            log_ok(f"Chipset: {self.chipset['name']}  ({self.chipset['description']})")
        else:
            log_warn(
                f"hw_code 0x{hw_code:04X} not in database.  "
                f"Use --payload to specify a binary manually."
            )

        return self.chipset

    # ==================================================================
    # Step 4 — Watchdog disable
    # ==================================================================

    def watchdog_disable(self) -> bool:
        """
        Write WDT_MODE disable value via CMD_WRITE32 (0xD4).

        Must be called before payload upload.  If the watchdog fires
        during the multi-second upload, the device resets mid-transfer
        and the partial payload in SRAM can corrupt execution state.

        CMD_WRITE32 protocol (BROM, big-endian):
          TX: [0xD4 | addr(4 BE) | word_count(4 BE)] in one packet
          RX: status (u16 BE)
          TX: value (u32 BE)
          RX: status (u16 BE)
        """
        if not self.chipset:
            return True

        wdt_addr = self.chipset.get("watchdog")
        wdt_val  = self.chipset.get("wdt_disable_val", 0x22000000)
        if not wdt_addr:
            return True

        log_info(f"Disabling watchdog at 0x{wdt_addr:08X}...")
        try:
            header = struct.pack(">BII", self.CMD_WRITE32, wdt_addr, 1)
            self.usb.write(header)
            self._check_brom_status("WDT CMD_WRITE32 addr")
            self._brom_send_dword(wdt_val)
            self._check_brom_status("WDT CMD_WRITE32 val")
            log_ok(f"Watchdog disabled (0x{wdt_val:08X} -> 0x{wdt_addr:08X})")
            return True
        except Exception as exc:
            log_warn(f"Watchdog disable failed (non-fatal): {exc}")
            return False

    # ==================================================================
    # Step 5 — Payload load
    # ==================================================================

    def load_payload(self) -> Optional[bytes]:
        if not self.chipset:
            log_warn("No chipset identified — cannot auto-select payload.")
            return None
        name = self.chipset["payload"]
        path = PAYLOAD_DIR / name
        if not path.exists():
            log_warn(f"Payload not found locally — downloading {name} ...")
            if not _download_payload(name):
                log_error(
                    f"Auto-download failed for {name}.\n"
                    f"         Run menu option [H] Download All Payloads."
                )
                return None
        data = path.read_bytes()
        log_ok(f"Payload loaded: {name} ({len(data)} bytes)")
        return data

    # ==================================================================
    # CRC-16/CCITT helper (polynomial 0x1021, init 0x0000)
    # ==================================================================

    @staticmethod
    def _crc16_ccitt(data: bytes) -> int:
        """
        CRC-16/CCITT checksum used by MTK BROM SEND_DA handshake.

        Some SoCs (especially newer Dimensity series) require a two-way
        CRC exchange after payload upload before the BROM accepts it.
        Older SoCs (MT65xx / early MT67xx) skip the CRC step entirely.
        """
        crc = 0
        for b in data:
            crc ^= b << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc <<= 1
            crc &= 0xFFFF
        return crc

    # ==================================================================
    # Step 6 — Payload upload + execution
    # ==================================================================

    def validate_payload(self, data: bytes) -> bool:
        """
        Sanity-check a payload binary before upload to BROM.

        Checks performed
        ----------------
        1. Non-empty — a zero-byte payload cannot do anything.
        2. Minimum size (64 bytes) — absolute floor; valid BROM payloads
           contain at minimum a reset-vector stub + patch code.
        3. Maximum size (512 KiB) — BROM SRAM on all known MTK SoCs is
           ≤ 512 KiB; a larger payload can never fit and is rejected.
        4. Fingerprint log — prints first 16 bytes for debugging so the
           operator can manually verify the payload variant.

        This method is intentionally permissive on content: it does NOT
        enforce magic bytes because community payloads use varying formats.
        Execution correctness depends on the binary matching the target
        BROM revision and the address in CHIPSET_DB / ExploitProfile.

        Returns True if the payload passes all hard limits.
        """
        MIN_SIZE =    64           # bytes — absolute floor
        MAX_SIZE = 512 * 1024      # bytes — 512 KiB SRAM ceiling

        if len(data) == 0:
            log_error("Payload validation FAIL: file is empty (0 bytes).")
            return False

        if len(data) < MIN_SIZE:
            log_warn(
                f"Payload validation WARNING: payload is very small "
                f"({len(data)}B < {MIN_SIZE}B minimum).  "
                f"This is unlikely to be a valid BROM exploit payload."
            )

        if len(data) > MAX_SIZE:
            log_error(
                f"Payload validation FAIL: payload is too large "
                f"({len(data)}B > {MAX_SIZE}B).  "
                f"No known MTK SoC SRAM can hold a payload this large — "
                f"aborting to prevent BROM crash."
            )
            return False

        header_hex = data[:16].hex().upper()
        log_debug(
            f"Payload validated: {len(data)}B  header={header_hex}"
        )

        # Advisory: check whether an ExploitProfile exists for this chipset
        # and whether the payload file name matches expectations.
        if self.chipset:
            hw  = self.hw_code
            ver = getattr(self, "brom_version", "")
            profile = EXPLOIT_REGISTRY.select(hw, ver)
            if profile:
                expected = profile.payload_name
                chip_payload = self.chipset.get("payload", "")
                if (
                    expected
                    and chip_payload
                    and expected != chip_payload
                ):
                    log_warn(
                        f"Payload name mismatch: CHIPSET_DB expects "
                        f"'{chip_payload}', ExploitRegistry recommends "
                        f"'{expected}' for hw=0x{hw:04X} BROM={ver[:8]!r}.  "
                        f"Proceeding with the loaded binary."
                    )

        return True

    def send_payload(self, payload_data: bytes) -> bool:
        """
        Upload payload via CMD_SEND_DA (0xD7) and execute via CMD_JUMP_DA (0xD5).

        The entire 13-byte SEND_DA header is sent as ONE atomic USB write.
        Sending it across multiple write() calls causes the BROM to time out
        waiting for the rest of the header on most SoCs.

        Protocol (BROM, big-endian):
          TX: [0xD7 | target_addr(4) | payload_len(4) | sig_len(4)] — one write
          RX: status (u16 BE)
          TX: payload data (chunked)
          RX: status (u16 BE)
          TX: [0xD5 | target_addr(4)] — one write
          RX: status (u16 BE)
        """
        if not self.validate_payload(payload_data):
            return False

        if not self.chipset:
            log_error("Chipset not identified — cannot send payload.")
            return False

        target = self.chipset["payload_addr"]
        log_info(
            f"Uploading payload -> 0x{target:08X}  "
            f"({len(payload_data)} bytes)..."
        )

        try:
            header = struct.pack(
                ">BIII",
                self.CMD_SEND_DA,
                target,
                len(payload_data),
                0,           # sig_length = 0
            )
            self.usb.write(header)
            self._check_brom_status("SEND_DA header")

            offset = 0
            total  = len(payload_data)
            pbar   = _tqdm(
                total=total, unit="B", unit_scale=True, desc="Uploading"
            ) if HAS_TQDM else None

            while offset < total:
                chunk = payload_data[offset: offset + USB_CHUNK_BYTES]
                self.usb.write(chunk)
                offset += len(chunk)
                if pbar:
                    pbar.update(len(chunk))
                elif VERBOSE_MODE:
                    log_debug(f"  payload {offset}/{total}B")

            if pbar:
                pbar.close()

            # ── CRC / status auto-detection ──────────────────────────
            # BROM sends 2 bytes after the data transfer.  Two cases:
            #   Old SoCs (no CRC): BROM sends 0x0000 status directly.
            #   New SoCs (CRC mode): BROM sends its u16 CRC, expects
            #     ours back, then sends the real 0x0000 status.
            # Misreading the CRC as a status would raise a false error
            # and leave BROM waiting for our CRC — corrupting the session.
            _brom_word = self._brom_recv_word()
            if _brom_word == self.BROM_STATUS_OK:
                log_debug("SEND_DA: no-CRC mode (BROM ACK=0x0000)")
            else:
                # Non-zero → treat as BROM's CRC; reply with ours.
                _tool_crc = self._crc16_ccitt(payload_data)
                log_debug(
                    f"SEND_DA: CRC mode — "
                    f"BROM CRC=0x{_brom_word:04X}  "
                    f"tool CRC=0x{_tool_crc:04X}"
                )
                self._brom_send_word(_tool_crc)
                # Now read the real status after the CRC exchange.
                self._check_brom_status("SEND_DA CRC verify")

            log_info(f"Executing payload at 0x{target:08X}...")
            jump_cmd = struct.pack(">BI", self.CMD_JUMP_DA, target)
            self.usb.write(jump_cmd)
            self._check_brom_status("JUMP_DA")

            log_ok("Payload executed")
            self.da_loaded = True
            return True

        except Exception as exc:
            err = PayloadError(str(exc))
            log_error(f"Payload send/execute failed: {exc}")
            log_warn(f"Recovery hint: {err.recovery}")
            if DEBUG_MODE:
                traceback.print_exc()
            return False

    # ==================================================================
    # Step 7 — SLA / DAA bypass verification
    # ==================================================================

    def bypass_sla_daa(self) -> bool:
        """
        Verify SLA/DAA bypass by performing the post-payload DA sync.

        Real protocol:
          TX: 0x5A  (DA sync request)
          RX: 0xA5  (ACK — bypass confirmed)

        Older SoCs without SLA echo 0x5A or respond 0x00 — treated as OK.
        Any other value indicates a failed bypass and is reported honestly.

        Retry policy
        ------------
        The DA sync is retried up to MAX_SYNC_ATTEMPTS times with a
        growing delay between attempts.  This covers the race window
        where the payload needs a few milliseconds to patch BROM memory
        before it signals readiness.  Each retry resends the 0x5A byte
        to restart the handshake rather than accumulating stale bytes.
        """
        if not self.da_loaded:
            log_warn("Payload not loaded — SLA bypass skipped.")
            return False

        MAX_SYNC_ATTEMPTS = 3
        log_info("DA sync (SLA/DAA bypass verification)...")

        for attempt in range(1, MAX_SYNC_ATTEMPTS + 1):
            try:
                self.usb.write(bytes([0x5A]))
                ack = self.usb.read_exact(1, timeout=5000)[0]

                if ack == 0xA5:
                    log_ok(
                        f"SLA bypass confirmed (0xA5 ACK, attempt {attempt})"
                    )
                    return True

                if ack in (0x5A, 0x00):
                    log_ok(
                        f"DA sync ACK=0x{ack:02X} — SLA not active on this "
                        f"SoC (attempt {attempt}) — continuing."
                    )
                    return True

                log_warn(
                    f"DA sync attempt {attempt}/{MAX_SYNC_ATTEMPTS}: "
                    f"unexpected ACK=0x{ack:02X} (expected 0xA5 or 0x5A).  "
                    f"{'Retrying...' if attempt < MAX_SYNC_ATTEMPTS else 'All attempts exhausted.'}"
                )

                if attempt < MAX_SYNC_ATTEMPTS:
                    time.sleep(0.15 * attempt)

            except Exception as exc:
                log_warn(
                    f"DA sync attempt {attempt}/{MAX_SYNC_ATTEMPTS} "
                    f"exception: {exc}"
                )
                if attempt < MAX_SYNC_ATTEMPTS:
                    time.sleep(0.2 * attempt)
                else:
                    if DEBUG_MODE:
                        traceback.print_exc()

        log_error(
            f"SLA/DAA bypass verification FAILED after "
            f"{MAX_SYNC_ATTEMPTS} attempts.\n"
            f"  Possible causes:\n"
            f"    1. Payload binary does not match this BROM revision.\n"
            f"    2. Payload was loaded at the wrong SRAM address.\n"
            f"    3. SLA/DAA is enforced by hardware (eFuse) on this device.\n"
            f"    4. USB cable causing marginal signal quality — try another cable.\n"
            f"  Action: Run --device-info to fingerprint the BROM version,\n"
            f"          then select the matching payload variant."
        )
        return False

    # ==================================================================
    # BROM memory read  (CMD_READ32 / CMD_READ16)
    # ==================================================================

    def brom_read32(self, addr: int, count: int = 1) -> List[int]:
        """
        CMD_READ32 (0xD1) — read `count` 32-bit dwords from `addr`.

        Protocol (BROM, big-endian):
          TX: [0xD1 | addr(4 BE) | count(4 BE)] as one atomic packet
          RX: status (u16 BE)
          RX: data   (count * 4 bytes, BE dwords)
          RX: status (u16 BE)

        Returns a list of integer values.
        Raises BROMError on BROM error or communication failure.
        """
        try:
            cmd = struct.pack(">BII", self.CMD_READ32, addr, count)
            self.usb.write(cmd)
            self._check_brom_status(f"CMD_READ32 addr=0x{addr:08X}")
            values = []
            for _ in range(count):
                values.append(self._brom_recv_dword())
            self._check_brom_status(f"CMD_READ32 finalize")
            return values
        except BROMError:
            raise
        except Exception as exc:
            raise BROMError(
                f"CMD_READ32 failed at 0x{addr:08X}: {exc}"
            ) from exc

    def brom_read32_safe(self, addr: int) -> Optional[int]:
        """Non-raising wrapper around brom_read32. Returns None on failure."""
        try:
            return self.brom_read32(addr, 1)[0]
        except Exception as exc:
            log_debug(f"brom_read32_safe(0x{addr:08X}): {exc}")
            return None

    # ==================================================================
    # BROM memory write  (CMD_WRITE32)
    # ==================================================================

    def brom_write32(self, addr: int, value: int) -> None:
        """
        CMD_WRITE32 (0xD4) — write a single 32-bit dword to `addr`.

        Protocol (BROM, big-endian):
          TX: [0xD4 | addr(4 BE) | count(4 BE, always 1)] — one atomic write
          RX: status (u16 BE)
          TX: value (4 BE)
          RX: status (u16 BE)

        Intended for research / SRAM patching workflows.
        Use with extreme care — writing to an incorrect address will corrupt
        BROM state and require a physical power-cycle to recover.

        Raises RuntimeError on any BROM error status.
        """
        cmd = struct.pack(">BII", self.CMD_WRITE32, addr, 1)
        self.usb.write(cmd)
        self._check_brom_status(f"CMD_WRITE32 setup addr=0x{addr:08X}")
        self.usb.write(struct.pack(">I", value))
        self._check_brom_status(f"CMD_WRITE32 finalize addr=0x{addr:08X}")
        log_debug(f"brom_write32: [0x{addr:08X}] <- 0x{value:08X}")

    def brom_write32_safe(self, addr: int, value: int) -> bool:
        """
        Non-raising wrapper around brom_write32.

        Returns True on success, False on any error.
        Safe to call in fire-and-forget exploit sequences where a single
        failed write should not abort the entire operation.
        """
        try:
            self.brom_write32(addr, value)
            return True
        except Exception as exc:
            log_debug(
                f"brom_write32_safe(0x{addr:08X}, 0x{value:08X}): {exc}"
            )
            return False

    def brom_write32_range(
        self, base_addr: int, values: List[int]
    ) -> int:
        """
        Write a sequence of 32-bit dwords starting at `base_addr`.

        Each dword is written via a separate CMD_WRITE32.  Returns the
        number of dwords successfully written before any error.

        This is a convenience wrapper for patching small SRAM regions
        (e.g. zeroing an auth blob or writing a ROP gadget chain).
        """
        written = 0
        for i, val in enumerate(values):
            try:
                self.brom_write32(base_addr + i * 4, val)
                written += 1
            except Exception as exc:
                log_warn(
                    f"brom_write32_range: stopped at offset {i} "
                    f"(addr=0x{base_addr + i * 4:08X}): {exc}"
                )
                break
        log_debug(
            f"brom_write32_range: {written}/{len(values)} dwords written "
            f"from 0x{base_addr:08X}"
        )
        return written

    # ==================================================================
    # BROM version + ME-ID fingerprinting
    # ==================================================================

    def read_brom_version(self) -> str:
        """
        Read the BROM version/signature string.

        On most MTK BROM images, the first 4 bytes of BROM ROM (address
        0x00000000) contain a branch-over-data instruction, and the next
        4 bytes (0x00000004) contain the BROM build date string start.
        Reading 8 dwords (32 bytes) from 0x00000000 gives a fingerprint
        sufficient to identify the BROM revision and select the correct
        exploit variant.

        Returns a hex string of the first 32 bytes, or "unknown" on
        failure.  This method is always non-fatal.
        """
        try:
            vals  = self.brom_read32(0x00000000, 8)
            raw   = b"".join(struct.pack(">I", v) for v in vals)
            # Try to extract printable ASCII from the build string region
            try:
                text = raw[4:].decode("latin-1")
                text = "".join(c if 0x20 <= ord(c) < 0x7F else "." for c in text)
            except Exception:
                text = raw[4:].hex()
            self.brom_version = raw.hex()
            log_debug(f"BROM ROM[0:32] = {raw.hex()}")
            log_debug(f"BROM version string: {text.strip('.')!r}")
            return self.brom_version
        except Exception as exc:
            log_debug(f"read_brom_version failed (non-fatal): {exc}")
            self.brom_version = "unknown"
            return "unknown"

    def get_me_id(self) -> Optional[bytes]:
        """
        CMD_GET_ME_ID (0xE1) — read the 16-byte MediaTek Device ME-ID.

        ME-ID is a per-chip identifier burned into OTP at manufacture.
        It is used by some challenge-response auth sequences and by
        commercial unlock services to generate device-specific keys.

        Protocol (BROM, big-endian):
          TX: [0xE1]
          RX: length (u16 BE) — should be 16
          RX: me_id  (length bytes)
          RX: status (u16 BE)

        Returns 16-byte ME-ID or None on unsupported / failure.
        """
        CMD_GET_ME_ID = 0xE1
        try:
            self.usb.write(bytes([CMD_GET_ME_ID]))
            length = self._brom_recv_word()
            if length == 0 or length > 64:
                log_debug(f"get_me_id: unexpected length {length}")
                return None
            me_id  = self.usb.read_exact(length)
            _status = self._brom_recv_word()   # consume final status
            self.me_id = me_id
            log_debug(f"ME-ID ({length}B): {me_id.hex().upper()}")
            log_ok(f"ME-ID: {me_id.hex().upper()}")
            return me_id
        except Exception as exc:
            log_debug(f"get_me_id failed (non-fatal): {exc}")
            return None

    def get_socid(self) -> Optional[bytes]:
        """
        CMD_GET_SOC_ID (0xE0) — read 32-byte SoC unique identifier.

        Available on some newer MTK SoCs. Non-fatal if unsupported.
        """
        CMD_GET_SOC_ID = 0xE0
        try:
            self.usb.write(bytes([CMD_GET_SOC_ID]))
            length  = self._brom_recv_word()
            if length == 0 or length > 128:
                return None
            soc_id  = self.usb.read_exact(length)
            _status = self._brom_recv_word()
            log_debug(f"SoC-ID ({length}B): {soc_id.hex().upper()}")
            return soc_id
        except Exception as exc:
            log_debug(f"get_socid failed (non-fatal): {exc}")
            return None

    def print_brom_security_report(self) -> None:
        """
        Print a comprehensive, human-readable security analysis of the
        connected device, combining all available BROM-level information.

        Covers: hw_code, BROM version, ME-ID, target config, SoC-ID,
        recommended bypass strategy, and Oppo/Realme/Vivo-specific notes.
        """
        cfg   = self.target_config
        chip  = (self.chipset or {}).get("name", f"0x{self.hw_code:04X}")
        desc  = (self.chipset or {}).get("description", "Unknown")

        _sep = f"{Fore.CYAN}{'─' * 66}{Style.RESET_ALL}"
        print(f"\n{_sep}")
        print(
            f"  {Fore.CYAN}{Style.BRIGHT}BROM Security Analysis Report{Style.RESET_ALL}"
        )
        print(_sep)
        print(f"  Chipset     : {chip}  ({desc})")
        print(f"  hw_code     : 0x{self.hw_code:04X}")
        print(
            f"  hw_sub/ver  : "
            f"0x{self.hw_subcode:04X} / 0x{self.hw_version:04X}"
        )
        print(f"  sw_version  : 0x{self.sw_version:04X}")

        if hasattr(self, "brom_version") and self.brom_version != "unknown":
            print(f"  BROM ROM    : {self.brom_version[:32]}...")
        if hasattr(self, "me_id") and self.me_id:
            print(f"  ME-ID       : {self.me_id.hex().upper()}")

        print()
        print(f"  {Style.BRIGHT}Security flags (from CMD_GET_TARGET_CONFIG):{Style.RESET_ALL}")

        def _flag(name: str, key: str) -> None:
            val  = cfg.get(key, False)
            col  = Fore.RED if val else Fore.GREEN
            icon = "ENABLED " if val else "disabled"
            print(f"    {col}{Style.BRIGHT}{icon}{Style.RESET_ALL}  {name}")

        _flag("SBC  — Secure Boot Chain", "sbc_enabled")
        _flag("SLA  — Secure Link Auth",  "sla_enabled")
        _flag("DAA  — DA Authentication", "daa_enabled")
        print(
            f"    Raw config word: "
            f"{cfg.get('raw', 'N/A')}"
        )

        sla_on = cfg.get("sla_enabled", False)
        daa_on = cfg.get("daa_enabled", False)
        sbc_on = cfg.get("sbc_enabled", False)

        print()
        print(f"  {Style.BRIGHT}Bypass strategy recommendation:{Style.RESET_ALL}")

        if not sla_on and not daa_on:
            print(
                f"    {Fore.GREEN}{Style.BRIGHT}No auth bypass needed.{Style.RESET_ALL}\n"
                f"    Standard unsigned payload will be accepted by BROM.\n"
                f"    This device is 'open' at BROM level — easiest case."
            )
        elif sla_on and not daa_on:
            print(
                f"    {Fore.YELLOW}{Style.BRIGHT}SLA only — payload-based bypass required.{Style.RESET_ALL}\n"
                f"    A Kamakiri-class payload binary for {chip} must be used.\n"
                f"    Source: mtkclient payloads/ directory.\n"
                f"    SLA challenge can be bypassed by the payload exploit."
            )
        elif not sla_on and daa_on:
            print(
                f"    {Fore.YELLOW}{Style.BRIGHT}DAA only — authenticated DA required.{Style.RESET_ALL}\n"
                f"    The Download Agent binary must be signed by MTK.\n"
                f"    Community Kamakiri payloads may work if BROM is exploitable."
            )
        else:
            print(
                f"    {Fore.RED}{Style.BRIGHT}SLA + DAA both active — full bypass payload needed.{Style.RESET_ALL}\n"
                f"    Requires Kamakiri/Amonet-class exploit payload for {chip}.\n"
                f"    Community logs show SLA can be bypassed dynamically on this\n"
                f"    chipset — DAA bypass is embedded in the payload.\n"
                f"    Source: mtkclient / UMT / UnlockTool payloads."
            )

        if sbc_on:
            print(
                f"\n    {Fore.RED}⚠ Secure Boot Chain active — preloader and bootloader\n"
                f"      are signature-verified.  Unsigned bootloaders will be\n"
                f"      rejected even after DA bypass.{Style.RESET_ALL}"
            )

        print(_sep + "\n")

    # ==================================================================
    # Step 8 — Storage initialisation
    # ==================================================================

    def init_storage(self) -> bool:
        """
        DA_CMD_STORAGE_INIT (0x70) — initialise eMMC or UFS.

        DA protocol (little-endian):
          TX: [0x70 | storage_id] as one 2-byte packet
          RX: status    (u16 LE)
          RX: block_size(u32 LE)
          RX: total_hi  (u32 LE)
          RX: total_lo  (u32 LE)

        Auto-retries with alternate storage type if first attempt fails.
        Validates block_size sanity (must be 512/1024/2048/4096).
        """
        if not self.da_loaded:
            log_warn("DA not loaded — storage init skipped.")
            return False

        hint       = (self.chipset or {}).get("storage", "unknown")
        storage_id = 1 if hint == "ufs" else 0
        labels     = {0: "eMMC", 1: "UFS"}

        log_info(f"Initialising storage (hint: {hint})...")

        def _try(sid: int) -> bool:
            self.usb.write(bytes([self.DA_CMD_STORAGE_INIT, sid]))
            status = self._da_recv_word()
            if status != self.DA_STATUS_OK:
                log_warn(f"{labels[sid]} init rejected: 0x{status:04X}")
                return False

            self.storage_type = labels[sid].lower()
            self.block_size   = self._da_recv_dword()
            total_hi          = self._da_recv_dword()
            total_lo          = self._da_recv_dword()
            self.total_blocks = (total_hi << 32) | total_lo

            if self.block_size not in (512, 1024, 2048, 4096):
                log_warn(f"Unusual block_size={self.block_size} — defaulting to 512")
                self.block_size = 512

            if self.total_blocks == 0:
                log_error("Storage reports 0 blocks — init failed.")
                return False

            total_gb = (self.total_blocks * self.block_size) / 1024 ** 3
            log_ok(
                f"{self.storage_type.upper()} ready — "
                f"block={self.block_size}B  "
                f"capacity={self.total_blocks} blocks ({total_gb:.2f} GB)"
            )
            return True

        try:
            if _try(storage_id):
                return True
            alt = 1 - storage_id
            log_warn(f"Retrying with {labels[alt]}...")
            if _try(alt):
                return True
            log_error("Storage init failed for both eMMC and UFS.")
            return False
        except Exception as exc:
            log_error(f"Storage init exception: {exc}")
            if DEBUG_MODE:
                traceback.print_exc()
            return False

    # ==================================================================
    # Step 9 — Block I/O
    # ==================================================================

    def read_blocks(self, lba: int, count: int) -> bytes:
        """
        DA_CMD_MEM_READ (0x71) — read `count` blocks at `lba`.

        Protocol (DA, little-endian):
          TX: [0x71 | lba(8 LE) | count(4 LE)] as one packet
          RX: status (u16 LE)
          RX: data   (count * block_size bytes)
        """
        if not self.da_loaded:
            raise RuntimeError("DA not loaded — block reads unavailable.")

        cmd = struct.pack("<BQI", self.DA_CMD_MEM_READ, lba, count)
        self.usb.write(cmd)

        status = self._da_recv_word()
        if status != self.DA_STATUS_OK:
            raise RuntimeError(
                f"DA_CMD_MEM_READ rejected: LBA={lba} count={count} "
                f"status=0x{status:04X}"
            )

        return self.usb.read_exact(count * self.block_size)

    def write_blocks(self, lba: int, data: bytes) -> None:
        """
        DA_CMD_MEM_WRITE (0x72) — write `data` starting at `lba`.

        Protocol (DA, little-endian):
          TX: [0x72 | lba(8 LE) | block_count(4 LE)] as one packet
          RX: status (u16 LE)
          TX: data (chunked)
          RX: final status (u16 LE)

        block_count = len(data) // block_size  (NOT byte count).
        data must be block-aligned (enforced).

        """
        if not self.da_loaded:
            raise RuntimeError("DA not loaded — block writes unavailable.")

        if len(data) % self.block_size != 0:
            raise ValueError(
                f"write_blocks: {len(data)}B is not a multiple of "
                f"block_size {self.block_size}"
            )

        block_count = len(data) // self.block_size

        cmd = struct.pack("<BQI", self.DA_CMD_MEM_WRITE, lba, block_count)
        self.usb.write(cmd)

        status = self._da_recv_word()
        if status != self.DA_STATUS_OK:
            raise RuntimeError(
                f"DA_CMD_MEM_WRITE rejected: LBA={lba} blocks={block_count} "
                f"status=0x{status:04X}"
            )

        offset = 0
        while offset < len(data):
            chunk = data[offset: offset + USB_CHUNK_BYTES]
            self.usb.write(chunk)
            offset += len(chunk)

        final = self._da_recv_word()
        if final != self.DA_STATUS_OK:
            raise RuntimeError(
                f"DA_CMD_MEM_WRITE finalize failed: LBA={lba} "
                f"status=0x{final:04X}"
            )

    # ==================================================================
    # DA_CMD_FORMAT — on-device hardware erase  (W7 fix)
    # ==================================================================

    def format_partition_da(self, lba: int, block_count: int) -> bool:
        """
        DA_CMD_FORMAT (0x74) — request the DA to erase a partition in hardware.

        Hardware erase is orders of magnitude faster than sending zero bytes
        over USB.  This method is tried first; if the DA rejects the command
        (status != 0x0000) it returns False so the caller can fall back to
        the zero-fill path.

        Protocol (DA, little-endian):
          TX: [0x74 | lba(8 LE) | block_count(4 LE)] as one atomic packet
          RX: status (u16 LE)  — 0x0000 = OK, anything else = unsupported/error
        """
        if not self.da_loaded:
            log_debug("format_partition_da: DA not loaded — skipping")
            return False
        try:
            cmd = struct.pack("<BQI", self.DA_CMD_FORMAT, lba, block_count)
            self.usb.write(cmd)
            status = self._da_recv_word()
            if status == self.DA_STATUS_OK:
                return True
            log_debug(
                f"DA_CMD_FORMAT rejected (0x{status:04X}) — "
                f"falling back to zero-fill"
            )
            return False
        except Exception as exc:
            log_debug(f"DA_CMD_FORMAT exception: {exc} — falling back to zero-fill")
            return False

    # ==================================================================
    # Reboot command
    # ==================================================================

    def reboot(self, mode: str = "normal") -> None:
        """
        DA_CMD_REBOOT (0x73) — issue a software reboot via the loaded DA.

        After this command the device immediately resets and disconnects.
        No status response is read — the USB disconnect is the confirmation.

        Modes:
          "normal"   → boot to Android      (mode byte 0)
          "recovery" → boot to Recovery     (mode byte 1)
          "fastboot" → boot to Fastboot     (mode byte 2)
          "download" → stay in Download DA  (mode byte 3)
        """
        if not self.da_loaded:
            raise RuntimeError("DA not loaded — cannot reboot.")

        mode_map  = {"normal": 0, "recovery": 1, "fastboot": 2, "download": 3}
        mode_byte = mode_map.get(mode.lower(), 0)

        log_info(f"Sending reboot command (mode={mode})...")
        try:
            self.usb.write(struct.pack("<BB", self.DA_CMD_REBOOT, mode_byte))
            time.sleep(0.3)   # Give device time to start rebooting
        except Exception:
            pass    # Expected: device disconnects mid-write
        log_ok(f"Reboot sent — device restarting ({mode} mode)")


# ===========================================================================
#  ANDROID A/B BOOT_CTRL PARSER
# ===========================================================================

class BootCtrlParser:
    """
    Parse and modify the Android A/B boot_ctrl structure.

    Located at offset 0 of the 'misc' partition (first 56 bytes).

    Layout (AOSP hardware/interfaces/boot/1.0/, little-endian):
      0x00  char[4]   slot_suffix   — current active suffix ("\0\0\0\0" / "_a\0\0" / "_b\0\0")
      0x04  uint32    magic         — 0x42414C43 ("BALC")
      0x08  uint8     version       — 1
      0x09  uint8     nb_slot       — 2
      0x0A  uint8     recovery_tries_remaining
      0x0B  uint8     reserved
      0x0C  SlotMetadata[4]:
        each slot = 8 bytes:
          uint8 priority         (0–15, higher = preferred)
          uint8 tries_remaining  (0–7)
          uint8 successful_boot  (1 = verified good boot)
          uint8 verity_corrupted (0 = OK)
          uint8 reserved[4]
      0x2C  uint8[8]  reserved1
      0x34  uint32    crc32_le      — CRC32 over bytes [0..51]

    Total: 56 bytes.
    """

    MAGIC       = BOOT_CTRL_MAGIC
    STRUCT_SIZE = BOOT_CTRL_SIZE
    SLOT_OFFSET = 12
    SLOT_STRIDE = 8
    CRC_OFFSET  = 52

    def __init__(self, raw_misc: bytes) -> None:
        self.valid   = False
        self.raw     = bytearray(raw_misc[:self.STRUCT_SIZE])
        self.slots   : List[Dict[str, Any]] = []
        self.suffix  = ""
        self.nb_slot = 0
        self._parse()

    def _parse(self) -> None:
        if len(self.raw) < self.STRUCT_SIZE:
            log_warn(
                f"boot_ctrl: data too short "
                f"({len(self.raw)} < {self.STRUCT_SIZE})"
            )
            return

        suffix_raw = self.raw[0:4]
        magic      = struct.unpack_from("<I", self.raw, 4)[0]

        if magic != self.MAGIC:
            log_warn(
                f"boot_ctrl magic invalid: 0x{magic:08X} "
                f"(expected 0x{self.MAGIC:08X}).  "
                f"Device may not use A/B slots or misc is unformatted."
            )
            return

        stored_crc = struct.unpack_from("<I", self.raw, self.CRC_OFFSET)[0]
        calc_crc   = zlib.crc32(bytes(self.raw[:self.CRC_OFFSET])) & 0xFFFFFFFF
        if calc_crc != stored_crc:
            log_warn(
                f"boot_ctrl CRC mismatch: "
                f"stored=0x{stored_crc:08X} calc=0x{calc_crc:08X}.  "
                f"Structure may be corrupt."
            )

        version        = self.raw[8]
        self.nb_slot   = self.raw[9]
        recovery_tries = self.raw[10]

        self.suffix = suffix_raw.decode("ascii", errors="replace").rstrip("\x00")

        self.slots = []
        for i in range(min(self.nb_slot, 4)):
            off = self.SLOT_OFFSET + i * self.SLOT_STRIDE
            self.slots.append({
                "name"            : chr(ord("a") + i),
                "priority"        : self.raw[off],
                "tries_remaining" : self.raw[off + 1],
                "successful_boot" : bool(self.raw[off + 2]),
                "verity_ok"       : not bool(self.raw[off + 3]),
            })

        self.valid = True
        log_debug(
            f"boot_ctrl parsed: suffix='{self.suffix}'  "
            f"nb_slot={self.nb_slot}  version={version}  "
            f"recovery_tries={recovery_tries}"
        )

    def active_slot(self) -> str:
        """Return the name ('a' or 'b') of the highest-priority slot."""
        if not self.slots:
            return "unknown"
        best = max(self.slots, key=lambda s: s["priority"])
        return best["name"]

    def print_slots(self) -> None:
        """Print a formatted A/B slot status table."""
        print(
            f"\n{Fore.CYAN}{Style.BRIGHT}"
            f"A/B Slot Status{Style.RESET_ALL}"
        )
        print("-" * 56)
        if not self.valid:
            print(f"  {Fore.YELLOW}boot_ctrl not found / invalid — device may be A-only{Style.RESET_ALL}")
            return

        active = self.active_slot()
        print(f"  Current suffix : {self.suffix or '(none)'}")
        print(f"  Active slot    : {active}")
        print()

        header = (
            f"  {'Slot':<6} {'Priority':>8} {'Tries':>6} "
            f"{'Successful':>11} {'Verity':>7}"
        )
        print(f"{Fore.CYAN}{Style.BRIGHT}{header}{Style.RESET_ALL}")

        for slot in self.slots:
            marker = f"  {Fore.GREEN}*{Style.RESET_ALL}" if slot["name"] == active else "   "
            succ   = "YES" if slot.get("successful_boot", False) else "no"
            verity = "OK" if slot["verity_ok"] else "BAD"
            print(
                f"{marker} {slot['name']:<5} "
                f"{slot['priority']:>8} "
                f"{slot['tries_remaining']:>6} "
                f"{succ:>11} "
                f"{verity:>7}"
            )
        print()

    def make_active(self, target: str) -> bytes:
        """
        Return a modified boot_ctrl byte-string with `target` set as active.

        Sets target slot: priority=15, tries=7, successful=0 (fresh boot).
        Sets other slots: priority=0 (lowest).
        Recomputes CRC32 over first 52 bytes.

        Returns the full 56-byte struct as bytes.
        Does NOT write to device — caller must do write_blocks().
        """
        if not self.valid:
            raise RuntimeError(
                "boot_ctrl is invalid or not found — cannot switch slots."
            )

        target = target.lower()
        valid_slots = {s["name"] for s in self.slots}
        if target not in valid_slots:
            raise ValueError(
                f"Slot '{target}' not in device slots {valid_slots}"
            )

        result      = bytearray(self.raw)
        target_idx  = ord(target) - ord("a")

        for i in range(min(self.nb_slot, 4)):
            off = self.SLOT_OFFSET + i * self.SLOT_STRIDE
            if i == target_idx:
                result[off]     = 15   # max priority
                result[off + 1] = 7    # max tries
                result[off + 2] = 0    # not yet marked successful
                result[off + 3] = 0    # verity OK
            else:
                result[off]     = 0    # lowest priority
                result[off + 1] = 0
                result[off + 2] = 0
                result[off + 3] = 0

        # Update current suffix
        new_suffix = f"_{target}\x00\x00"
        result[0:4] = new_suffix[:4].encode("ascii")

        # Recompute CRC32 over bytes 0..51
        new_crc = zlib.crc32(bytes(result[:self.CRC_OFFSET])) & 0xFFFFFFFF
        struct.pack_into("<I", result, self.CRC_OFFSET, new_crc)

        log_debug(
            f"boot_ctrl modified: slot={target}  "
            f"new CRC=0x{new_crc:08X}"
        )
        return bytes(result)


# ===========================================================================
#  MTK SCATTER FILE PARSER
# ===========================================================================

class ScatterParser:
    """
    Parse MTK SP Flash Tool scatter (.txt) files.

    Scatter files are the standard firmware layout descriptor used by
    SP Flash Tool and other MTK flashing utilities.  They describe:
      - partition name
      - image file name
      - whether the partition should be downloaded
      - start address and size
      - region (EMMC_USER, EMMC_BOOT_1, etc.)

    Each partition block is delimited by 'begin:' ... 'end:' markers.
    Key-value pairs use 'key: value' or 'key = value' format.

    Example entry:
      begin:
          partition_name: boot
          file_name: boot.img
          is_download: true
          linear_start_addr: 0x6400000
          partition_size: 0x4000000
          region: EMMC_USER
      end:
    """

    def __init__(self, path: Path) -> None:
        self.path    = path
        self.entries : List[Dict[str, str]] = []
        self._parse()

    def _parse(self) -> None:
        try:
            text = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            log_error(f"Scatter file read failed: {exc}")
            return

        current : Dict[str, str] = {}
        in_block = False

        for raw_line in text.splitlines():
            line = raw_line.strip()

            if line == "begin:":
                current  = {}
                in_block = True
                continue

            if line == "end:" and in_block:
                if current:
                    self.entries.append(current)
                in_block = False
                current  = {}
                continue

            if not in_block:
                continue

            # Parse "key: value" or "key = value" (scatter uses both)
            for sep in (":", "="):
                if sep in line:
                    key, _, val = line.partition(sep)
                    key = key.strip().lstrip("#")
                    val = val.strip().strip('"')
                    if key:
                        current[key] = val
                    break

        log_ok(
            f"Scatter parsed: {len(self.entries)} entries "
            f"from {self.path.name}"
        )

    def flashable(self) -> List[Dict[str, str]]:
        """Return only entries where is_download == true and file_name is not NONE."""
        return [
            e for e in self.entries
            if e.get("is_download", "").lower() == "true"
            and e.get("file_name", "").upper() not in ("NONE", "", "NONE.BIN")
        ]

    def print_table(self) -> None:
        """Print a formatted table of all scatter entries."""
        print(
            f"\n{Fore.CYAN}{Style.BRIGHT}"
            f"{'Partition':<24} {'Download':>10} "
            f"{'Start Addr':>14} {'Size':>14} {'File'}"
            f"{Style.RESET_ALL}"
        )
        print("-" * 80)
        for e in self.entries:
            name     = e.get("partition_name", "?")
            dl       = e.get("is_download", "false")
            start    = e.get("linear_start_addr", e.get("physical_start_addr", "?"))
            size     = e.get("partition_size", "?")
            fname    = e.get("file_name", "?")
            dl_color = Fore.GREEN if dl.lower() == "true" else Fore.RED
            print(
                f"  {Fore.CYAN}{name:<22}{Style.RESET_ALL}"
                f"{dl_color}{dl:>10}{Style.RESET_ALL}"
                f"  {start:>14}"
                f"  {size:>14}"
                f"  {fname}"
            )
        print()


# ===========================================================================
#  DEVICE INFO COLLECTOR
# ===========================================================================

class DeviceInfoCollector:
    """
    Aggregates all readable device information into a single structured dict.

    Includes:
      - hw_code, hw_subcode, hw_version, sw_version
      - Chipset name and description
      - Target config security flags
      - Storage type, block_size, total_blocks, capacity_gb
      - A/B slot info (if misc partition exists)
      - Full GPT partition list
      - Timestamp
    """

    def __init__(
        self,
        brom: BROMProtocol,
        gpt: "GPTReader",
        boot_ctrl: Optional[BootCtrlParser] = None,
    ) -> None:
        self.brom       = brom
        self.gpt        = gpt
        self.boot_ctrl  = boot_ctrl

    def collect(self) -> Dict[str, Any]:
        chip     = self.brom.chipset or {}
        hw_code  = self.brom.hw_code

        # Exploit classification — merged from ExploitRegistry + classification table
        exploit  = get_exploit_info(hw_code)

        # BROM fingerprint fields captured during _setup_brom()
        brom_ver = getattr(self.brom, "brom_version", "unknown")
        me_id_raw: Optional[bytes] = getattr(self.brom, "me_id", None)
        me_id_hex = me_id_raw.hex().upper() if me_id_raw else None

        # ExploitProfile selected for this device
        ep = EXPLOIT_REGISTRY.select(hw_code, brom_ver)
        ep_info: Dict[str, Any] = {}
        if ep:
            ep_info = {
                "brom_prefix"  : ep.brom_prefix or "(any)",
                "payload_name" : ep.payload_name,
                "payload_addr" : f"0x{ep.payload_addr:08X}",
                "notes"        : ep.notes,
            }

        info: Dict[str, Any] = {
            "tool"              : "androidForge v1.5",
            "timestamp"         : time.strftime("%Y-%m-%dT%H:%M:%S"),
            "hw_code"           : f"0x{hw_code:04X}",
            "hw_subcode"        : f"0x{self.brom.hw_subcode:04X}",
            "hw_version"        : f"0x{self.brom.hw_version:04X}",
            "sw_version"        : f"0x{self.brom.sw_version:04X}",
            "brom_version"      : brom_ver,
            "me_id"             : me_id_hex,
            "chipset_name"      : chip.get("name", "unknown"),
            "chipset_desc"      : chip.get("description", "unknown"),
            "exploit_class"     : exploit.get("exploit_class", "unknown"),
            "bypass_method"     : exploit.get("bypass_method", "unknown"),
            "sram_base"         : exploit.get("sram_base", "0x00100000"),
            "exploit_profile"   : ep_info or None,
            "target_config"     : self.brom.target_config,
            "storage_type"      : self.brom.storage_type,
            "block_size"        : self.brom.block_size,
            "total_blocks"      : self.brom.total_blocks,
            "capacity_gb"       : round(
                (self.brom.total_blocks * self.brom.block_size) / 1024 ** 3, 3
            ),
        }

        if self.boot_ctrl and self.boot_ctrl.valid:
            info["ab_slots"] = {
                "active_slot" : self.boot_ctrl.active_slot(),
                "suffix"      : self.boot_ctrl.suffix,
                "slots"       : self.boot_ctrl.slots,
            }
        else:
            info["ab_slots"] = None

        info["partitions"] = [
            {
                "name"      : p.name,
                "first_lba" : p.first_lba,
                "last_lba"  : p.last_lba,
                "size_bytes": p.size_bytes,
                "flags"     : p.flags,
            }
            for p in self.gpt.partitions
        ]

        return info

    def print_summary(self, info: Dict[str, Any]) -> None:
        """Print a human-readable summary of device info."""
        print(
            f"\n{Fore.CYAN}{Style.BRIGHT}"
            f"Device Information{Style.RESET_ALL}"
        )
        print("-" * 50)

        rows = [
            ("Chipset",        info["chipset_name"]),
            ("Description",    info["chipset_desc"]),
            ("hw_code",        info["hw_code"]),
            ("hw_sub / ver",   f"{info['hw_subcode']} / {info['hw_version']}"),
            ("sw_version",     info["sw_version"]),
            ("Storage",        info["storage_type"].upper()),
            ("Block size",     f"{info['block_size']} bytes"),
            ("Total blocks",   f"{info['total_blocks']:,}"),
            ("Capacity",       f"{info['capacity_gb']} GB"),
        ]
        for label, value in rows:
            print(f"  {Fore.CYAN}{label:<18}{Style.RESET_ALL} {value}")

        cfg = info.get("target_config", {})
        if cfg:
            print()
            flags_on  = [k for k, v in cfg.items() if v is True]
            flags_off = [k for k, v in cfg.items() if v is False]
            if flags_on:
                print(
                    f"  {Fore.YELLOW}{Style.BRIGHT}Security ON: "
                    f"{Style.RESET_ALL}{Fore.YELLOW}"
                    f"{', '.join(flags_on)}{Style.RESET_ALL}"
                )
            if flags_off:
                print(
                    f"  {Fore.GREEN}Security OFF: "
                    f"{Style.RESET_ALL}{', '.join(flags_off)}"
                )

        ab = info.get("ab_slots")
        if ab:
            print(
                f"\n  A/B active slot : "
                f"{Fore.GREEN}{ab['active_slot']}{Style.RESET_ALL}  "
                f"(suffix: '{ab['suffix']}')"
            )

        print(f"\n  Partitions found: {len(info['partitions'])}")
        print()

    def save(self, path: Path, info: Dict[str, Any]) -> None:
        path.write_text(json.dumps(info, indent=2), encoding="utf-8")
        log_ok(f"Device info saved: {path}")


# ===========================================================================
#  GPT PARSER
# ===========================================================================

class Partition:
    """Immutable representation of one GPT partition entry."""

    __slots__ = ("name", "type_guid", "part_guid", "first_lba", "last_lba", "flags")

    def __init__(
        self, name: str, type_guid: bytes, part_guid: bytes,
        first_lba: int, last_lba: int, flags: int,
    ) -> None:
        self.name      = name
        self.type_guid = type_guid
        self.part_guid = part_guid
        self.first_lba = first_lba
        self.last_lba  = last_lba
        self.flags     = flags

    @property
    def size_bytes(self) -> int:
        return (self.last_lba - self.first_lba + 1) * GPT_SECTOR_SIZE

    def __repr__(self) -> str:
        return (
            f"Partition(name={self.name!r}, "
            f"lba=[{self.first_lba}..{self.last_lba}], "
            f"size={self.size_bytes // 1024}KiB)"
        )


class GPTReader:
    """
    Reads and validates the GUID Partition Table from a block device.

    Steps:
      1. Read primary GPT header at LBA 1
      2. Validate header CRC32 (92-byte header, CRC field zeroed)
      3. Validate partition entry array CRC32
      4. Fall back to backup GPT if primary fails

    Reference: UEFI Specification 2.10, section 5.3
    """

    def __init__(self, brom: BROMProtocol) -> None:
        self.brom       = brom
        self.partitions : List[Partition] = []

    @staticmethod
    def _crc32(data: bytes) -> int:
        return binascii.crc32(data) & 0xFFFFFFFF

    def _parse_header(self, sector: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse a 512-byte GPT header.

        GPT header layout (UEFI spec 5.3.2, little-endian):
          0x00  8s   Signature  "EFI PART"
          0x08   I   Revision
          0x0C   I   HeaderSize
          0x10   I   HeaderCRC32  (zeroed when computing)
          0x14   I   Reserved
          0x18   Q   MyLBA
          0x20   Q   AlternateLBA
          0x28   Q   FirstUsableLBA
          0x30   Q   LastUsableLBA
          0x38  16s  DiskGUID
          0x48   Q   PartitionEntryLBA
          0x50   I   NumPartitionEntries
          0x54   I   SizeOfPartitionEntry
          0x58   I   PartitionEntryArrayCRC32
          Total: 92 bytes
        """
        if len(sector) < 92:
            return None
        if sector[:8] != GPT_HEADER_MAGIC:
            return None

        stored_crc = struct.unpack_from("<I", sector, 16)[0]
        check_buf  = bytearray(sector[:92])
        check_buf[16:20] = b"\x00\x00\x00\x00"
        calc_crc   = self._crc32(bytes(check_buf))

        if calc_crc != stored_crc:
            log_warn(
                f"GPT header CRC: stored=0x{stored_crc:08X} "
                f"calc=0x{calc_crc:08X}"
            )
            return None

        (
            _sig, _rev, _hs, _crc_f, _res,
            my_lba, alt_lba, _fu, _lu,
            _disk_guid,
            part_entry_lba, num_parts, part_size, parts_crc,
        ) = struct.unpack_from("<8sIIIIQQQQ16sQIII", sector, 0)

        return {
            "my_lba"         : my_lba,
            "alt_lba"        : alt_lba,
            "part_entry_lba" : part_entry_lba,
            "num_parts"      : min(num_parts, GPT_MAX_PARTS),
            "part_size"      : part_size,
            "parts_crc"      : parts_crc,
        }

    def _parse_entries(
        self, raw: bytes, count: int, entry_size: int, crc_expected: int,
    ) -> List[Partition]:
        entry_data = raw[: count * entry_size]
        calc_crc   = self._crc32(entry_data)
        if calc_crc != crc_expected:
            # SAFETY: corrupted GPT entry array means we cannot trust ANY
            # partition LBA.  Writing to wrong LBAs will brick the device.
            # Abort here — the caller will fall back to backup GPT or fail.
            log_error(
                f"GPT partition entry CRC MISMATCH: "
                f"expected=0x{crc_expected:08X}  calc=0x{calc_crc:08X}.\n"
                f"  Partition table data is corrupt or was read incorrectly.\n"
                f"  Aborting this GPT copy — will try backup GPT if available.\n"
                f"  Writing to unknown LBAs can permanently brick the device."
            )
            return []

        parts: List[Partition] = []
        for i in range(count):
            off   = i * entry_size
            entry = raw[off: off + entry_size]
            if len(entry) < 128:
                continue
            type_guid = entry[0:16]
            if type_guid == b"\x00" * 16:
                continue
            part_guid = entry[16:32]
            first_lba, last_lba, flags = struct.unpack_from("<QQQ", entry, 32)
            if first_lba == 0 or last_lba < first_lba:
                continue
            name = entry[56:128].decode("utf-16-le", errors="replace").rstrip("\x00")
            parts.append(
                Partition(name, type_guid, part_guid, first_lba, last_lba, flags)
            )
        return parts

    def read(self) -> bool:
        log_info("Reading GPT partition table...")

        try:
            sector = self.brom.read_blocks(GPT_HEADER_LBA, 1)
            hdr    = self._parse_header(sector)
            if hdr:
                log_ok("Primary GPT valid")
                if self._load_entries(hdr):
                    return True
            log_warn("Primary GPT invalid — trying backup...")
        except Exception as exc:
            log_warn(f"Primary GPT read error: {exc}")

        try:
            if self.brom.total_blocks < 2:
                log_error("total_blocks not set — cannot locate backup GPT.")
                return False
            sector = self.brom.read_blocks(self.brom.total_blocks - 1, 1)
            hdr    = self._parse_header(sector)
            if hdr:
                log_ok("Backup GPT valid")
                return self._load_entries(hdr)
        except Exception as exc:
            log_error(f"Backup GPT read error: {exc}")

        log_error("GPT parsing failed.")
        return False

    def _load_entries(self, hdr: Dict[str, Any]) -> bool:
        try:
            total_bytes    = hdr["num_parts"] * hdr["part_size"]
            sectors_needed = (total_bytes + GPT_SECTOR_SIZE - 1) // GPT_SECTOR_SIZE
            raw            = self.brom.read_blocks(hdr["part_entry_lba"], sectors_needed)
            self.partitions = self._parse_entries(
                raw, hdr["num_parts"], hdr["part_size"], hdr["parts_crc"]
            )
            log_ok(f"GPT: {len(self.partitions)} partitions")
            if VERBOSE_MODE:
                for p in self.partitions:
                    log_debug(f"  {p}")
            return len(self.partitions) > 0
        except Exception as exc:
            log_error(f"GPT entry load failed: {exc}")
            if DEBUG_MODE:
                traceback.print_exc()
            return False

    def find(self, name: str) -> Optional[Partition]:
        """
        Case-insensitive partition lookup with A/B slot fallback.
        find("boot") → tries "boot", then "boot_a", then "boot_b".
        """
        nl = name.lower()
        for p in self.partitions:
            if p.name.lower() == nl:
                return p
        for suffix in ("_a", "_b"):
            for p in self.partitions:
                if p.name.lower() == nl + suffix:
                    log_debug(f"A/B fallback: '{name}' resolved to '{p.name}'")
                    return p
        return None

    def print_table(self) -> None:
        print(
            f"\n{Fore.CYAN}{Style.BRIGHT}"
            f"{'Partition':<24} {'First LBA':>12} {'Last LBA':>12} "
            f"{'Size':>10}"
            f"{Style.RESET_ALL}"
        )
        print("-" * 63)
        for p in self.partitions:
            size_kb  = p.size_bytes // 1024
            size_str = (
                f"{size_kb // 1024} MiB"
                if size_kb >= 1024
                else f"{size_kb} KiB"
            )
            print(
                f"  {Fore.CYAN}{p.name:<22}{Style.RESET_ALL}"
                f"{p.first_lba:>13} "
                f"{p.last_lba:>13} "
                f"{size_str:>10}"
            )
        print()


# ===========================================================================
#  NVRAM PARSER  — extract IMEI / WiFi / BT MAC from a raw NVRAM dump
# ===========================================================================

class NVRAMParser:
    """
    Parse a raw MTK NVRAM partition dump to extract device identities.

    Strategy A — ASCII scan:  find 15-consecutive-digit strings that pass
      the Luhn checksum (standard IMEI validation per 3GPP TS 23.003 §6.2.1).

    Strategy B — BCD semi-octet scan:  decode 8-byte sequences where pairs
      of nibbles form a valid 15-digit IMEI.  Matches the modem's internal
      binary representation.

    Strategy C — MAC scan:  locate 6-byte sequences that look like valid
      non-broadcast unicast MAC addresses and match known OEM/MTK OUI prefixes.
    """

    _MTK_OUI: Set[bytes] = {
        bytes([0x00, 0x0C, 0xE7]), bytes([0x02, 0x0C, 0xE7]),   # MediaTek ref
        bytes([0xA8, 0x9C, 0xED]), bytes([0x4C, 0xBC, 0x98]),   # Oppo/Realme
        bytes([0x48, 0x8D, 0x36]), bytes([0xB4, 0x9D, 0x0B]),   # Vivo
        bytes([0x0C, 0x1C, 0x57]), bytes([0x98, 0xFA, 0xE3]),   # Xiaomi
        bytes([0xFC, 0x3F, 0x7C]), bytes([0x64, 0xB4, 0x73]),   # Samsung MTK
    }

    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    @staticmethod
    def _luhn_ok(digits: str) -> bool:
        total = 0
        for i, ch in enumerate(reversed(digits)):
            n = int(ch)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0

    def _scan_ascii_imei(self) -> List[str]:
        found: List[str] = []
        raw_str = self.raw.decode("latin-1")
        i = 0
        while i < len(raw_str) - 15:
            chunk = raw_str[i:i + 15]
            if chunk.isdigit() and self._luhn_ok(chunk):
                found.append(chunk)
                i += 15
            else:
                i += 1
        return list(dict.fromkeys(found))

    # Cap BCD scan to avoid O(n) stall on pathologically large dumps (> 8 MiB)
    _BCD_SCAN_CAP = 8 * 1024 * 1024

    def _scan_bcd_imei(self) -> List[str]:
        found: List[str] = []
        data = self.raw[:self._BCD_SCAN_CAP]
        if len(self.raw) > self._BCD_SCAN_CAP:
            log_warn(
                f"NVRAMParser: BCD scan capped at "
                f"{self._BCD_SCAN_CAP // (1024*1024)} MiB "
                f"(file is {len(self.raw) // (1024*1024)} MiB)"
            )
        for off in range(0, len(data) - 8):
            digits: List[str] = []
            valid = True
            for byte in data[off:off + 8]:
                lo, hi = byte & 0x0F, (byte >> 4) & 0x0F
                if lo > 9:
                    valid = False
                    break
                digits.append(str(lo))
                if len(digits) < 15:
                    if hi > 9:
                        valid = False
                        break
                    digits.append(str(hi))
            if valid and len(digits) >= 15:
                candidate = "".join(digits[:15])
                if candidate != "0" * 15 and self._luhn_ok(candidate):
                    found.append(candidate)
        return list(dict.fromkeys(found))

    def _scan_mac(self) -> List[str]:
        found: List[str] = []
        for off in range(0, len(self.raw) - 6):
            chunk = self.raw[off:off + 6]
            if chunk in (b"\x00" * 6, b"\xff" * 6):
                continue
            if chunk[0] & 0x01:      # multicast — skip
                continue
            if len(set(chunk)) < 2:  # all-same bytes — skip
                continue
            found.append(":".join(f"{b:02X}" for b in chunk))
        # Prefer known OUI prefixes; fall back to first 4 any
        known = [m for m in found
                 if bytes(int(x, 16) for x in m.split(":")[:3]) in self._MTK_OUI]
        return list(dict.fromkeys(known or found[:4]))

    def parse(self) -> Dict[str, Any]:
        ascii_imei = self._scan_ascii_imei()
        bcd_imei   = self._scan_bcd_imei()
        all_imei   = list(dict.fromkeys(ascii_imei + bcd_imei))
        macs       = self._scan_mac()
        return {"raw_size": len(self.raw),
                "imei_list": all_imei[:4],
                "mac_list":  macs[:4]}

    def print_report(self) -> None:
        result = self.parse()
        print(
            f"\n  {Fore.CYAN}{Style.BRIGHT}"
            f"── NVRAM Contents ─────────────────────────────{Style.RESET_ALL}\n"
            f"  Raw size : {result['raw_size']:,} bytes"
        )
        if result["imei_list"]:
            for i, imei in enumerate(result["imei_list"], 1):
                print(f"  {Fore.GREEN}IMEI {i:<3}{Style.RESET_ALL}:"
                      f"  {Fore.WHITE}{Style.BRIGHT}{imei}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.YELLOW}No IMEI found "
                  f"(partition may be encrypted or empty){Style.RESET_ALL}")
        lbl = ["WiFi MAC", "BT   MAC", "MAC    3", "MAC    4"]
        for i, mac in enumerate(result["mac_list"][:4]):
            print(f"  {Fore.GREEN}{lbl[i]}{Style.RESET_ALL}:"
                  f"  {Fore.WHITE}{Style.BRIGHT}{mac}{Style.RESET_ALL}")
        print(f"\n  {Fore.CYAN}{'─' * 48}{Style.RESET_ALL}\n")


# ===========================================================================
#  BOOT IMAGE INSPECTOR  — parse any Android boot.img without flashing
# ===========================================================================

class BootImageInspector:
    """
    Parse Android boot image headers (v0 / v1 / v2 / v3-GKI) and report:
      • Header version, OS version, board name, page size
      • Kernel size, compression algorithm, Linux version string
      • Ramdisk size
      • Magisk injection detection (scans for magiskinit / magisk64 markers)
      • Full kernel command line

    No device connection required — works purely on a local .img file.
    """

    MAGIC    = b"ANDROID!"
    _HDR_V02 = struct.Struct("<8sIIIIIIII")   # magic … page_size (36 bytes)

    def __init__(self, path: Path) -> None:
        self.path  = path
        self._data = b""

    @staticmethod
    def _linux_version(data: bytes) -> str:
        marker = b"Linux version "
        idx = data.find(marker)
        if idx == -1:
            return "unknown"
        end = data.find(b"\x00", idx + len(marker))
        raw = data[idx + len(marker): idx + len(marker) + 80
                   if end == -1 else min(end, idx + len(marker) + 80)]
        return raw.decode("latin-1", errors="replace").strip().split()[0]

    @staticmethod
    def _compression(blob: bytes) -> str:
        if blob[:2]  == b"\x1f\x8b":             return "gzip"
        if blob[:6]  == b"\xfd7zXZ\x00":         return "xz"
        if blob[:3]  == b"BZh":                   return "bzip2"
        if blob[:4]  == b"\x02\x21\x4c\x18":     return "lz4-legacy"
        if blob[:4]  == b"\x04\x22\x4d\x18":     return "lz4-frame"
        if blob[:4]  == b"\x89\x4c\x5a\x4f":     return "lzo"
        return "raw"

    @staticmethod
    def _has_magisk(data: bytes) -> bool:
        for marker in (b"MAGISK", b"magiskinit", b"magisk64",
                       b"magisk32", b"/sbin/magisk", b"ro.magisk"):
            if marker in data:
                return True
        return False

    def inspect(self) -> Optional[Dict[str, Any]]:
        try:
            self._data = self.path.read_bytes()
        except OSError as exc:
            log_error(f"Cannot read file: {exc}")
            return None

        data = self._data
        if not data.startswith(self.MAGIC):
            log_error(f"Not a valid Android boot image (no ANDROID! magic): "
                      f"{self.path.name}")
            return None
        if len(data) < 48:
            log_error("Boot image header too short.")
            return None

        hdr_version = struct.unpack_from("<I", data, 44)[0]

        if hdr_version == 3:
            # GKI v3 layout
            kernel_size  = struct.unpack_from("<I", data, 8)[0]
            ramdisk_size = struct.unpack_from("<I", data, 12)[0]
            os_ver_raw   = struct.unpack_from("<I", data, 16)[0]
            header_size  = struct.unpack_from("<I", data, 20)[0]
            page_size    = 4096
            board_name   = ""
            cmdline      = data[44: 44 + 1536].rstrip(b"\x00").decode(
                               "latin-1", errors="replace")
            kernel_off   = header_size
        else:
            (_, kernel_size, _kaddr, ramdisk_size, _raddr,
             _second_size, _saddr, _tags, page_size) = self._HDR_V02.unpack_from(data)
            os_ver_raw   = struct.unpack_from("<I", data, 40)[0]
            board_name   = data[48: 48 + 16].rstrip(b"\x00").decode(
                               "latin-1", errors="replace")
            cmdline      = data[64: 64 + 512].rstrip(b"\x00").decode(
                               "latin-1", errors="replace")
            kernel_off   = page_size

        os_major = (os_ver_raw >> 25) & 0x7F
        os_minor = (os_ver_raw >> 18) & 0x7F
        os_patch = (os_ver_raw >> 11) & 0x7F
        os_str   = f"{os_major}.{os_minor}.{os_patch}" if os_major else "unknown"

        kernel_blob = data[kernel_off: kernel_off + kernel_size] if kernel_size else b""
        return {
            "filename"          : self.path.name,
            "file_size_kb"      : len(data) // 1024,
            "header_version"    : hdr_version,
            "os_version"        : os_str,
            "board_name"        : board_name.strip(),
            "page_size"         : page_size,
            "kernel_size_kb"    : kernel_size // 1024,
            "kernel_compression": self._compression(kernel_blob),
            "kernel_version"    : self._linux_version(data),
            "ramdisk_size_kb"   : ramdisk_size // 1024,
            "magisk_detected"   : self._has_magisk(data),
            "cmdline"           : cmdline.strip(),
        }

    def print_report(self) -> None:
        info = self.inspect()
        if not info:
            return
        mag = (f"{Fore.GREEN}{Style.BRIGHT}YES — Magisk injected{Style.RESET_ALL}"
               if info["magisk_detected"]
               else f"{Fore.WHITE}No (stock / unpatched){Style.RESET_ALL}")
        print(
            f"\n  {Fore.CYAN}{Style.BRIGHT}"
            f"── Boot Image Inspector ──────────────────────────────────{Style.RESET_ALL}\n"
            f"  File           : {Fore.WHITE}{Style.BRIGHT}{info['filename']}{Style.RESET_ALL}"
            f"  ({info['file_size_kb']} KiB)\n"
            f"  Header version : v{info['header_version']}\n"
            f"  OS version     : {info['os_version']}\n"
            f"  Board name     : {info['board_name'] or '(none)'}\n"
            f"  Page size      : {info['page_size']} bytes\n"
            f"\n  {Fore.CYAN}Kernel{Style.RESET_ALL}\n"
            f"    Size         : {info['kernel_size_kb']} KiB\n"
            f"    Compression  : {info['kernel_compression']}\n"
            f"    Version      : {Fore.YELLOW}{info['kernel_version']}{Style.RESET_ALL}\n"
            f"\n  {Fore.CYAN}Ramdisk{Style.RESET_ALL}\n"
            f"    Size         : {info['ramdisk_size_kb']} KiB\n"
            f"\n  {Fore.CYAN}Magisk{Style.RESET_ALL}          : {mag}\n"
            f"\n  {Fore.CYAN}Cmdline{Style.RESET_ALL}:\n"
            f"  {Fore.WHITE}{Style.DIM}{info['cmdline'][:120] or '(empty)'}{Style.RESET_ALL}\n"
            f"\n  {Fore.CYAN}{'─' * 58}{Style.RESET_ALL}\n"
        )


# ===========================================================================
#  OTA PAYLOAD EXTRACTOR  — extract partition images from payload.bin
# ===========================================================================

class OTAPayloadExtractor:
    """
    Extract individual partition .img files from an Android OTA payload.bin.

    Accepts:
      • A bare payload.bin file
      • A zipped OTA package (.zip) — payload.bin is found automatically

    Protobuf DeltaArchiveManifest is parsed with a minimal hand-written wire
    decoder (no proto compiler required).  REPLACE, REPLACE_BZ, and REPLACE_XZ
    operations are extracted.  Delta (BSDIFF/IMGDIFF) operations are listed but
    skipped (they require the base partition image to reconstruct).

    Reference: AOSP system/update_engine/update_metadata.proto
    """

    _MAGIC = b"CrAU"

    # InstallOperation types extractable without a base image
    _REPLACE    = 0
    _REPLACE_BZ = 1
    _REPLACE_XZ = 8
    _ZERO       = 6

    def __init__(self, source: Path, out_dir: Path) -> None:
        self.source   = source
        self.out_dir  = out_dir
        self._payload = b""

    def _load(self) -> bool:
        import zipfile
        if self.source.suffix.lower() == ".zip":
            try:
                with zipfile.ZipFile(self.source) as zf:
                    if "payload.bin" not in zf.namelist():
                        log_error("No payload.bin inside the OTA zip.")
                        return False
                    log_info("Extracting payload.bin from OTA zip…")
                    self._payload = zf.read("payload.bin")
            except zipfile.BadZipFile as exc:
                log_error(f"Bad zip file: {exc}")
                return False
        else:
            try:
                self._payload = self.source.read_bytes()
            except OSError as exc:
                log_error(f"Cannot read payload: {exc}")
                return False
        return True

    @staticmethod
    def _varint(data: bytes, pos: int):
        """Read a protobuf varint.  Returns (value, new_pos)."""
        result = shift = 0
        while pos < len(data):
            b = data[pos]; pos += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        return result, pos

    def _parse_install_op(self, data: bytes) -> Dict[str, int]:
        op_type = data_offset = data_length = 0
        pos = 0
        while pos < len(data):
            tag, pos = self._varint(data, pos)
            fld, wt  = tag >> 3, tag & 0x07
            if wt == 0:
                val, pos = self._varint(data, pos)
                if fld == 1: op_type     = val
            elif wt == 1:
                val = struct.unpack_from("<Q", data, pos)[0]; pos += 8
                if fld == 4: data_offset = val
                if fld == 5: data_length = val
            elif wt == 2:
                ln, pos = self._varint(data, pos); pos += ln
            elif wt == 5:
                pos += 4
            else:
                break
        return {"type": op_type, "offset": data_offset, "length": data_length}

    def _parse_partition_update(self, data: bytes) -> Optional[Dict[str, Any]]:
        name = None; ops = []; pos = 0
        while pos < len(data):
            tag, pos = self._varint(data, pos)
            fld, wt  = tag >> 3, tag & 0x07
            if wt == 0:
                _, pos = self._varint(data, pos)
            elif wt == 1:
                pos += 8
            elif wt == 2:
                ln, pos = self._varint(data, pos)
                blob = data[pos:pos + ln]; pos += ln
                if fld == 1: name = blob.decode("utf-8", errors="replace")
                if fld == 3: ops.append(self._parse_install_op(blob))
            elif wt == 5:
                pos += 4
            else:
                break
        return {"name": name, "operations": ops} if name else None

    def _parse_manifest(self, manifest: bytes) -> List[Dict[str, Any]]:
        parts = []; pos = 0
        while pos < len(manifest):
            tag, pos = self._varint(manifest, pos)
            fld, wt  = tag >> 3, tag & 0x07
            if wt == 0:
                _, pos = self._varint(manifest, pos)
            elif wt == 1:
                pos += 8
            elif wt == 2:
                ln, pos = self._varint(manifest, pos)
                blob = manifest[pos:pos + ln]; pos += ln
                if fld == 13:   # partitions field in DeltaArchiveManifest
                    p = self._parse_partition_update(blob)
                    if p: parts.append(p)
            elif wt == 5:
                pos += 4
            else:
                break
        return parts

    def extract(self) -> int:
        import bz2, lzma
        if not self._load():
            return 0
        d = self._payload
        if not d.startswith(self._MAGIC):
            log_error("Not a valid payload.bin (missing CrAU magic).")
            return 0
        if len(d) < 24:
            log_error("payload.bin header too short.")
            return 0

        version      = struct.unpack_from(">Q", d,  4)[0]
        manifest_len = struct.unpack_from(">Q", d, 12)[0]
        meta_sig_len = struct.unpack_from(">I", d, 20)[0]
        blob_start   = 24 + manifest_len + meta_sig_len

        log_info(f"payload.bin v{version} — manifest {manifest_len}B "
                 f"blob@0x{blob_start:X}")

        parts = self._parse_manifest(d[24:24 + manifest_len])
        if not parts:
            log_error("No partitions found — may be an unsupported format.")
            return 0

        log_info(f"Found {len(parts)} partition(s) in OTA manifest.")
        self.out_dir.mkdir(parents=True, exist_ok=True)

        TYPE_NAMES = {0:"REPLACE", 1:"REPLACE_BZ", 2:"BSDIFF",
                      3:"IMGDIFF", 6:"ZERO", 7:"DISCARD", 8:"REPLACE_XZ"}
        done = 0
        for part in parts:
            name = part["name"]
            ops  = part["operations"]
            has_delta = any(o["type"] in {2, 3} for o in ops)
            if has_delta:
                log_warn(f"  '{name}': delta OTA — skipped (needs base image)")
                continue
            if not ops:
                log_warn(f"  '{name}': no operations — skipped")
                continue
            # SEC-1: Sanitize partition name — block path traversal.
            # The name comes from untrusted OTA protobuf data; a crafted
            # OTA could set name="../../etc/cron.d/evil" to write outside
            # the output directory.  Strip all non-safe characters.
            safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', Path(name).name)[:64]
            if not safe_name or safe_name.startswith('.'):
                log_warn(f"  Skipping partition with unsafe name: {name!r}")
                continue

            out_path = self.out_dir / f"{safe_name}.img"

            # SEC-2: Ensure resolved path stays inside out_dir (symlink-safe).
            try:
                out_path.resolve().relative_to(self.out_dir.resolve())
            except ValueError:
                log_warn(f"  '{name}': resolved path escapes output dir — skipped")
                continue

            # Decompression bomb limit: 2 GiB per partition image.
            _MAX_DECOMP = 2 * 1024 * 1024 * 1024

            try:
                with open(out_path, "wb") as fout:
                    for op in ops:
                        t, off, ln = op["type"], op["offset"], op["length"]
                        if ln == 0:
                            continue

                        # SEC-3: Bounds check before slicing untrusted offsets.
                        if off < 0 or ln < 0 or blob_start + off + ln > len(d):
                            log_error(
                                f"  '{name}': op offset/length out of range "
                                f"(off={off}, len={ln}, blob_start=0x{blob_start:X}, "
                                f"payload={len(d)}) — malformed OTA"
                            )
                            break

                        raw = d[blob_start + off: blob_start + off + ln]

                        if t == self._REPLACE:
                            fout.write(raw)
                        elif t == self._REPLACE_BZ:
                            # SEC-4: Decompression bomb protection via max_length.
                            _dec = bz2.BZ2Decompressor()
                            _out = _dec.decompress(raw, max_length=_MAX_DECOMP)
                            if not _dec.eof:
                                raise StorageError(
                                    f"bzip2 decompressed data exceeds "
                                    f"{_MAX_DECOMP // 1024**2} MiB limit — "
                                    f"possible decompression bomb"
                                )
                            fout.write(_out)
                        elif t == self._REPLACE_XZ:
                            # SEC-4: Same protection for xz/lzma.
                            _dec = lzma.LZMADecompressor()
                            _out = _dec.decompress(raw, max_length=_MAX_DECOMP)
                            if not _dec.eof:
                                raise StorageError(
                                    f"xz decompressed data exceeds "
                                    f"{_MAX_DECOMP // 1024**2} MiB limit — "
                                    f"possible decompression bomb"
                                )
                            fout.write(_out)
                        elif t == self._ZERO:
                            pass   # sparse zero — size from GPT
                        else:
                            log_warn(f"    op {TYPE_NAMES.get(t, t)} skipped")

                sz = out_path.stat().st_size // 1024
                log_ok(f"  '{name}' → {out_path.name}  ({sz} KiB)")
                done += 1
            except StorageError as exc:
                log_error(f"  '{name}': {exc}")
                log_warn(f"  Recovery: {exc.recovery}")
                try: out_path.unlink(missing_ok=True)
                except OSError: pass
            except Exception as exc:
                log_error(f"  '{name}': {exc}")

        log_ok(f"OTA extraction complete: {done}/{len(parts)} → {self.out_dir}")
        return done


# ===========================================================================
#  PARTITION DUMPER
# ===========================================================================

class PartitionDumper:
    """
    Dumps partitions from device to local image files.

    read_partition() returns None on ANY partial read error — partial data
    is never written to disk (a short dump flashed back bricks the device).
    dump() validates received byte count == GPT partition size before write.
    """

    def __init__(
        self, brom: BROMProtocol, gpt: GPTReader, out_dir: Path,
    ) -> None:
        self.brom    = brom
        self.gpt     = gpt
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)

        # W3 — Load existing manifest to support dump-all resume.
        # If a previous session was interrupted, partitions already present
        # at the correct size are skipped automatically by dump().
        manifest_path = self.out_dir / "backup_manifest.json"
        if manifest_path.exists():
            try:
                self.manifest: Dict[str, Any] = json.loads(
                    manifest_path.read_text(encoding="utf-8")
                )
                log_info(
                    f"Resuming from existing manifest — "
                    f"{len(self.manifest)} partition(s) already completed."
                )
            except Exception as _exc:
                log_warn(f"Could not load manifest ({_exc}) — starting fresh.")
                self.manifest = {}
        else:
            self.manifest = {}

    def read_partition(self, name: str) -> Optional[bytes]:
        part = self.gpt.find(name)
        if not part:
            log_warn(f"Partition '{name}' not found in GPT.")
            return None

        total_blocks  = part.last_lba - part.first_lba + 1
        chunk_blocks  = max(1, USB_CHUNK_BYTES // self.brom.block_size)
        expected_size = total_blocks * self.brom.block_size

        log_info(
            f"Reading '{name}'  "
            f"({expected_size // 1024} KiB, "
            f"LBA {part.first_lba}..{part.last_lba})"
        )

        buf           = bytearray()
        offset_blocks = 0
        t_start       = time.time()
        read_error    = False

        pbar = _tqdm(
            total=expected_size, unit="B", unit_scale=True,
            desc=f"  {name}", leave=False,
        ) if HAS_TQDM else None

        while offset_blocks < total_blocks:
            to_read = min(chunk_blocks, total_blocks - offset_blocks)
            try:
                chunk = self.brom.read_blocks(
                    part.first_lba + offset_blocks, to_read
                )
            except Exception as exc:
                log_error(
                    f"Read error at LBA {part.first_lba + offset_blocks}: {exc}"
                )
                read_error = True
                break

            buf.extend(chunk)
            offset_blocks += to_read
            if pbar:
                pbar.update(len(chunk))
            elif VERBOSE_MODE:
                log_debug(
                    f"  '{name}': {len(buf)}/{expected_size}B "
                    f"({100 * len(buf) / expected_size:.1f}%)"
                )

        if pbar:
            pbar.close()

        if read_error:
            log_error(
                f"'{name}': read aborted at {len(buf)}/{expected_size}B — "
                f"partial data discarded (never written to disk)."
            )
            return None

        elapsed   = max(time.time() - t_start, 1e-3)
        speed_mbs = (len(buf) / 1024 ** 2) / elapsed
        log_debug(f"  '{name}': {len(buf)}B in {elapsed:.2f}s ({speed_mbs:.2f} MB/s)")

        return bytes(buf)

    def dump(self, name: str) -> bool:
        part = self.gpt.find(name)
        if not part:
            log_warn(f"'{name}' not in GPT — skipping.")
            return False

        out     = self.out_dir / f"{name}.img"
        partial = self.out_dir / f"{name}.partial"

        # Use the DA block_size (not the GPT_SECTOR_SIZE constant) so that
        # UFS devices with 4 096-byte native sectors get the correct byte count.
        # Using the wrong size here would cause valid dumps to be discarded,
        # and a truncated dump flashed back would brick the device.
        total_blocks  = part.last_lba - part.first_lba + 1
        expect_bytes  = total_blocks * self.brom.block_size
        chunk_blocks  = max(1, USB_CHUNK_BYTES // self.brom.block_size)

        # --- Already completed ---
        if out.exists() and out.stat().st_size == expect_bytes:
            log_ok(f"'{name}' already at correct size — skipping.")
            self._record_manifest(name, out, part)
            return True

        # --- W3: sector-level resume via .partial temp file ---
        resume_blocks = 0
        if partial.exists():
            partial_size = partial.stat().st_size
            if partial_size > 0 and partial_size % self.brom.block_size == 0:
                resume_blocks = partial_size // self.brom.block_size
                log_info(
                    f"'{name}': resuming from block {resume_blocks}/{total_blocks} "
                    f"({partial_size // 1024} KiB already on disk)."
                )
            else:
                log_warn(
                    f"'{name}': .partial size {partial_size}B not block-aligned — "
                    f"discarding and restarting."
                )
                partial.unlink(missing_ok=True)
                resume_blocks = 0

        log_info(f"Dumping {name}.img  ({expect_bytes // 1024} KiB)…")

        t_start       = time.time()
        offset_blocks = resume_blocks
        read_error    = False

        pbar = _tqdm(
            total=expect_bytes, unit="B", unit_scale=True,
            desc=f"  {name}", leave=False,
            initial=resume_blocks * self.brom.block_size,
        ) if HAS_TQDM else None

        # Open in append mode so a resume continues where it left off.
        fmode = "ab" if resume_blocks else "wb"
        try:
            with open(partial, fmode) as fh:
                while offset_blocks < total_blocks:
                    to_read = min(chunk_blocks, total_blocks - offset_blocks)
                    try:
                        chunk = self.brom.read_blocks(
                            part.first_lba + offset_blocks, to_read
                        )
                    except Exception as exc:
                        log_error(
                            f"Read error at LBA {part.first_lba + offset_blocks}: {exc}"
                        )
                        read_error = True
                        break

                    fh.write(chunk)
                    fh.flush()   # W3: push to kernel buffer after each chunk
                    offset_blocks += to_read

                    if pbar:
                        pbar.update(len(chunk))
                    elif VERBOSE_MODE:
                        written = offset_blocks * self.brom.block_size
                        log_debug(
                            f"  '{name}': {written}/{expect_bytes}B "
                            f"({100 * written / expect_bytes:.1f}%)"
                        )
        except OSError as exc:
            log_error(f"File I/O error during dump of '{name}': {exc}")
            read_error = True

        if pbar:
            pbar.close()

        if read_error:
            log_error(
                f"'{name}': read aborted — partial data preserved in "
                f"'{partial.name}' for resume on next run."
            )
            return False

        # --- Integrity check before atomic rename ---
        actual = partial.stat().st_size
        if actual != expect_bytes:
            log_error(
                f"DUMP INTEGRITY FAIL '{name}': "
                f"got {actual}B, expected {expect_bytes}B — "
                f".partial file left for inspection."
            )
            return False

        partial.rename(out)
        elapsed   = max(time.time() - t_start, 1e-3)
        speed_mbs = (expect_bytes / 1024 ** 2) / elapsed
        log_ok(f"'{name}' written: {expect_bytes}B ({speed_mbs:.2f} MB/s)")
        self._record_manifest(name, out, part)
        return True

    def _record_manifest(
        self, name: str, out: Path,
        part: Partition, data: Optional[bytes] = None,
    ) -> None:
        # If already in manifest and file is at the right size, reuse checksums
        # to avoid re-reading the entire file (important for large partitions).
        if name in self.manifest and data is None:
            cached = self.manifest[name]
            if cached.get("size") == out.stat().st_size:
                log_debug(f"Manifest cache hit for '{name}' — reusing checksums")
                return

        if data is None:
            data = out.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        md5    = hashlib.md5(data).hexdigest()
        log_ok(f"SHA256 [{name}]: {sha256}")
        log_debug(f"MD5    [{name}]: {md5}")
        self.manifest[name] = {
            "file"      : str(out),
            "size"      : len(data),
            "sha256"    : sha256,
            "md5"       : md5,
            "first_lba" : part.first_lba,
            "last_lba"  : part.last_lba,
            "timestamp" : int(time.time()),
        }
        # W3 — Save manifest to disk immediately after each partition so a
        # crash or USB disconnect mid-dump-all does not lose all progress.
        self._flush_manifest()

    def _flush_manifest(self) -> None:
        """Write the in-memory manifest to disk (called after every partition)."""
        try:
            path = self.out_dir / "backup_manifest.json"
            path.write_text(json.dumps(self.manifest, indent=2), encoding="utf-8")
        except Exception as exc:
            log_warn(f"Manifest flush failed: {exc}")

    def save_manifest(self) -> Path:
        path = self.out_dir / "backup_manifest.json"
        path.write_text(json.dumps(self.manifest, indent=2), encoding="utf-8")
        log_ok(f"Manifest: {path}")
        return path


# ===========================================================================
#  PARTITION VERIFIER  (new in v1.2)
# ===========================================================================

class PartitionVerifier:
    """
    Compare a local image file against the live partition on device.

    Read-only: never writes to the device.
    Comparison is against the raw (unpadded) image bytes vs the matching
    prefix of the device partition data.
    """

    def __init__(self, brom: BROMProtocol, gpt: GPTReader) -> None:
        self.brom = brom
        self.gpt  = gpt

    def verify(self, name: str, image_path: Path) -> bool:
        """
        SHA256 compare device partition prefix vs local image.

        The local image may be smaller than the partition (the remainder
        of the partition may contain zeros or other data we don't care about).
        We compare: SHA256(device_data[:len(local_raw)]) vs SHA256(local_raw).

        Returns True if matching, False if mismatch or any error.
        """
        if not image_path.exists():
            log_error(f"Image file not found: {image_path}")
            return False

        part = self.gpt.find(name)
        if not part:
            log_error(f"Partition '{name}' not in GPT.")
            return False

        local_raw  = image_path.read_bytes()
        local_size = len(local_raw)

        if local_size > part.size_bytes:
            log_error(
                f"Image ({local_size}B) is larger than "
                f"partition '{name}' ({part.size_bytes}B) — cannot compare."
            )
            return False

        log_info(
            f"Verifying '{name}' ({local_size}B image "
            f"vs {part.size_bytes}B partition)..."
        )

        # Read only enough blocks to cover the image
        bs          = self.brom.block_size
        blocks_need = (local_size + bs - 1) // bs
        blocks_need = max(1, blocks_need)

        try:
            device_data = self.brom.read_blocks(part.first_lba, blocks_need)
        except Exception as exc:
            log_error(f"Device read failed during verification: {exc}")
            return False

        # Compare the first local_size bytes
        device_prefix = device_data[:local_size]

        sha_local  = hashlib.sha256(local_raw).hexdigest()
        sha_device = hashlib.sha256(device_prefix).hexdigest()

        if sha_local == sha_device:
            log_ok(
                f"VERIFY PASS: '{name}' matches {image_path.name}\n"
                f"  SHA256: {sha_local}"
            )
            return True

        log_error(
            f"VERIFY FAIL: '{name}' does NOT match {image_path.name}\n"
            f"  Image SHA256 : {sha_local}\n"
            f"  Device SHA256: {sha_device}"
        )
        return False


# ===========================================================================
#  PARTITION FLASHER
# ===========================================================================

class PartitionFlasher:
    """
    Safely flash a partition image onto the device.

    Safety layers:
      1. Protected-partition blacklist (hard block)
      2. userdata/metadata detected and redirected to PartitionFormatter
      3. Partition presence in GPT
      4. Sparse image detection (simg2img required)
      5. Image size <= partition size
      6. Interactive confirmation (bypassed with --force)
      7. Post-write readback SHA256 verification
    """

    def __init__(
        self, brom: BROMProtocol, gpt: GPTReader, force: bool = False,
    ) -> None:
        self.brom  = brom
        self.gpt   = gpt
        self.force = force

    def _safety_check(self, name: str, image_path: Path) -> bool:
        if name.lower() in PROTECTED_PARTITIONS:
            log_error(
                f"'{name}' is in the protected-partition list — "
                f"flashing blocked unconditionally."
            )
            return False

        if name.lower() in USERDATA_PARTITIONS:
            log_error(
                f"'{name}' is a userdata partition.  "
                f"Use --wipe-userdata for a full wipe, or "
                f"--format for zero-fill erase."
            )
            return False

        part = self.gpt.find(name)
        if not part:
            log_error(f"Partition '{name}' not in GPT.")
            return False

        if not image_path.exists():
            log_error(f"Image not found: {image_path}")
            return False

        # Sparse images are auto-converted by flash_partition() before _safety_check
        # is called. This guard is a defensive fallback only.
        if image_path.stat().st_size >= 4:
            with open(image_path, "rb") as _f:
                magic = _f.read(4)
            if magic == SPARSE_MAGIC:
                log_error(
                    f"'{image_path.name}' is still a sparse image after conversion attempt.\n"
                    f"  Convert manually with: simg2img {image_path.name} raw.img"
                )
                return False

        img_size = image_path.stat().st_size
        bs       = self.brom.block_size

        # Compute real partition byte size using the DA block_size, NOT the
        # GPT_SECTOR_SIZE constant (which is always 512 and is wrong for UFS
        # 4 096-byte native-block devices).
        part_bytes = (part.last_lba - part.first_lba + 1) * bs
        padded     = img_size + (-img_size % bs)

        if padded > part_bytes:
            log_error(
                f"Image ({img_size}B padded to {padded}B) exceeds "
                f"partition '{name}' ({part_bytes}B, "
                f"{part.last_lba - part.first_lba + 1} × {bs}B blocks) — "
                f"aborting.  Flashing an oversized image would overwrite "
                f"adjacent partitions and brick the device."
            )
            return False

        if img_size < part_bytes * 0.05:
            log_warn(
                f"Image ({img_size}B) is very small compared to "
                f"partition '{name}' ({part_bytes}B) — "
                f"confirm this image is correct before proceeding."
            )

        return True

    def _confirm(self, name: str, img: Path) -> bool:
        if self.force:
            return True
        print(
            f"\n{Fore.YELLOW}{Style.BRIGHT}"
            f"[CONFIRM] Flash '{img.name}' -> partition '{name}'\n"
            f"          This permanently overwrites partition data.\n"
            f"          Type YES to proceed: "
            f"{Style.RESET_ALL}",
            end="",
        )
        return input().strip() == "YES"

    def flash_partition(self, name: str, image_path: Path) -> bool:
        log_info(f"Preparing flash: '{name}' <- {image_path.name}")

        # W6 — Auto-convert Android sparse images to raw before any checks
        if image_path.exists() and image_path.stat().st_size >= 4:
            with open(image_path, "rb") as _f:
                _magic = _f.read(4)
            if _magic == SPARSE_MAGIC:
                log_warn(
                    f"'{image_path.name}' is a sparse image — "
                    f"converting to raw automatically (no simg2img needed)..."
                )
                converted = _sparse_to_raw(image_path)
                if converted is None:
                    log_error(
                        "Sparse → raw conversion failed.  "
                        "Convert manually with: simg2img <file> raw.img"
                    )
                    return False
                image_path = converted

        if not self._safety_check(name, image_path):
            return False

        if not self._confirm(name, image_path):
            log_warn("Flash cancelled by user.")
            return False

        part = self.gpt.find(name)

        # W11 — Auto-backup existing partition before overwriting (safety net)
        auto_bak = BACKUP_DIR / f"{name}_pre-flash_{int(time.time())}.img"
        log_info(f"Auto-backup '{name}' before flash → {auto_bak.name}")
        try:
            _total_bak = part.last_lba - part.first_lba + 1
            bak_data   = self.brom.read_blocks(part.first_lba, _total_bak)
            auto_bak.write_bytes(bak_data)
            log_ok(f"Pre-flash backup saved: {auto_bak}")
        except Exception as _exc:
            log_warn(
                f"Pre-flash backup failed ({_exc}) — "
                f"proceeding without backup.  Ensure you have a copy!"
            )

        raw         = image_path.read_bytes()
        bs          = self.brom.block_size
        rem         = len(raw) % bs
        padded_data = raw + (b"\x00" * (bs - rem)) if rem else raw

        sha_before = hashlib.sha256(padded_data).hexdigest()
        num_blocks = len(padded_data) // bs

        log_info(
            f"Writing {len(padded_data)}B ({num_blocks} blocks) "
            f"to '{name}' at LBA {part.first_lba}..."
        )

        t_start = time.time()
        try:
            self.brom.write_blocks(part.first_lba, padded_data)
        except Exception as exc:
            log_error(f"Flash write failed: {exc}")
            log_warn(f"Pre-flash backup available at: {auto_bak}")
            if DEBUG_MODE:
                traceback.print_exc()
            return False

        elapsed   = max(time.time() - t_start, 1e-3)
        speed_mbs = (len(padded_data) / 1024 ** 2) / elapsed
        log_ok(f"Write done: {elapsed:.2f}s  {speed_mbs:.2f} MB/s")

        log_info("Readback SHA256 verification...")
        try:
            verify    = self.brom.read_blocks(part.first_lba, num_blocks)
            sha_after = hashlib.sha256(verify).hexdigest()

            if sha_after == sha_before:
                log_ok(f"FLASH VERIFIED: '{name}'")
            else:
                log_error(
                    f"FLASH VERIFY FAILED: '{name}'\n"
                    f"  Written SHA256 : {sha_before}\n"
                    f"  Readback SHA256: {sha_after}\n"
                    f"  Restore from backup immediately."
                )
                return False
        except Exception as exc:
            log_warn(f"Readback check failed ({exc}) — flash may still be OK.")

        return True


# ===========================================================================
#  PARTITION FORMATTER  (new in v1.2)
# ===========================================================================

class PartitionFormatter:
    """
    Erase a partition using the fastest available method.

    Strategy (W7 fix):
      1. Try DA_CMD_FORMAT (0x74) — on-device hardware erase, takes seconds.
      2. Fall back to zero-fill via write_blocks() if DA rejects the command.

    Protected partitions are blocked unconditionally.
    Userdata partitions require the dedicated --wipe-userdata workflow.
    """

    def __init__(
        self, brom: BROMProtocol, gpt: GPTReader, force: bool = False,
    ) -> None:
        self.brom  = brom
        self.gpt   = gpt
        self.force = force

    def format_partition(self, name: str) -> bool:
        """
        Zero-fill the named partition.

        Returns True on complete success.
        """
        if name.lower() in PROTECTED_PARTITIONS:
            log_error(
                f"'{name}' is in the protected-partition list — "
                f"format blocked unconditionally."
            )
            return False

        part = self.gpt.find(name)
        if not part:
            log_error(f"Partition '{name}' not in GPT.")
            return False

        total_blocks  = part.last_lba - part.first_lba + 1
        chunk_blocks  = max(1, USB_CHUNK_BYTES // self.brom.block_size)
        total_bytes   = total_blocks * self.brom.block_size
        chunk_bytes   = chunk_blocks * self.brom.block_size

        log_info(
            f"Format '{name}': {total_bytes // 1024} KiB "
            f"({total_blocks} blocks) at LBA {part.first_lba}"
        )

        if not self.force:
            print(
                f"\n{Fore.RED}{Style.BRIGHT}"
                f"[CONFIRM] Erase partition '{name}' ({total_bytes // 1024} KiB).\n"
                f"          ALL data in this partition will be destroyed.\n"
                f"          Type ERASE to confirm: "
                f"{Style.RESET_ALL}",
                end="",
            )
            if input().strip() != "ERASE":
                log_warn("Format cancelled.")
                return False

        t_start = time.time()

        # W7 — Try fast on-device hardware erase first (DA_CMD_FORMAT 0x74).
        # If the loaded DA supports it, this completes in seconds regardless
        # of partition size. Fall back to zero-fill write only if rejected.
        log_info(f"Attempting on-device hardware erase for '{name}'...")
        if self.brom.format_partition_da(part.first_lba, total_blocks):
            elapsed = max(time.time() - t_start, 1e-3)
            log_ok(
                f"'{name}' erased via DA hardware erase in "
                f"{elapsed:.2f}s  (fast path)"
            )
            return True

        log_info("DA hardware erase not supported — falling back to zero-fill...")

        zero_chunk = bytes(chunk_bytes)
        offset     = 0

        pbar = _tqdm(
            total=total_bytes, unit="B", unit_scale=True,
            desc=f"  Zero-filling {name}", leave=False,
        ) if HAS_TQDM else None

        while offset < total_blocks:
            to_write   = min(chunk_blocks, total_blocks - offset)
            write_data = zero_chunk if to_write == chunk_blocks else bytes(
                to_write * self.brom.block_size
            )
            try:
                self.brom.write_blocks(part.first_lba + offset, write_data)
            except Exception as exc:
                log_error(
                    f"Format write error at LBA "
                    f"{part.first_lba + offset}: {exc}"
                )
                if pbar:
                    pbar.close()
                return False
            offset += to_write
            if pbar:
                pbar.update(len(write_data))

        if pbar:
            pbar.close()

        elapsed   = max(time.time() - t_start, 1e-3)
        speed_mbs = (total_bytes / 1024 ** 2) / elapsed
        log_ok(
            f"'{name}' zero-filled: {total_bytes}B in "
            f"{elapsed:.2f}s  ({speed_mbs:.2f} MB/s)"
        )
        return True


# ===========================================================================
#  USB STABILITY MANAGER
# ===========================================================================

class USBStabilityManager:
    """Background thread that monitors USB device connectivity."""

    def __init__(self, usb_dev: USBDevice) -> None:
        self.usb     = usb_dev
        self._active = False
        self._thread : Optional[threading.Thread] = None

    def start(self) -> None:
        self._active = True
        self._thread = threading.Thread(
            target=self._poll, daemon=True, name="usb-stability"
        )
        self._thread.start()
        log_debug("USB stability monitor started.")

    def stop(self) -> None:
        self._active = False

    def _poll(self) -> None:
        while self._active:
            if not self.usb.is_connected():
                log_warn("USB device disconnected unexpectedly!")
                self._active = False
                return
            time.sleep(2.0)

    def wait_reconnect(self, timeout_s: float = 30.0) -> bool:
        log_info("Waiting for device reconnect...")
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if self.usb.is_connected():
                log_ok("Device reconnected.")
                return True
            time.sleep(0.5)
        log_error("Device did not reconnect within timeout.")
        return False


# ===========================================================================
#  SHARED BROM SETUP
# ===========================================================================

# ===========================================================================
#  AVB PATCHER — Android Verified Boot 2.0 vbmeta flag editor
# ===========================================================================

class AVBPatcher:
    """
    Android Verified Boot 2.0 vbmeta image patcher.

    Reads the vbmeta (or vbmeta_a / vbmeta_b) partition, detects the
    current AVB flags, and optionally patches them to disable all
    verification — allowing Magisk-patched boot images, custom kernels,
    or modified system partitions to boot without triggering a dm-verity
    or AVB chain-of-trust failure.

    AVBVBMetaImageHeader layout (256-byte header, all big-endian):
      Offset   0  : magic "AVB0"  (4 bytes)
      Offset   4  : required_libavb_version_major  (u32)
      Offset   8  : required_libavb_version_minor  (u32)
      Offset  12  : authentication_data_block_size (u64)
      Offset  20  : auxiliary_data_block_size      (u64)
      Offset  28  : algorithm_type                 (u32)
      Offset  32  : hash_offset                    (u64)
      Offset  40  : hash_size                      (u64)
      Offset  48  : signature_offset               (u64)
      Offset  56  : signature_size                 (u64)
      Offset  64  : public_key_offset              (u64)
      Offset  72  : public_key_size                (u64)
      Offset  80  : public_key_metadata_offset     (u64)
      Offset  88  : public_key_metadata_size       (u64)
      Offset  96  : descriptor_offset              (u64)
      Offset 104  : descriptor_size                (u64)
      Offset 112  : rollback_index                 (u64)
      Offset 120  : flags                          (u32)
                       bit 0 = HASHTREE_DISABLED
                       bit 1 = VERIFICATION_DISABLED
      Offset 124  : rollback_index_location        (u32)
      Offset 128  : release_string                 (128 bytes, NUL-padded)

    To disable AVB enforcement this class:
      1. Reads the vbmeta partition (first 512 bytes; header is 256).
      2. Verifies the "AVB0" magic.
      3. Sets flags to 0x03 (HASHTREE_DISABLED | VERIFICATION_DISABLED).
      4. Zeroes the authentication block (hash + signature) so the
         signature no longer covers the mutated flags field. The bootloader
         on devices with VERIFICATION_DISABLED must accept this state.
      5. Writes the modified sector back.

    Recovery: flash the original vbmeta dump to undo.
    """

    MAGIC            = b"AVB0"
    HEADER_SIZE      = 256
    FLAGS_OFFSET     = 120       # u32 BE in vbmeta header
    AUTH_SIZE_OFFSET = 12        # u64 BE: authentication block size

    FLAG_HASHTREE_DISABLED     = 0x01
    FLAG_VERIFICATION_DISABLED = 0x02

    _VBMETA_CANDIDATES = ["vbmeta", "vbmeta_a", "vbmeta_b"]

    def __init__(self, brom: "BROMProtocol", gpt: "GPTReader") -> None:
        self.brom = brom
        self.gpt  = gpt
        self._part_name: Optional[str] = None
        self._part_entry               = None
        self._raw: Optional[bytearray] = None

    # ------------------------------------------------------------------
    def _find_vbmeta(self) -> Optional[str]:
        for name in self._VBMETA_CANDIDATES:
            if self.gpt.find(name):
                return name
        return None

    # ------------------------------------------------------------------
    def detect(self) -> Optional[Dict[str, Any]]:
        """
        Read vbmeta and decode current AVB flags.

        Returns dict with keys: partition, magic_ok, flags,
        hashtree_disabled, verification_disabled, auth_block_size,
        needs_patch.  Returns None on failure.
        """
        name = self._find_vbmeta()
        if not name:
            log_warn("AVBPatcher: no vbmeta partition found in GPT.")
            return None

        entry = self.gpt.find(name)
        if not entry:
            return None

        # AVB vbmeta layout: 256-byte header + auth_block + descriptor_block.
        # Auth block on real devices is commonly 1–4 KiB.  Reading only 1
        # sector (512 bytes) is sufficient to parse flags but then the auth
        # block zero-fill in disable_avb() would be clipped.  We read enough
        # sectors to cover a 4 KiB auth block and then extend further if the
        # stored auth_block_size is larger.  The initial read uses 8 sectors
        # (4 KiB) which covers the vast majority of real devices.
        INITIAL_SECTORS = 8
        part_sectors = entry.last_lba - entry.first_lba + 1
        read_sectors = min(INITIAL_SECTORS, part_sectors)

        try:
            raw_bytes = self.brom.read_blocks(entry.first_lba, read_sectors)
        except Exception as exc:
            log_error(f"AVBPatcher: failed to read '{name}': {exc}")
            return None

        if len(raw_bytes) < self.HEADER_SIZE:
            log_error("AVBPatcher: read too short.")
            return None

        # Peek at auth_block_size from the header we just read, then extend
        # the read if the auth block overflows the initial buffer.
        _auth_sz_peek = struct.unpack_from(">Q", raw_bytes, self.AUTH_SIZE_OFFSET)[0]
        needed_bytes  = self.HEADER_SIZE + int(_auth_sz_peek)
        if needed_bytes > len(raw_bytes):
            bs = self.brom.block_size
            extra_sectors = min(
                (needed_bytes - len(raw_bytes) + bs - 1) // bs,
                part_sectors - read_sectors,
            )
            if extra_sectors > 0:
                try:
                    extra = self.brom.read_blocks(
                        entry.first_lba + read_sectors, extra_sectors
                    )
                    raw_bytes = raw_bytes + extra
                    log_debug(
                        f"AVBPatcher: extended read +{extra_sectors} sectors "
                        f"to cover auth block ({_auth_sz_peek}B)"
                    )
                except Exception as exc:
                    log_warn(
                        f"AVBPatcher: could not extend read for large auth "
                        f"block ({exc}) — zeroing will be partial."
                    )

        self._part_name   = name
        self._part_entry  = entry
        self._raw         = bytearray(raw_bytes)
        self._read_sectors = (len(raw_bytes) + GPT_SECTOR_SIZE - 1) // GPT_SECTOR_SIZE

        magic_ok = self._raw[:4] == self.MAGIC
        if not magic_ok:
            log_warn(
                f"AVBPatcher: '{name}' does not start with 'AVB0' "
                f"(got {self._raw[:4].hex()}).  "
                f"Device may use a non-standard AVB layout."
            )

        flags   = struct.unpack_from(">I", self._raw, self.FLAGS_OFFSET)[0]
        auth_sz = struct.unpack_from(">Q", self._raw, self.AUTH_SIZE_OFFSET)[0]

        info: Dict[str, Any] = {
            "partition":              name,
            "magic_ok":               magic_ok,
            "flags":                  flags,
            "hashtree_disabled":      bool(flags & self.FLAG_HASHTREE_DISABLED),
            "verification_disabled":  bool(flags & self.FLAG_VERIFICATION_DISABLED),
            "auth_block_size":        auth_sz,
            "needs_patch":            not bool(
                flags & self.FLAG_VERIFICATION_DISABLED
            ),
        }
        log_debug(
            f"AVBPatcher: '{name}'  magic={'OK' if magic_ok else 'BAD'}  "
            f"flags=0x{flags:08X}  auth_block={auth_sz}B"
        )
        return info

    # ------------------------------------------------------------------
    def print_status(self, info: Dict[str, Any]) -> None:
        _sep = f"{Fore.CYAN}{'─' * 66}{Style.RESET_ALL}"
        print(f"\n{_sep}")
        print(
            f"  {Fore.CYAN}{Style.BRIGHT}"
            f"AVB Status  —  {info['partition']}{Style.RESET_ALL}"
        )
        print(_sep)

        def _fl(label: str, val: bool) -> None:
            col  = Fore.GREEN if val else Fore.RED
            icon = "YES  (disabled)" if val else "NO   (verification active)"
            print(f"  {label:<32} {col}{Style.BRIGHT}{icon}{Style.RESET_ALL}")

        print(
            f"  {'AVB magic':<32} "
            + (
                f"{Fore.GREEN}OK{Style.RESET_ALL}"
                if info["magic_ok"]
                else f"{Fore.RED}MISSING{Style.RESET_ALL}"
            )
        )
        print(f"  {'Flags (raw)':<32} 0x{info['flags']:08X}")
        _fl("Hashtree disabled",    info["hashtree_disabled"])
        _fl("Verification disabled", info["verification_disabled"])
        print(f"  {'Auth block size':<32} {info['auth_block_size']} bytes")
        print()

        if info["needs_patch"]:
            print(
                f"  {Fore.YELLOW}{Style.BRIGHT}"
                f"AVB verification is ACTIVE.{Style.RESET_ALL}\n"
                f"  Flashing a Magisk-patched boot.img without disabling AVB\n"
                f"  will cause a verification-error bootloop on this device.\n"
                f"  Use --disable-avb (menu  [I]) to patch vbmeta first."
            )
        else:
            print(
                f"  {Fore.GREEN}{Style.BRIGHT}"
                f"AVB verification is DISABLED — device will accept custom images."
                f"{Style.RESET_ALL}"
            )
        print(_sep + "\n")

    # ------------------------------------------------------------------
    def disable_avb(self, force: bool = False) -> bool:
        """
        Patch vbmeta to disable AVB enforcement.

        Sets flags = HASHTREE_DISABLED | VERIFICATION_DISABLED (0x03)
        and zeroes the auth block so the signature cannot be verified.
        Writes the modified sector back to the vbmeta partition.

        Returns True on success.
        """
        info = self.detect()
        if info is None:
            return False

        self.print_status(info)

        if not info["magic_ok"]:
            log_warn(
                "AVB0 magic missing — patching flags anyway.  "
                "Boot behaviour depends on the specific bootloader build."
            )

        if not info["needs_patch"]:
            log_ok("AVB is already fully disabled — nothing to do.")
            return True

        if not force:
            confirm = input(
                f"  {Fore.RED}{Style.BRIGHT}"
                f"Patch vbmeta to disable all AVB verification? [y/N]:  "
                f"{Style.RESET_ALL}"
            ).strip().lower()
            if confirm != "y":
                log_warn("AVB patch cancelled.")
                return False

        raw = self._raw
        assert raw is not None

        # Patch flags field
        new_flags = (
            self.FLAG_HASHTREE_DISABLED | self.FLAG_VERIFICATION_DISABLED
        )
        struct.pack_into(">I", raw, self.FLAGS_OFFSET, new_flags)

        # Zero authentication block (hash + signature).
        # The zero-fill covers exactly the bytes we read from the device,
        # clipped to the in-memory buffer length.  detect() already extended
        # the read to cover auth_block_size if possible.
        auth_sz  = info["auth_block_size"]
        start    = self.HEADER_SIZE
        end      = start + int(auth_sz)
        _clip  = min(end, len(raw))
        zeroed = _clip - start
        if zeroed > 0:
            raw[start:_clip] = b'\x00' * zeroed
        if auth_sz > 0:
            log_debug(f"Zeroed {zeroed}/{auth_sz}B auth block in vbmeta image.")
            if zeroed < auth_sz:
                log_warn(
                    f"Auth block ({auth_sz}B) larger than buffer ({len(raw)}B) — "
                    f"only {zeroed}B zeroed.  Partial zero is still sufficient to "
                    f"break the RSA signature and prevent verification."
                )

        # Write back — use write_blocks with the correct byte count.
        # write_blocks() requires a buffer that is a multiple of block_size;
        # it handles zero-padding internally via the block-alignment logic.
        try:
            self.brom.write_blocks(self._part_entry.first_lba, bytes(raw))
        except Exception as exc:
            log_error(f"AVBPatcher write failed: {exc}")
            return False

        log_ok(
            f"vbmeta patched on '{self._part_name}'  "
            f"flags=0x{new_flags:08X}  "
            f"(HASHTREE_DISABLED | VERIFICATION_DISABLED)"
        )

        # ── A/B slot counterpart patching ─────────────────────────────────────
        # On A/B devices, both vbmeta_a and vbmeta_b must be patched.
        # The bootloader will verify whichever slot it boots — if only one is
        # patched, the first OTA reboot will switch to the unpatched slot and
        # re-enable verification, causing a bootloop on custom-imaged devices.
        counterpart_map = {"vbmeta_a": "vbmeta_b", "vbmeta_b": "vbmeta_a"}
        counterpart_name = counterpart_map.get(self._part_name)

        if counterpart_name:
            cp_entry = self.gpt.find(counterpart_name)
            if cp_entry:
                log_info(
                    f"A/B device detected — also patching counterpart "
                    f"'{counterpart_name}'..."
                )
                try:
                    cp_sectors = min(
                        getattr(self, "_read_sectors", 8),
                        cp_entry.last_lba - cp_entry.first_lba + 1,
                    )
                    cp_raw = bytearray(
                        self.brom.read_blocks(cp_entry.first_lba, cp_sectors)
                    )
                    if cp_raw[:4] == self.MAGIC:
                        struct.pack_into(">I", cp_raw, self.FLAGS_OFFSET, new_flags)
                        _cp_auth = struct.unpack_from(">Q", cp_raw, self.AUTH_SIZE_OFFSET)[0]
                        _cp_end  = self.HEADER_SIZE + int(_cp_auth)
                        _cp_clip = min(_cp_end, len(cp_raw))
                        if _cp_clip > self.HEADER_SIZE:
                            cp_raw[self.HEADER_SIZE:_cp_clip] = b'\x00' * (_cp_clip - self.HEADER_SIZE)
                        self.brom.write_blocks(cp_entry.first_lba, bytes(cp_raw))
                        log_ok(
                            f"Counterpart '{counterpart_name}' patched  "
                            f"flags=0x{new_flags:08X}"
                        )
                    else:
                        log_warn(
                            f"'{counterpart_name}' does not have AVB0 magic — "
                            f"skipping counterpart patch."
                        )
                except Exception as exc:
                    log_warn(
                        f"Counterpart '{counterpart_name}' patch failed: {exc}\n"
                        f"  Primary vbmeta was patched successfully.  You may need\n"
                        f"  to manually patch '{counterpart_name}' before rebooting."
                    )
            else:
                log_debug(
                    f"Counterpart '{counterpart_name}' not in GPT — "
                    f"single-slot device or alternate partition naming."
                )
        elif self._part_name == "vbmeta":
            # Generic "vbmeta" — check whether vbmeta_a / vbmeta_b also exist
            # and patch them to ensure A/B-unaware OTA does not undo our work.
            for _cand in ("vbmeta_a", "vbmeta_b"):
                _e = self.gpt.find(_cand)
                if not _e:
                    continue
                try:
                    _s = min(getattr(self, "_read_sectors", 8),
                             _e.last_lba - _e.first_lba + 1)
                    _r = bytearray(self.brom.read_blocks(_e.first_lba, _s))
                    if _r[:4] == self.MAGIC:
                        struct.pack_into(">I", _r, self.FLAGS_OFFSET, new_flags)
                        _a = struct.unpack_from(">Q", _r, self.AUTH_SIZE_OFFSET)[0]
                        for j in range(self.HEADER_SIZE,
                                       min(self.HEADER_SIZE + int(_a), len(_r))):
                            _r[j] = 0x00
                        self.brom.write_blocks(_e.first_lba, bytes(_r))
                        log_ok(f"Also patched '{_cand}'  flags=0x{new_flags:08X}")
                except Exception as exc:
                    log_warn(f"Optional patch of '{_cand}' failed: {exc}")

        return True


def _claim_usb_interface(raw_dev: "usb.core.Device") -> None:
    """Detach kernel driver and set USB configuration. Warns but never aborts."""
    try:
        if CURRENT_PLATFORM != "windows":
            try:
                if raw_dev.is_kernel_driver_active(0):
                    raw_dev.detach_kernel_driver(0)
                    log_debug("Kernel driver detached.")
            except Exception:
                pass
        raw_dev.set_configuration()
    except Exception as exc:
        log_warn(f"USB claim (non-fatal): {exc}")


# ---------------------------------------------------------------------------
# W4 — Session-level BROM / payload cache
# ---------------------------------------------------------------------------
# Within a single process (interactive menu) the same physical BROM session
# can be reused across back-to-back operations, skipping the expensive
# handshake + watchdog + payload-upload sequence.  Each caller validates
# that the device is still electrically connected before trusting the cache.
# ---------------------------------------------------------------------------
_SESSION: Dict[str, Any] = {
    "alive"        : False,
    "raw_dev"      : None,
    "usb_dev"      : None,
    "brom"         : None,
    "stability"    : None,
    "payload_hash" : "",   # sha256 hex of the last uploaded payload
    "payload_name" : "",
    "born_at"      : 0.0,  # time.time() when session was first established
}
_SESSION_TTL = 300.0   # seconds before a cached session is unconditionally expired


def _session_alive() -> bool:
    """Return True only if the cached BROM session is still usable."""
    if not _SESSION["alive"]:
        return False
    if time.time() - _SESSION["born_at"] > _SESSION_TTL:
        log_debug("W4: session TTL expired — will re-setup BROM.")
        _session_invalidate()
        return False
    try:
        usb_dev:   "USBDevice"         = _SESSION["usb_dev"]
        stability: "USBStabilityManager" = _SESSION["stability"]
        # If any workflow function called stability.stop() since the session
        # was stored, _active is False and the keepalive thread has exited.
        # Reusing such a session would operate without a USB heartbeat.
        if stability is not None and not stability._active:
            log_debug("W4: stability monitor stopped — invalidating session.")
            _session_invalidate()
            return False
        if not usb_dev.is_connected():
            log_debug("W4: device disconnected — invalidating session.")
            _session_invalidate()
            return False
    except Exception:
        _session_invalidate()
        return False
    return True


def _session_store(
    raw_dev: Any,
    usb_dev: "USBDevice",
    brom: "BROMProtocol",
    stability: "USBStabilityManager",
    payload_data: bytes,
    payload_name: str,
) -> None:
    """Persist a newly-established BROM session in the module-level cache."""
    _SESSION["alive"]        = True
    _SESSION["raw_dev"]      = raw_dev
    _SESSION["usb_dev"]      = usb_dev
    _SESSION["brom"]         = brom
    _SESSION["stability"]    = stability
    _SESSION["payload_hash"] = hashlib.sha256(payload_data).hexdigest()
    _SESSION["payload_name"] = payload_name
    _SESSION["born_at"]      = time.time()
    log_debug(f"W4: session cached (payload={payload_name}).")


def _session_invalidate() -> None:
    """Clear the module-level session cache."""
    _SESSION["alive"]        = False
    _SESSION["raw_dev"]      = None
    _SESSION["usb_dev"]      = None
    _SESSION["brom"]         = None
    _SESSION["stability"]    = None
    _SESSION["payload_hash"] = ""
    _SESSION["payload_name"] = ""
    _SESSION["born_at"]      = 0.0
    log_debug("W4: session invalidated.")


def _setup_brom(
    args: argparse.Namespace,
) -> Optional[Tuple["usb.core.Device", USBDevice, BROMProtocol, USBStabilityManager]]:
    """
    Full BROM connection sequence shared by all workflow functions.

    Order:
      device discovery → USB init → stability monitor → UART log enable
      → handshake → chipset ID → watchdog disable → payload upload
      → SLA bypass → storage init.

    Returns (raw_dev, usb_dev, brom, stability) or None on failure.

    W4: If a cached session from this process is still alive and the
    device is still connected, the expensive handshake + payload-upload
    steps are skipped entirely and the cached objects are returned directly.
    """
    # W4 — try to reuse an already-established BROM session
    if _session_alive():
        raw_dev   = _SESSION["raw_dev"]
        usb_dev   = _SESSION["usb_dev"]
        brom      = _SESSION["brom"]
        stability = _SESSION["stability"]
        pname     = _SESSION["payload_name"]
        log_ok(f"W4: reusing live BROM session (payload={pname}) — skipping re-upload.")
        return raw_dev, usb_dev, brom, stability

    raw_dev = find_mtk_device(timeout_s=args.wait_timeout)
    if raw_dev is None:
        return None

    _claim_usb_interface(raw_dev)

    try:
        usb_dev = USBDevice(raw_dev)
    except RuntimeError as exc:
        log_error(f"USB endpoint setup failed: {exc}")
        return None

    stability = USBStabilityManager(usb_dev)
    stability.start()

    brom    = BROMProtocol(usb_dev)

    # Enable UART1 BROM log channel (non-fatal — requires physical UART adapter)
    brom.enable_uart_log()

    if not brom.handshake():
        stability.stop()
        return None

    brom.identify_chipset()

    # Deepen fingerprint: read BROM ROM version + ME-ID (non-fatal)
    brom.read_brom_version()
    brom.get_me_id()

    # Payload selection
    if args.payload:
        ppath = Path(args.payload)
        if not ppath.exists():
            log_error(f"Specified payload not found: {ppath}")
            stability.stop()
            return None
        payload_data = ppath.read_bytes()
        log_ok(f"Custom payload: {ppath.name} ({len(payload_data)}B)")
    else:
        payload_data = brom.load_payload()

    if not payload_data:
        log_error(
            "No payload binary available.  "
            "Place the correct .bin in ./payloads/ or use --payload FILE."
        )
        stability.stop()
        return None

    brom.watchdog_disable()

    pname = (brom.chipset or {}).get("payload", "custom.bin")
    log_ok(f"Payload selected: {pname}")

    if not brom.send_payload(payload_data):
        log_error("Payload execution failed — aborting.")
        stability.stop()
        return None

    sla_ok = brom.bypass_sla_daa()
    if not sla_ok:
        cfg = brom.target_config
        if cfg.get("sla_enabled") or cfg.get("daa_enabled"):
            log_error(
                "SLA/DAA bypass FAILED on a device with SLA/DAA active.\n"
                "  A Kamakiri-class signed payload is required for this device.\n"
                "  Standard unsigned payloads are rejected by the BROM.\n"
                "  Aborting — no writes were performed."
            )
            stability.stop()
            return None
        log_warn(
            "SLA bypass ACK unexpected (non-0xA5) but SLA/DAA not flagged — "
            "continuing (device likely uses legacy no-SLA protocol)."
        )

    if not brom.init_storage():
        log_error("Storage init failed — aborting.")
        stability.stop()
        return None

    # W4 — cache the live session for reuse within this process
    _session_store(raw_dev, usb_dev, brom, stability, payload_data, pname)

    # Initialise session audit log (creates backup/<chipset>/forge_audit_*.jsonl)
    _chipset_name = (brom.chipset or {}).get("name", f"0x{brom.hw_code:04X}")
    _audit_dir    = BACKUP_DIR / _chipset_name
    _audit        = ForgeAuditLog.init(_audit_dir)
    _audit.log_connect(brom.hw_code, _chipset_name)

    return raw_dev, usb_dev, brom, stability


def _load_boot_ctrl(brom: BROMProtocol, gpt: GPTReader) -> Optional[BootCtrlParser]:
    """
    Read the first 512 bytes of the 'misc' partition and parse boot_ctrl.
    Returns None if misc partition is absent or parsing fails.
    """
    misc = gpt.find("misc")
    if not misc:
        log_debug("'misc' partition not found — A/B slot info unavailable.")
        return None
    try:
        sector = brom.read_blocks(misc.first_lba, 1)
        bc = BootCtrlParser(sector)
        if bc.valid:
            log_debug(f"boot_ctrl: active slot = {bc.active_slot()}")
        return bc
    except Exception as exc:
        log_warn(f"boot_ctrl read failed (non-fatal): {exc}")
        return None


# ===========================================================================
#  WORKFLOW — FULL DUMP
# ===========================================================================

def run_auto_workflow(args: argparse.Namespace) -> int:
    """
    Full automated MTK dump (+ optional flash) workflow.

    Supports --dump and --dump-all.
    """
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = args.debug
    VERBOSE_MODE = args.verbose or args.debug

    if not HAS_USB:
        log_error("pyusb not installed.  Run: pip install pyusb pyserial colorama tqdm")
        return 1

    log_info(f"Platform: {CURRENT_PLATFORM}")
    if not check_termux_usb():
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw_dev, _usb_dev, brom, stability = result

    gpt = GPTReader(brom)
    if not gpt.read():
        log_error("GPT read failed.")
        stability.stop()
        return 1

    gpt.print_table()

    chipset_label = (brom.chipset or {}).get("name", f"0x{brom.hw_code:04X}")
    out_dir       = BACKUP_DIR / chipset_label
    out_dir.mkdir(parents=True, exist_ok=True)
    log_info(f"Backup directory: {out_dir}")

    if getattr(args, "dump_all", False):
        targets = [p.name for p in gpt.partitions]
        log_info(f"--dump-all: {len(targets)} partitions")
    elif args.partitions:
        targets = [t.strip() for t in args.partitions.split(",")]
    else:
        targets = AUTO_DUMP_PARTITIONS

    dumper  = PartitionDumper(brom, gpt, out_dir)
    results : Dict[str, bool] = {}

    # A/B-capable partitions: if base name absent, try _a then _b suffix
    _AB_CAPABLE: Set[str] = {
        "boot", "init_boot", "recovery", "vbmeta", "dtbo",
        "system", "vendor", "product", "odm", "system_ext",
    }

    for pname in targets:
        if gpt.find(pname):
            results[pname] = dumper.dump(pname)
        else:
            # A/B fallback — try _a / _b suffixed partition names
            if pname in _AB_CAPABLE:
                found_ab = False
                for suffix in ("_a", "_b"):
                    ab_name = pname + suffix
                    if gpt.find(ab_name):
                        log_info(
                            f"'{pname}' not found — using A/B variant '{ab_name}'"
                        )
                        results[ab_name] = dumper.dump(ab_name)
                        found_ab = True
                if found_ab:
                    continue
            log_warn(f"'{pname}' not in GPT — skipping.")
            results[pname] = False

    mf = dumper.save_manifest()

    if args.flash_partition and args.flash_image:
        flasher = PartitionFlasher(brom, gpt, force=args.force)
        if not flasher.flash_partition(
            args.flash_partition, Path(args.flash_image)
        ):
            log_error(f"Flash of '{args.flash_partition}' failed.")

    stability.stop()
    ok_count    = sum(1 for v in results.values() if v)
    total_count = len(results)

    print()
    log_done(
        f"Backup complete: {ok_count}/{total_count} partitions  ->  {out_dir}"
    )
    log_done(f"Manifest : {mf}")
    log_done(f"Log file : {LOG_FILE}")

    return 0 if ok_count == total_count else 2


# ===========================================================================
#  WORKFLOW — LIST PARTITIONS
# ===========================================================================

def run_list_partitions(args: argparse.Namespace) -> int:
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = args.debug
    VERBOSE_MODE = args.verbose or args.debug

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw_dev, _usb_dev, brom, stability = result

    gpt = GPTReader(brom)
    if not gpt.read():
        stability.stop()
        return 1

    gpt.print_table()
    stability.stop()
    return 0


# ===========================================================================
#  WORKFLOW — DEVICE INFO
# ===========================================================================

def run_device_info(args: argparse.Namespace) -> int:
    """Connect, collect all device information, print summary, export JSON."""
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = args.debug
    VERBOSE_MODE = args.verbose or args.debug

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw_dev, _usb_dev, brom, stability = result

    gpt = GPTReader(brom)
    if not gpt.read():
        stability.stop()
        return 1

    boot_ctrl = _load_boot_ctrl(brom, gpt)

    collector = DeviceInfoCollector(brom, gpt, boot_ctrl)
    info      = collector.collect()

    collector.print_summary(info)
    gpt.print_table()

    if boot_ctrl and boot_ctrl.valid:
        boot_ctrl.print_slots()

    out_path = None
    if getattr(args, "out", None):
        out_path = Path(args.out)
    else:
        chipset  = (brom.chipset or {}).get("name", f"0x{brom.hw_code:04X}")
        out_path = LOG_DIR / f"device_info_{chipset}_{int(time.time())}.json"

    collector.save(out_path, info)
    stability.stop()
    return 0


# ===========================================================================
#  WORKFLOW — SLOT INFO
# ===========================================================================

def run_slot_info(args: argparse.Namespace) -> int:
    """Read and display A/B slot status from the misc partition."""
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = args.debug
    VERBOSE_MODE = args.verbose or args.debug

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw_dev, _usb_dev, brom, stability = result

    gpt = GPTReader(brom)
    if not gpt.read():
        stability.stop()
        return 1

    boot_ctrl = _load_boot_ctrl(brom, gpt)
    if boot_ctrl:
        boot_ctrl.print_slots()
    else:
        log_warn(
            "Could not read slot info.  "
            "Device may not use A/B slots or 'misc' partition is absent."
        )

    stability.stop()
    return 0


# ===========================================================================
#  WORKFLOW — SWITCH SLOT
# ===========================================================================

def run_switch_slot(args: argparse.Namespace) -> int:
    """
    Read boot_ctrl from misc partition, set target slot as active,
    write modified boot_ctrl back.

    Dry-run is fully supported: prints what would be written without touching
    the device.
    """
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = args.debug
    VERBOSE_MODE = args.verbose or args.debug

    target_slot = getattr(args, "switch_slot", "").lower()
    if target_slot not in ("a", "b"):
        log_error("--switch-slot requires 'a' or 'b'.")
        return 1

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw_dev, _usb_dev, brom, stability = result

    gpt = GPTReader(brom)
    if not gpt.read():
        stability.stop()
        return 1

    misc = gpt.find("misc")
    if not misc:
        log_error("'misc' partition not found in GPT — cannot switch slot.")
        stability.stop()
        return 1

    try:
        sector = brom.read_blocks(misc.first_lba, 1)
    except Exception as exc:
        log_error(f"Could not read misc partition: {exc}")
        stability.stop()
        return 1

    bc = BootCtrlParser(sector)
    if not bc.valid:
        log_error(
            "boot_ctrl not valid in misc partition.  "
            "Cannot switch slots safely."
        )
        stability.stop()
        return 1

    current = bc.active_slot()
    log_info(f"Current active slot: {current}  ->  switching to: {target_slot}")

    if current == target_slot:
        log_ok(f"Slot '{target_slot}' is already active — nothing to do.")
        stability.stop()
        return 0

    try:
        new_ctrl = bc.make_active(target_slot)
    except (RuntimeError, ValueError) as exc:
        log_error(f"boot_ctrl modification failed: {exc}")
        stability.stop()
        return 1

    if not args.force:
        print(
            f"\n{Fore.YELLOW}{Style.BRIGHT}"
            f"[CONFIRM] Switch active slot from '{current}' to '{target_slot}'.\n"
            f"          This modifies the misc partition boot_ctrl.\n"
            f"          Type YES to proceed: "
            f"{Style.RESET_ALL}",
            end="",
        )
        if input().strip() != "YES":
            log_warn("Slot switch cancelled.")
            stability.stop()
            return 0

    write_data = new_ctrl + bytes(GPT_SECTOR_SIZE - len(new_ctrl))
    try:
        brom.write_blocks(misc.first_lba, write_data)
        log_ok(f"Slot switched to '{target_slot}' — reboot to apply.")
    except Exception as exc:
        log_error(f"boot_ctrl write failed: {exc}")
        stability.stop()
        return 1

    stability.stop()
    return 0


# ===========================================================================
#  WORKFLOW — DISABLE AVB
# ===========================================================================

def run_disable_avb(args: argparse.Namespace) -> int:
    """
    Disable Android Verified Boot by patching the vbmeta partition flags.

    Connects via BROM (full payload session), reads vbmeta, sets the
    HASHTREE_DISABLED | VERIFICATION_DISABLED flags, zeroes the auth
    block, and writes back.  The backup of the original vbmeta is saved
    to BACKUP_DIR before any write is performed.

    This is required when flashing a Magisk-patched boot image on devices
    (such as Oppo A16 / CPH2269) that have AVB2 enforcement active —
    without it the device bootloops with a 'Verification Error' screen.
    """
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = args.debug
    VERBOSE_MODE = args.verbose or args.debug

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw_dev, _usb_dev, brom, stability = result

    gpt = GPTReader(brom)
    if not gpt.read():
        stability.stop()
        return 1

    # Pre-patch: auto-backup current vbmeta
    chipset_label = (brom.chipset or {}).get("name", f"0x{brom.hw_code:04X}")
    backup_dir    = BACKUP_DIR / chipset_label
    backup_dir.mkdir(parents=True, exist_ok=True)

    dumper = PartitionDumper(brom, gpt, backup_dir)
    for cand in ["vbmeta", "vbmeta_a", "vbmeta_b"]:
        if gpt.find(cand):
            log_info(f"Backing up '{cand}' before patching...")
            if not dumper.dump(cand):
                log_warn(
                    f"vbmeta backup of '{cand}' failed — "
                    f"proceeding without a safety copy.  "
                    f"Flash the original vbmeta.img manually to restore if needed."
                )
            break

    patcher = AVBPatcher(brom, gpt)
    ok      = patcher.disable_avb(force=getattr(args, "force", False))

    stability.stop()
    if ok:
        log_done(
            "AVB disabled.  You may now flash a Magisk-patched boot image\n"
            "  and the device will boot without an AVB verification error.\n"
            f"  Original vbmeta backup is in: {backup_dir}"
        )
    return 0 if ok else 1


# ===========================================================================
#  ROOT / SAFETY HELPERS
# ===========================================================================

def _find_magiskboot() -> Optional[str]:
    """
    Locate a magiskboot or magisk binary for local boot image patching.
    Checks PATH first, then common local directories.
    Returns the full path string, or None if nothing is found.
    """
    for name in ("magiskboot", "magiskboot.exe", "magisk", "magisk64", "magisk32",
                 "magisk.exe"):
        found = shutil.which(name)
        if found:
            return found
    extras = [
        Path.cwd() / "magiskboot",
        Path.cwd() / "magiskboot.exe",
        Path.cwd() / "magisk",
        Path.cwd() / "magisk64",
        Path(__file__).parent / "magiskboot",
        Path(__file__).parent / "tools" / "magiskboot",
        Path.home() / "magiskboot",
        Path.home() / "magisk",
    ]
    for p in extras:
        if p.exists() and p.is_file():
            return str(p)
    return None


def _auto_backup_nvram(
    brom: "BROMProtocol",
    gpt:  "GPTReader",
    backup_dir: Path,
) -> None:
    """
    Auto-dump NVRAM / NV-data partitions before any destructive operation.

    These partitions store IMEI, WiFi/BT MAC addresses, and RF calibration
    data.  Losing or corrupting them causes permanent signal loss
    ('baseband not found' / 'invalid IMEI').

    Called automatically by: run_wipe_userdata(), run_backup_critical().
    """
    NV_CANDIDATES = [
        "nvram", "nvram_a", "nvram_b",
        "nvdata", "nvdata_a", "nvdata_b",
        "nvcfg",
    ]
    dumper = PartitionDumper(brom, gpt, backup_dir)
    backed = 0
    for name in NV_CANDIDATES:
        if not gpt.find(name):
            continue
        log_info(f"Auto-backing up '{name}' (IMEI/MAC/calibration data)…")
        if dumper.dump(name):
            backed += 1
    if backed:
        log_ok(f"NVRAM backup done — {backed} partition(s) → {backup_dir}")
    else:
        log_debug("No NVRAM partitions found in GPT — nothing to back up.")


# ===========================================================================
#  WORKFLOW — ROOT DEVICE  (guided Magisk + AVB sequence)
# ===========================================================================

def run_root_device(args: argparse.Namespace) -> int:
    """
    Guided root workflow for MTK devices (e.g. Oppo A16 / CPH2269).

    Step sequence:
      1. Connect via BROM (full payload session).
      2. Read GPT and locate boot / boot_a partition.
      3. Auto-detect A/B slot (from misc/boot_ctrl) and choose correct slot.
      4. Dump the active boot image to disk.
      5. Print Magisk patch instructions (user patches on their phone or PC).
      6. Wait for user to supply the patched image path.
      7. Validate the patched image (ANDROID! magic check).
      8. Optional: disable AVB (strongly recommended — backs up vbmeta first).
      9. Flash the Magisk-patched boot image to the correct slot.
     10. Reboot to system.

    This workflow does NOT modify system, vendor, or preloader — it is the
    minimum-footprint approach used by the MTK community for Magisk rooting.
    """
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = args.debug
    VERBOSE_MODE = args.verbose or args.debug

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    _sub_header("Root Device  ·  Magisk + AVB Guide")

    print(
        f"\n  {Fore.CYAN}{Style.BRIGHT}androidForge Root Workflow{Style.RESET_ALL}\n"
        f"\n  This wizard guides you through the standard MTK root process:\n"
        f"    1. Dump your active boot image\n"
        f"    2. Patch it with Magisk (you do this step on your phone / PC)\n"
        f"    3. Disable AVB verification (prevents bootloop after root)\n"
        f"    4. Flash the patched boot back\n"
        f"    5. Reboot to rooted system\n"
    )

    confirm = input(
        f"  {Fore.YELLOW}{Style.BRIGHT}Continue? [y/N]:  {Style.RESET_ALL}"
    ).strip().lower()
    if confirm != "y":
        log_warn("Root workflow cancelled.")
        return 0

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw_dev, _usb_dev, brom, stability = result

    gpt = GPTReader(brom)
    if not gpt.read():
        stability.stop()
        return 1

    # ── Step 1: identify active boot partition ────────────────────────
    boot_ctrl  = _load_boot_ctrl(brom, gpt)
    active_slot: Optional[str] = None
    if boot_ctrl and boot_ctrl.valid:
        active_slot = boot_ctrl.active_slot()   # "a" or "b"
        log_ok(f"A/B device — active slot: {active_slot}")

    boot_name: Optional[str] = None
    for candidate in (
        [f"boot_{active_slot}"] if active_slot else []
    ) + ["boot", "boot_a"]:
        if gpt.find(candidate):
            boot_name = candidate
            break

    if not boot_name:
        log_error(
            "Cannot find a boot partition in the GPT.  "
            "Checked: boot, boot_a, and slot-specific names."
        )
        stability.stop()
        return 1

    log_ok(f"Target boot partition: '{boot_name}'")

    # ── Step 1b: Android 13+ init_boot detection ─────────────────────
    # Magisk v26+ patches init_boot (not boot) on Android 13 GKI devices.
    # If init_boot is present in the GPT it takes priority over boot.
    for ib_cand in (
        [f"init_boot_{active_slot}"] if active_slot else []
    ) + ["init_boot", "init_boot_a"]:
        if gpt.find(ib_cand):
            log_info(
                f"Android 13+ device — 'init_boot' partition found ({ib_cand}).\n"
                f"  Magisk v26+ patches init_boot, not boot, on Android 13 GKI devices.\n"
                f"  Switching root target to '{ib_cand}'."
            )
            boot_name = ib_cand
            break

    # ── Step 2: dump boot image ───────────────────────────────────────
    chipset_label = (brom.chipset or {}).get("name", f"0x{brom.hw_code:04X}")
    out_dir       = BACKUP_DIR / chipset_label
    out_dir.mkdir(parents=True, exist_ok=True)

    dumper  = PartitionDumper(brom, gpt, out_dir)
    dump_ok = dumper.dump(boot_name)
    if not dump_ok:
        log_error("Boot dump failed — aborting root workflow.")
        stability.stop()
        return 1

    boot_dump_path = out_dir / f"{boot_name}.img"
    log_done(f"Boot image saved to: {boot_dump_path}")

    # ── Step 3: Magisk patch — detect local binary or guide manually ─────
    _magisk_bin = _find_magiskboot()

    print(
        f"\n  {Fore.CYAN}{Style.BRIGHT}── Magisk Patch Instructions {'─' * 24}{Style.RESET_ALL}\n"
    )

    if _magisk_bin and ("magisk" in Path(_magisk_bin).name and
                        "boot" not in Path(_magisk_bin).name):
        # Full magisk binary found — can patch directly with --patch flag
        print(
            f"  {Fore.GREEN}{Style.BRIGHT}✔ magisk binary detected:{Style.RESET_ALL}"
            f" {Fore.YELLOW}{_magisk_bin}{Style.RESET_ALL}\n"
            f"\n  You can patch the boot image locally — no phone needed.\n"
            f"  Run this in a terminal (keep it open, then paste the output path below):\n"
            f"\n    {Fore.CYAN}{_magisk_bin} --patch {boot_dump_path}{Style.RESET_ALL}\n"
            f"\n  Magisk saves the result as  magisk_patched_<hash>.img"
            f"\n  in the current directory.  Copy that path and paste it below.\n"
        )
    elif _magisk_bin:
        # magiskboot found but not the full magisk binary
        print(
            f"  {Fore.YELLOW}{Style.BRIGHT}✔ magiskboot found:{Style.RESET_ALL}"
            f" {Fore.YELLOW}{_magisk_bin}{Style.RESET_ALL}\n"
            f"\n  magiskboot can unpack/inspect images but cannot inject the Magisk\n"
            f"  init daemon on its own — you need the full magisk binary.\n"
            f"\n  Download from: {Fore.CYAN}https://github.com/topjohnwu/Magisk/releases{Style.RESET_ALL}\n"
            f"  Then run:  {Fore.CYAN}magisk --patch {boot_dump_path}{Style.RESET_ALL}\n"
            f"\n  OR use Option A (on-phone patching) below.\n"
        )
    else:
        print(
            f"  {Fore.WHITE}No magisk binary found on this PC — choose an option below.{Style.RESET_ALL}\n"
        )

    print(
        f"  {Fore.WHITE}{Style.BRIGHT}Option A — Patch on your phone:{Style.RESET_ALL}"
        f"\n    1. Copy boot image to phone:"
        f"\n       {Fore.YELLOW}{boot_dump_path}{Style.RESET_ALL}"
        f"\n    2. Open Magisk app → Install → 'Select and Patch a File'"
        f"\n    3. Select  {boot_name}.img"
        f"\n    4. Magisk saves: {Fore.YELLOW}/sdcard/Download/magisk_patched_<hash>.img{Style.RESET_ALL}"
        f"\n    5. Copy the patched image back to this PC\n"
        f"\n  {Fore.WHITE}{Style.BRIGHT}Option B — Local PC patching:{Style.RESET_ALL}"
        f"\n    {Fore.CYAN}https://github.com/topjohnwu/Magisk/releases{Style.RESET_ALL}"
        f"\n    Run:  magisk --patch {boot_dump_path}\n"
    )

    print(f"\n  {Fore.CYAN}{'─' * 66}{Style.RESET_ALL}\n")

    patched_path_str = input(
        f"  {Fore.CYAN}›{Style.RESET_ALL} "
        f"{Fore.WHITE}Path to Magisk-patched boot image:{Style.RESET_ALL}  "
    ).strip()

    if not patched_path_str:
        log_warn(
            "No path supplied.  "
            "Workflow paused — re-run and supply the patched image path."
        )
        stability.stop()
        return 0

    patched_path = Path(patched_path_str)
    if not patched_path.exists():
        log_error(f"File not found: {patched_path}")
        stability.stop()
        return 1

    # ── Step 4: validate patched image ───────────────────────────────
    try:
        hdr = patched_path.read_bytes()[:8]
    except OSError as exc:
        log_error(f"Cannot read patched image: {exc}")
        stability.stop()
        return 1

    if hdr[:8] != b"ANDROID!":
        log_error(
            f"Patched image does not start with 'ANDROID!' magic "
            f"(got {hdr[:8]!r}).  "
            f"This does not look like a valid Android boot image."
        )
        stability.stop()
        return 1

    patched_size = patched_path.stat().st_size
    log_ok(f"Patched image validated (ANDROID! magic OK)  {patched_size}B")

    # Size sanity — patched image should be within 10 % of the original dump.
    orig_size = boot_dump_path.stat().st_size if boot_dump_path.exists() else 0
    if orig_size and abs(patched_size - orig_size) / orig_size > 0.10:
        log_warn(
            f"Patched image size ({patched_size}B) differs from the original dump "
            f"({orig_size}B) by more than 10 %.\n"
            f"  This may mean the wrong boot.img was patched — proceed carefully."
        )

    # ── Step 5: optionally disable AVB ───────────────────────────────
    print(
        f"\n  {Fore.YELLOW}{Style.BRIGHT}"
        f"Disable AVB verification (strongly recommended){Style.RESET_ALL}\n"
        f"\n  If this device has AVB2.0 active (most Oppo/Realme/Vivo devices),\n"
        f"  flashing a custom boot image without disabling AVB will cause\n"
        f"  a 'Verification Error' bootloop.\n"
    )
    do_avb = input(
        f"  {Fore.CYAN}›{Style.RESET_ALL} "
        f"{Fore.WHITE}Disable AVB now? [Y/n]:  {Style.RESET_ALL}"
    ).strip().lower()

    avb_disabled = False
    if do_avb != "n":
        # Backup vbmeta first
        for cand in ["vbmeta", "vbmeta_a", "vbmeta_b"]:
            if gpt.find(cand):
                if not dumper.dump(cand):
                    log_warn(
                        f"vbmeta backup of '{cand}' failed — "
                        f"proceeding without a safety copy.  "
                        f"Flash the original vbmeta.img manually to restore if needed."
                    )
                break
        patcher      = AVBPatcher(brom, gpt)
        avb_disabled = patcher.disable_avb(force=True)
        if avb_disabled:
            log_ok("AVB disabled successfully.")
        else:
            log_warn(
                "AVB disable failed — check that vbmeta partition is present.\n"
                "  Continuing with boot flash — device MAY bootloop if AVB is active."
            )
    else:
        log_info("Skipping AVB disable — proceeding to boot flash.")

    # ── Step 6: flash patched boot ────────────────────────────────────
    log_info(f"Flashing patched boot to '{boot_name}'...")
    flasher = PartitionFlasher(brom, gpt, force=True)
    flash_ok = flasher.flash_partition(boot_name, patched_path)

    if not flash_ok:
        log_error("Flash of patched boot failed — device unchanged.")
        stability.stop()
        return 1

    log_ok(f"'{boot_name}' flashed successfully.")

    # ── Step 7: reboot ────────────────────────────────────────────────
    do_reboot = input(
        f"\n  {Fore.CYAN}›{Style.RESET_ALL} "
        f"{Fore.WHITE}Reboot to system now? [Y/n]:  {Style.RESET_ALL}"
    ).strip().lower()

    if do_reboot != "n":
        brom.reboot()
        log_ok("Rebooting device...")
    else:
        log_info("Skipping reboot — you can reboot manually.")

    stability.stop()

    print(
        f"\n  {Fore.GREEN}{Style.BRIGHT}Root workflow complete!{Style.RESET_ALL}\n"
        f"\n  After the device boots, open Magisk — if it shows 'Requires"
        f"\n  Additional Setup', tap OK and let it finish.  "
        f"Root should then be active.\n"
        f"\n  If the device bootloops: hold power + vol-down to enter BROM\n"
        f"  and flash the original {boot_name}.img from: {boot_dump_path}\n"
    )
    return 0


# ===========================================================================
#  WORKFLOW — VERIFY PARTITION
# ===========================================================================

def run_verify_partition(args: argparse.Namespace) -> int:
    """Readback and SHA256 compare partition vs local image. Read-only."""
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = args.debug
    VERBOSE_MODE = args.verbose or args.debug

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    name  = getattr(args, "verify_partition", None)
    image = getattr(args, "image", None)
    if not name or not image:
        log_error("--verify-partition requires both NAME and --image FILE.")
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw_dev, _usb_dev, brom, stability = result

    gpt = GPTReader(brom)
    if not gpt.read():
        stability.stop()
        return 1

    verifier = PartitionVerifier(brom, gpt)
    ok       = verifier.verify(name, Path(image))

    stability.stop()
    return 0 if ok else 1


# ===========================================================================
#  WORKFLOW — BACKUP CRITICAL PARTITIONS  [K]
# ===========================================================================

def run_backup_critical(args: argparse.Namespace) -> int:
    """
    Dump every safety-critical partition to disk in one operation.

    Partitions covered:
      boot / boot_a / boot_b        — kernel + ramdisk
      init_boot / init_boot_a/b     — Android 13+ GKI ramdisk
      recovery / recovery_a/b       — stock recovery
      vbmeta / vbmeta_a/b           — AVB verification flags
      vbmeta_system / vbmeta_vendor — sub-partition AVB tables
      nvram / nvdata / nvcfg        — IMEI, WiFi/BT MAC, RF calibration
      lk / lk_a / lk_b             — little kernel (bootloader stage 2)
      dtbo / dtbo_a / dtbo_b        — device tree overlays

    All dumps go to backup/<chipset_name>/ alongside any existing backups.
    """
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = getattr(args, "debug",   False)
    VERBOSE_MODE = getattr(args, "verbose", False) or DEBUG_MODE

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw_dev, _usb_dev, brom, stability = result

    gpt = GPTReader(brom)
    if not gpt.read():
        stability.stop()
        return 1

    chipset_label = (brom.chipset or {}).get("name", f"0x{brom.hw_code:04X}")
    backup_dir    = BACKUP_DIR / chipset_label
    backup_dir.mkdir(parents=True, exist_ok=True)

    CRITICAL_PARTS = [
        "boot",       "boot_a",       "boot_b",
        "init_boot",  "init_boot_a",  "init_boot_b",
        "recovery",   "recovery_a",   "recovery_b",
        "vbmeta",     "vbmeta_a",     "vbmeta_b",
        "vbmeta_system", "vbmeta_vendor",
        "nvram",      "nvram_a",      "nvram_b",
        "nvdata",     "nvdata_a",     "nvdata_b",
        "nvcfg",
        "lk",         "lk_a",         "lk_b",
        "dtbo",       "dtbo_a",       "dtbo_b",
    ]

    dumper = PartitionDumper(brom, gpt, backup_dir)
    log_info(f"Critical partition backup → {backup_dir}")
    found = done = 0
    for name in CRITICAL_PARTS:
        if not gpt.find(name):
            continue
        found += 1
        log_info(f"  Backing up '{name}'…")
        if dumper.dump(name):
            done += 1

    stability.stop()
    if not found:
        log_warn("No critical partitions found in GPT — nothing backed up.")
        return 0
    if done == found:
        log_ok(f"Critical backup complete — {done}/{found} partitions saved to {backup_dir}")
        return 0
    else:
        log_warn(f"Partial backup — {done}/{found} succeeded.  Check errors above.")
        return 1


# ===========================================================================
#  WORKFLOW — RESTORE BOOT / UN-ROOT  [L]
# ===========================================================================

def run_restore_boot(args: argparse.Namespace) -> int:
    """
    Restore the original (stock) boot image from a prior backup — un-roots
    the device and removes Magisk.

    Scans backup/ for *.img files whose names match known boot partitions,
    lets the user pick one, validates it (ANDROID! magic), flashes it back,
    and optionally restores the vbmeta backup (re-enables AVB).
    """
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = getattr(args, "debug",   False)
    VERBOSE_MODE = getattr(args, "verbose", False) or DEBUG_MODE

    # ── Scan for backed-up boot images ───────────────────────────────────
    BOOT_STEMS = {
        "boot", "boot_a", "boot_b",
        "init_boot", "init_boot_a", "init_boot_b",
    }
    candidates: List[Path] = []
    for p in sorted(BACKUP_DIR.rglob("*.img")):
        if p.stem in BOOT_STEMS:
            candidates.append(p)

    if candidates:
        print(
            f"\n  {Fore.CYAN}{Style.BRIGHT}Available boot backups:{Style.RESET_ALL}"
        )
        for i, p in enumerate(candidates, 1):
            size_kb = p.stat().st_size // 1024
            mtime   = time.strftime("%Y-%m-%d %H:%M",
                                    time.localtime(p.stat().st_mtime))
            rel = p.relative_to(BACKUP_DIR) if BACKUP_DIR in p.parents else p
            print(
                f"  {Fore.CYAN}[{i}]{Style.RESET_ALL}  "
                f"{Fore.WHITE}{rel}{Style.RESET_ALL}"
                f"  {Fore.WHITE}{Style.DIM}({size_kb} KiB · {mtime}){Style.RESET_ALL}"
            )
        print(f"  {Fore.WHITE}{Style.DIM}[0]  Cancel{Style.RESET_ALL}")

        try:
            sel = input(f"\n  {Fore.CYAN}›{Style.RESET_ALL} Select backup: ").strip()
        except (EOFError, KeyboardInterrupt):
            return 0
        if sel == "0" or not sel:
            log_warn("Restore cancelled.")
            return 0
        try:
            restore_img = candidates[int(sel) - 1]
        except (ValueError, IndexError):
            log_error("Invalid selection.")
            return 1

    else:
        log_warn(
            f"No boot image backups found under {BACKUP_DIR}.\n"
            f"  Run option [K] 'Backup Critical Partitions' first, or\n"
            f"  enter the path to your original stock boot.img manually."
        )
        try:
            manual = input(
                f"\n  {Fore.CYAN}›{Style.RESET_ALL} "
                f"Path to boot.img (Enter to cancel): "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            return 0
        if not manual:
            return 0
        restore_img = Path(manual)

    if not restore_img.exists():
        log_error(f"File not found: {restore_img}")
        return 1

    # Derive partition name from filename stem
    part_name = restore_img.stem   # e.g. "boot_a" from "boot_a.img"

    # Quick magic validation
    try:
        magic = restore_img.read_bytes()[:8]
    except OSError as exc:
        log_error(f"Cannot read file: {exc}")
        return 1
    if not magic.startswith(b"ANDROID!"):
        log_warn(
            f"File does not start with ANDROID! magic — it may not be a valid "
            f"boot image.  Proceed with caution."
        )

    log_warn(
        f"About to overwrite '{part_name}' with:\n"
        f"  {restore_img}  ({restore_img.stat().st_size // 1024} KiB)\n"
        f"  This will REMOVE Magisk if the image is the stock original."
    )
    try:
        confirm = input(
            f"  {Fore.RED}{Style.BRIGHT}Proceed? [y/N]:  {Style.RESET_ALL}"
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return 0
    if confirm != "y":
        log_warn("Restore cancelled.")
        return 0

    # ── Connect to device and flash ───────────────────────────────────────
    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw_dev, _usb_dev, brom, stability = result

    gpt = GPTReader(brom)
    if not gpt.read():
        stability.stop()
        return 1

    flasher  = PartitionFlasher(brom, gpt, force=True)
    flash_ok = flasher.flash_partition(part_name, restore_img)

    if flash_ok:
        log_ok(f"'{part_name}' restored — Magisk removed.")

        # Offer to restore vbmeta too (re-enables AVB verification)
        vbmeta_cands: List[Path] = []
        for vn in ("vbmeta", "vbmeta_a", "vbmeta_b"):
            for p in BACKUP_DIR.rglob(f"{vn}.img"):
                vbmeta_cands.append(p)

        if vbmeta_cands:
            try:
                do_vb = input(
                    f"\n  {Fore.CYAN}›{Style.RESET_ALL} "
                    f"Also restore original vbmeta (re-enables AVB)? [y/N]:  "
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                do_vb = "n"
            if do_vb == "y":
                for vp in vbmeta_cands:
                    vpart = vp.stem
                    if gpt.find(vpart):
                        if flasher.flash_partition(vpart, vp):
                            log_ok(f"vbmeta '{vpart}' restored.")
                        else:
                            log_warn(f"vbmeta '{vpart}' restore failed.")

    # Offer reboot
    try:
        do_reboot = input(
            f"\n  {Fore.CYAN}›{Style.RESET_ALL} "
            f"Reboot to system now? [Y/n]:  "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        do_reboot = "n"
    if do_reboot != "n":
        brom.reboot()
        log_ok("Rebooting device…")

    stability.stop()
    return 0 if flash_ok else 1


# ===========================================================================
#  PRE-FLASH SAFETY CHECKLIST
# ===========================================================================

def _preflight_checklist(
    brom:           "BROMProtocol",
    gpt:            "GPTReader",
    partition_name: str,
    image_path:     Path,
    backup_dir:     Path,
) -> bool:
    """
    Run safety checks before any write operation.

    Returns True only when all *hard* checks pass (image fits partition).
    Soft warnings (missing backup, AVB advisory) are shown but do not block.
    """
    PASS = f"  {Fore.GREEN}[✔]{Style.RESET_ALL}"
    WARN = f"  {Fore.YELLOW}[!]{Style.RESET_ALL}"
    FAIL = f"  {Fore.RED}[✘]{Style.RESET_ALL}"
    print(
        f"\n  {Fore.CYAN}{Style.BRIGHT}"
        f"── Pre-Flash Safety Checklist ─────────────────────────{Style.RESET_ALL}"
    )
    all_ok = True

    # 1. Image readable
    try:
        img_size = image_path.stat().st_size
        print(f"{PASS} Image readable — {image_path.name}  ({img_size // 1024} KiB)")
    except OSError as exc:
        print(f"{FAIL} Cannot read image: {exc}")
        return False

    # 2. Image fits inside the GPT partition
    part = gpt.find(partition_name)
    if part:
        part_size = part.size_bytes
        if img_size <= part_size:
            print(f"{PASS} Image fits partition  "
                  f"({img_size // 1024} KiB ≤ {part_size // 1024} KiB)")
        else:
            print(f"{FAIL} Image EXCEEDS partition size  "
                  f"({img_size // 1024} KiB > {part_size // 1024} KiB) — "
                  f"aborting to prevent brick")
            all_ok = False
    else:
        print(f"{WARN} '{partition_name}' not found in GPT — size check skipped")

    # 3. NVRAM backed up somewhere under backup/
    nvram_ok = any(backup_dir.rglob("nvram.img")) or \
               any(backup_dir.rglob("nvdata.img"))
    if nvram_ok:
        print(f"{PASS} NVRAM backup exists")
    else:
        print(f"{WARN} No NVRAM backup — run [K] Backup Critical before any wipe")

    # 4. Boot backup exists when flashing boot
    boot_parts = {"boot", "boot_a", "boot_b", "init_boot", "init_boot_a", "init_boot_b"}
    if partition_name.lower() in boot_parts:
        boot_ok = any(backup_dir.rglob(f"{partition_name}.img"))
        if boot_ok:
            print(f"{PASS} Original '{partition_name}' backup exists")
        else:
            print(f"{WARN} No original '{partition_name}' backup — "
                  f"[L] Restore Boot won't be available if this goes wrong")
        print(f"{WARN} Confirm [I] Disable AVB was run before flashing a patched boot")

    print(f"  {Fore.CYAN}{'─' * 55}{Style.RESET_ALL}\n")
    return all_ok


# ===========================================================================
#  WORKFLOW — USB AUTO-WATCH  [S]
# ===========================================================================

def run_watch_mode(args: argparse.Namespace) -> int:
    """
    Poll the USB bus every 200 ms for an MTK device entering BROM mode.

    The moment an MTK BROM VID:PID is detected the tool announces it and
    (optionally) auto-triggers a workflow specified by --watch-action.
    Press Ctrl-C to cancel.
    """
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = getattr(args, "debug",   False)
    VERBOSE_MODE = getattr(args, "verbose", False) or DEBUG_MODE

    if not HAS_USB:
        log_error("pyusb not installed — USB watch not available.")
        return 1

    import usb.core as _usb_core

    BROM_PIDS = set(BROM_MODE_PIDS)
    print(
        f"\n  {Fore.CYAN}{Style.BRIGHT}"
        f"── Watch Mode — Waiting for MTK Device ──────────────────{Style.RESET_ALL}\n"
        f"\n  Polling USB every 200 ms for MediaTek BROM mode  (VID 0x0E8D)."
        f"\n  Put device into BROM mode: hold Vol↑ while plugging USB."
        f"\n  {Fore.WHITE}{Style.DIM}Press Ctrl-C to cancel.{Style.RESET_ALL}\n"
    )

    seen_serial: Optional[str] = None
    dot = 0
    try:
        while True:
            devs = list(_usb_core.find(find_all=True, idVendor=MTK_VID) or [])
            for dev in devs:
                if dev.idProduct in BROM_PIDS:
                    serial = f"{dev.bus}:{dev.address}"
                    if serial != seen_serial:
                        seen_serial = serial
                        print(
                            f"\n\n  {Fore.GREEN}{Style.BRIGHT}"
                            f"✔ MTK BROM device detected!{Style.RESET_ALL}"
                            f"  PID=0x{dev.idProduct:04X}"
                            f"  Bus={dev.bus} Dev={dev.address}\n"
                        )
                        action = getattr(args, "watch_action", None)
                        if   action == "backup": return run_backup_critical(args)
                        elif action == "info":   return run_device_info(args)
                        elif action == "root":   return run_root_device(args)
                        else:
                            log_ok("Device ready — you can now run any operation.")
                            return 0
            dot = (dot + 1) % 4
            print(f"\r  {Fore.WHITE}{Style.DIM}Watching"
                  f"{'.' * dot}{'   '[:4-dot]}{Style.RESET_ALL}",
                  end="", flush=True)
            time.sleep(0.2)
    except KeyboardInterrupt:
        print(f"\n\n  {Fore.YELLOW}Watch mode cancelled.{Style.RESET_ALL}\n")
        return 0


# ===========================================================================
#  WORKFLOW — PARTITION MAP VISUALIZER  [P]
# ===========================================================================

def run_partition_map(args: argparse.Namespace) -> int:
    """
    Display an ASCII bar-chart partition map with proportional sizes.

    Colour coding:
      Red    — write-protected (preloader, lk, seccfg …)
      Green  — backup exists in backup/
      Cyan   — both protected AND backed up
      White  — normal, no backup
    """
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = getattr(args, "debug",   False)
    VERBOSE_MODE = getattr(args, "verbose", False) or DEBUG_MODE

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw, _usb, brom, stability = result

    gpt = GPTReader(brom)
    if not gpt.read():
        stability.stop()
        return 1

    parts = sorted(gpt.partitions, key=lambda p: p.size_bytes, reverse=True)
    stability.stop()

    if not parts:
        log_warn("No partitions found.")
        return 0

    backed: Set[str] = {p.stem for p in BACKUP_DIR.rglob("*.img")}
    max_sz  = max(p.size_bytes for p in parts) or 1
    BAR_W   = 38

    print(
        f"\n  {Fore.CYAN}{Style.BRIGHT}"
        f"── Partition Map ─────────────────────────────────────────────{Style.RESET_ALL}\n"
        f"  {'Name':<22} {'Size':>9}   Map (proportional to largest)\n"
        f"  {Fore.WHITE}{Style.DIM}{'─' * 74}{Style.RESET_ALL}"
    )

    for p in parts:
        is_prot  = p.name.lower() in PROTECTED_PARTITIONS
        has_bk   = p.name in backed
        bar_len  = max(1, int(BAR_W * p.size_bytes / max_sz))
        bar      = "█" * bar_len

        if   is_prot and has_bk: color = Fore.CYAN
        elif is_prot:             color = Fore.RED
        elif has_bk:              color = Fore.GREEN
        else:                     color = Fore.WHITE

        sz = (f"{p.size_bytes//(1024**3):.1f}G" if p.size_bytes >= 1024**3
              else f"{p.size_bytes//(1024**2):.0f}M" if p.size_bytes >= 1024**2
              else f"{p.size_bytes//1024:.0f}K")

        tags = ("🔒" if is_prot else "") + ("✔" if has_bk else "")
        print(f"  {color}{p.name:<22}{Style.RESET_ALL} {sz:>9}   "
              f"{color}{bar}{Style.RESET_ALL} {tags}")

    print(
        f"\n  {Fore.WHITE}{Style.DIM}"
        f"🔒=write-protected  ✔=backup in backup/  "
        f"Cyan=both  Red=protected  Green=backed{Style.RESET_ALL}\n"
    )
    return 0


# ===========================================================================
#  WORKFLOW — NVRAM PARSE  [O]  (offline — no device needed)
# ===========================================================================

def run_nvram_parse(args: argparse.Namespace) -> int:
    """Parse a locally saved NVRAM dump and display IMEI / MAC addresses."""
    path_str = getattr(args, "nvram_parse", None)
    if not path_str:
        # Interactive: let user pick from backup/
        candidates = sorted(BACKUP_DIR.rglob("nvram*.img"))
        if not candidates:
            log_error(f"No nvram*.img found under {BACKUP_DIR}.  "
                      f"Run [K] Backup Critical first, or supply --nvram-parse <file>.")
            return 1
        print(f"\n  {Fore.CYAN}{Style.BRIGHT}Available NVRAM dumps:{Style.RESET_ALL}")
        for i, c in enumerate(candidates, 1):
            print(f"  [{i}]  {c.relative_to(BACKUP_DIR)}"
                  f"  ({c.stat().st_size // 1024} KiB)")
        try:
            sel = input(f"\n  {Fore.CYAN}›{Style.RESET_ALL} Select: ").strip()
            if not sel or sel == "0":
                return 0
            path = candidates[int(sel) - 1]
        except (ValueError, IndexError, EOFError, KeyboardInterrupt):
            return 0
    else:
        path = Path(path_str)

    if not path.exists():
        log_error(f"File not found: {path}")
        return 1

    raw = path.read_bytes()
    log_info(f"Parsing {path.name}  ({len(raw):,} bytes)…")
    NVRAMParser(raw).print_report()
    return 0


# ===========================================================================
#  WORKFLOW — BOOT IMAGE INSPECTOR  [N]  (offline — no device needed)
# ===========================================================================

def run_boot_inspect(args: argparse.Namespace) -> int:
    """Inspect a local boot.img and display header, kernel, and Magisk status."""
    path_str = getattr(args, "inspect_boot", None)
    if not path_str:
        # Interactive: list backed-up boot images
        candidates = sorted(
            p for p in BACKUP_DIR.rglob("*.img")
            if p.stem in {"boot", "boot_a", "boot_b",
                          "init_boot", "init_boot_a", "init_boot_b"}
        )
        if not candidates:
            log_error(f"No boot image backups under {BACKUP_DIR}.  "
                      f"Run [K] or supply --inspect-boot <file>.")
            return 1
        print(f"\n  {Fore.CYAN}{Style.BRIGHT}Available boot images:{Style.RESET_ALL}")
        for i, c in enumerate(candidates, 1):
            print(f"  [{i}]  {c.relative_to(BACKUP_DIR)}"
                  f"  ({c.stat().st_size // 1024} KiB)")
        try:
            sel = input(f"\n  {Fore.CYAN}›{Style.RESET_ALL} Select (or path): ").strip()
            if not sel or sel == "0":
                return 0
            if sel.isdigit():
                path = candidates[int(sel) - 1]
            else:
                path = Path(sel)
        except (ValueError, IndexError, EOFError, KeyboardInterrupt):
            return 0
    else:
        path = Path(path_str)

    if not path.exists():
        log_error(f"File not found: {path}")
        return 1

    BootImageInspector(path).print_report()
    return 0


# ===========================================================================
#  WORKFLOW — OTA PAYLOAD EXTRACTOR  [Q]  (offline — no device needed)
# ===========================================================================

def run_ota_extract(args: argparse.Namespace) -> int:
    """Extract partition images from an Android OTA payload.bin (or .zip)."""
    source_str = getattr(args, "ota_extract", None)
    if not source_str:
        try:
            source_str = input(
                f"  {Fore.CYAN}›{Style.RESET_ALL} "
                f"Path to OTA zip or payload.bin: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            return 0
    if not source_str:
        return 0

    source  = Path(source_str)
    if not source.exists():
        log_error(f"File not found: {source}")
        return 1

    out_dir_str = getattr(args, "out", None)
    out_dir = Path(out_dir_str) if out_dir_str else BACKUP_DIR / "ota_extracted"

    n = OTAPayloadExtractor(source, out_dir).extract()
    return 0 if n > 0 else 1


# ===========================================================================
#  RECIPE RUNNER  [R] — execute a JSON automation script
# ===========================================================================

class RecipeRunner:
    """
    Execute a sequence of androidForge operations from a JSON recipe file.

    Recipe format::

        {
          "name": "Root Oppo A16",
          "device": "MT6765 (optional note)",
          "steps": [
            {"action": "backup_critical"},
            {"action": "disable_avb"},
            {"action": "flash",  "partition": "boot",
                                  "image": "magisk_patched.img"},
            {"action": "verify", "partition": "boot",
                                  "image": "magisk_patched.img"},
            {"action": "reboot", "mode": "normal"}
          ]
        }

    Supported actions:
      backup_critical  — run [K] critical backup
      disable_avb      — run [I] disable AVB
      flash            — flash a partition  (requires partition + image)
      verify           — verify partition vs image  (requires partition + image)
      dump             — dump partitions  (requires partitions list or "all")
      reboot           — reboot device  (requires mode: normal/recovery/fastboot)
      root             — run full [J] root workflow (interactive)
      restore_boot     — run [L] restore boot
    """

    def __init__(self, recipe_path: Path, base_args: argparse.Namespace) -> None:
        self.path      = recipe_path
        self.base_args = base_args
        self._parser   = build_parser()

    def _make_args(self, **kwargs: Any) -> argparse.Namespace:
        """Clone base_args and overlay keyword fields."""
        ns = argparse.Namespace(**vars(self.base_args))
        for k, v in kwargs.items():
            setattr(ns, k, v)
        return ns

    def run(self) -> int:
        try:
            with open(self.path, encoding="utf-8") as fh:
                recipe = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            log_error(f"Cannot load recipe: {exc}")
            return 1

        name  = recipe.get("name", self.path.name)
        steps = recipe.get("steps", [])
        if not steps:
            log_warn("Recipe has no steps.")
            return 0

        # SEC-5: Cap step count to prevent runaway or adversarial recipes.
        _MAX_RECIPE_STEPS = 100
        if len(steps) > _MAX_RECIPE_STEPS:
            log_error(
                f"Recipe has {len(steps)} steps; maximum is {_MAX_RECIPE_STEPS}.  "
                f"Refusing to execute."
            )
            return 1

        print(
            f"\n  {Fore.CYAN}{Style.BRIGHT}"
            f"── Recipe: {name} ─────────────────────────────{Style.RESET_ALL}\n"
            f"  {len(steps)} step(s) — executing in order\n"
        )

        for i, step in enumerate(steps, 1):
            action = step.get("action", "").lower()
            print(f"  {Fore.CYAN}[{i}/{len(steps)}]{Style.RESET_ALL} {action}…")

            rc = self._run_step(action, step)
            if rc != 0:
                log_error(f"Step {i} '{action}' failed (rc={rc}) — recipe aborted.")
                return rc
            log_ok(f"  Step {i} done.")

        log_ok(f"Recipe '{name}' completed successfully.")
        return 0

    # SEC-6: Explicit allowlist of permitted recipe actions.
    _ALLOWED_ACTIONS: Set[str] = {
        "backup_critical", "disable_avb", "flash", "verify",
        "dump", "reboot", "root", "restore_boot",
    }

    @staticmethod
    def _validate_partition_name(name: str, step_label: str) -> bool:
        """Return True only if name is a safe partition identifier."""
        if not name or not _SAFE_NAME_RE.match(name):
            log_error(
                f"Recipe '{step_label}': invalid partition name {name!r}.  "
                f"Allowed pattern: [a-zA-Z0-9_-]{{1,64}}"
            )
            return False
        return True

    @staticmethod
    def _validate_image_path(path_str: str, step_label: str) -> bool:
        """Return True only if path_str is a safe image file path."""
        if not path_str:
            log_error(f"Recipe '{step_label}': 'image' is required.")
            return False
        # Block null bytes and path traversal sequences
        if "\x00" in path_str or ".." in path_str.split("/") or ".." in path_str.split("\\"):
            log_error(
                f"Recipe '{step_label}': image path {path_str!r} "
                f"contains illegal sequences (null bytes or '..')."
            )
            return False
        return True

    def _run_step(self, action: str, step: Dict[str, Any]) -> int:
        a = self.base_args

        # SEC-6: Reject any action not in the explicit allowlist.
        if action not in self._ALLOWED_ACTIONS:
            log_error(
                f"Recipe action '{action}' is not permitted.  "
                f"Allowed: {', '.join(sorted(self._ALLOWED_ACTIONS))}"
            )
            return 1

        if action == "backup_critical":
            return run_backup_critical(a)

        if action == "disable_avb":
            return run_disable_avb(a)

        if action == "flash":
            part  = step.get("partition", "")
            image = step.get("image", "")
            # SEC-7 + SEC-8: Validate partition name and image path.
            if not self._validate_partition_name(part, "flash"):
                return 1
            if not self._validate_image_path(image, "flash"):
                return 1
            ns = self._make_args(flash_only=True, flash_partition=part,
                                 flash_image=image)
            return run_flash_only(ns)

        if action == "verify":
            part  = step.get("partition", "")
            image = step.get("image", "")
            if not self._validate_partition_name(part, "verify"):
                return 1
            if not self._validate_image_path(image, "verify"):
                return 1
            ns = self._make_args(verify_partition=part, image=image)
            return run_verify_partition(ns)

        if action == "dump":
            parts = step.get("partitions", "")
            if parts == "all":
                ns = self._make_args(dump_all=True, partitions=None, dump=False)
            else:
                ns = self._make_args(dump_all=False,
                                     partitions=parts if parts else None,
                                     dump=bool(parts))
            return run_auto_workflow(ns)

        if action == "reboot":
            mode = step.get("mode", "normal")
            # Validate reboot mode against known safe values
            _SAFE_MODES = {"normal", "recovery", "fastboot", "download"}
            if mode not in _SAFE_MODES:
                log_error(
                    f"Recipe 'reboot': invalid mode {mode!r}.  "
                    f"Allowed: {', '.join(sorted(_SAFE_MODES))}"
                )
                return 1
            ns = self._make_args(reboot_mode=mode)
            return run_reboot(ns)

        if action == "root":
            ns = self._make_args(root_device=True)
            return run_root_device(ns)

        if action == "restore_boot":
            return run_restore_boot(a)

        # Unreachable after allowlist check above, but kept for safety.
        log_error(f"Unknown recipe action: '{action}'")
        return 1


def run_recipe(args: argparse.Namespace) -> int:
    """Load and execute a JSON recipe file."""
    path_str = getattr(args, "recipe", None)
    if not path_str:
        try:
            path_str = input(
                f"  {Fore.CYAN}›{Style.RESET_ALL} Path to recipe .json: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            return 0
    if not path_str:
        return 0
    path = Path(path_str)
    if not path.exists():
        log_error(f"Recipe file not found: {path}")
        return 1
    return RecipeRunner(path, args).run()


# ===========================================================================
#  [SHOCK] BROM MEMORY EXPLORER  [M]
#  Interactive hex viewer / writer for live BROM SRAM — CMD_READ32/WRITE32
# ===========================================================================

def run_brom_explorer(args: argparse.Namespace) -> int:
    """
    Interactive BROM SRAM memory explorer.

    After uploading the exploit payload, the BROM CPU is still live and
    CMD_READ32 (0xD1) can read arbitrary 32-bit values from any SRAM address.
    This function turns that into an interactive hex+ASCII memory viewer —
    like a hardware debugger attached directly to the chip.

    Commands (entered at the › prompt):
      n / Enter   — next page  (+256 bytes)
      p           — previous page  (-256 bytes)
      g <hex>     — jump to address  (e.g.  g 00100600)
      w <h> <v>   — write dword     (e.g.  w 00100000 DEADBEEF)
      s <text>    — search ASCII in next 64 KiB
      x <hex>     — find all occurrences of a dword value in next 64 KiB
      i           — show chipset SRAM / UART / payload addresses
      q           — quit

    What you can see:
      · Security registers (SBC / SLA / DAA flags)
      · Encryption keys left in SRAM by the ROM bootloader
      · Device calibration data loaded from NV
      · The live BROM stack frame
      · Custom payload code you uploaded
    """
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = getattr(args, "debug",   False)
    VERBOSE_MODE = getattr(args, "verbose", False) or DEBUG_MODE

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw, _usb, brom, stability = result

    # Starting address: chipset SRAM base or 0x00100000 (most MTK chips)
    sram_base = (brom.chipset or {}).get("sram_base", 0x00100000)
    addr      = sram_base
    PAGE      = 256   # bytes per screen (64 dwords × 4 bytes)
    COLS      = 4     # dwords per display row
    ROWS      = PAGE // (COLS * 4)   # = 16 rows

    def _read_page(base: int) -> List[Optional[int]]:
        """Read PAGE bytes as dwords; None on read error."""
        try:
            return brom.brom_read32(base, PAGE // 4)
        except Exception:
            return [None] * (PAGE // 4)

    def _render(base: int, dwords: List[Optional[int]]) -> None:
        print(
            f"\n  {Fore.CYAN}{Style.BRIGHT}"
            f"── BROM Memory Explorer ──  0x{base:08X}"
            f"  [{(brom.chipset or {}).get('name','?')}]{Style.RESET_ALL}\n"
            f"  {'Address':<12} {'Dwords (LE hex)':40} ASCII"
        )
        print(f"  {Fore.WHITE}{Style.DIM}{'─' * 70}{Style.RESET_ALL}")
        for row in range(ROWS):
            row_addr  = base + row * COLS * 4
            row_words = dwords[row * COLS: row * COLS + COLS]
            hex_parts = []
            raw_bytes = bytearray()
            for w in row_words:
                if w is None:
                    hex_parts.append(f"{Fore.RED}????????{Style.RESET_ALL}")
                    raw_bytes += b"\x00" * 4
                else:
                    # Colour non-zero dwords brighter
                    col = Style.BRIGHT if w else Style.DIM
                    hex_parts.append(f"{col}{w:08X}{Style.RESET_ALL}")
                    raw_bytes += struct.pack("<I", w)
            ascii_repr = "".join(
                chr(b) if 0x20 <= b < 0x7F else "."
                for b in raw_bytes
            )
            print(
                f"  {Fore.WHITE}0x{row_addr:08X}{Style.RESET_ALL}  "
                f"{'  '.join(hex_parts)}  "
                f"{Fore.GREEN}{ascii_repr}{Style.RESET_ALL}"
            )
        print(
            f"\n  {Fore.WHITE}{Style.DIM}"
            f"n=next  p=prev  g <addr>  w <addr> <val>  "
            f"s <text>  x <val>  i=info  q=quit"
            f"{Style.RESET_ALL}"
        )

    def _search_str(base: int, text: str) -> None:
        needle = text.encode("latin-1")
        log_info(f"Scanning 64 KiB from 0x{base:08X} for '{text}'…")
        try:
            words = brom.brom_read32(base, 65536 // 4)
        except Exception as exc:
            log_error(f"Read error: {exc}")
            return
        buf = b"".join(struct.pack("<I", w) for w in words)
        off = 0
        hits = 0
        while True:
            idx = buf.find(needle, off)
            if idx == -1:
                break
            print(f"  {Fore.GREEN}Found at 0x{base + idx:08X}{Style.RESET_ALL}")
            hits += 1
            off = idx + 1
        if hits == 0:
            log_warn("Not found in scanned range.")

    def _search_dword(base: int, val: int) -> None:
        log_info(f"Scanning 64 KiB from 0x{base:08X} for 0x{val:08X}…")
        try:
            words = brom.brom_read32(base, 65536 // 4)
        except Exception as exc:
            log_error(f"Read error: {exc}")
            return
        hits = [i for i, w in enumerate(words) if w == val]
        if not hits:
            log_warn("Value not found in scanned range.")
        for i in hits:
            print(f"  {Fore.GREEN}Found at 0x{base + i*4:08X}{Style.RESET_ALL}")

    # ── Main explorer loop ─────────────────────────────────────────────────
    print(
        f"\n  {Fore.CYAN}{Style.BRIGHT}"
        f"╔══════════════════════════════════════════════════════════╗\n"
        f"║        BROM MEMORY EXPLORER  — androidForge v1.5        ║\n"
        f"║  Reading live BROM SRAM via CMD_READ32 (0xD1)           ║\n"
        f"║  You are looking at real chip memory right now.         ║\n"
        f"╚══════════════════════════════════════════════════════════╝"
        f"{Style.RESET_ALL}\n"
    )

    while True:
        dwords = _read_page(addr)
        _render(addr, dwords)
        try:
            cmd = input(f"\n  {Fore.CYAN}›{Style.RESET_ALL} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if cmd in ("q", "quit"):
            break
        elif cmd in ("", "n", "next"):
            addr += PAGE
        elif cmd in ("p", "prev"):
            addr = max(0, addr - PAGE)
        elif cmd.startswith("g "):
            try:
                addr = int(cmd[2:].strip(), 16)
            except ValueError:
                log_warn("Usage:  g <hex_address>  e.g.  g 00100600")
        elif cmd.startswith("w "):
            parts = cmd[2:].split()
            if len(parts) != 2:
                log_warn("Usage:  w <hex_addr> <hex_val>  e.g.  w 00100000 DEADBEEF")
            else:
                try:
                    waddr = int(parts[0], 16)
                    wval  = int(parts[1], 16)

                    # SEC-12: Address range guard — warn loudly if write target
                    # is outside the expected SRAM window.  Writing to wrong
                    # addresses corrupts BROM state and requires power-cycle.
                    _SRAM_END = sram_base + 0x80000   # 512 KiB window
                    _in_range = sram_base <= waddr < _SRAM_END
                    if not _in_range:
                        print(
                            f"\n  {Fore.RED}{Style.BRIGHT}"
                            f"⚠  Address 0x{waddr:08X} is OUTSIDE the known SRAM "
                            f"range [0x{sram_base:08X} – 0x{_SRAM_END:08X}]."
                            f"\n  Writing here may corrupt BROM state and require "
                            f"a physical power-cycle to recover."
                            f"{Style.RESET_ALL}\n"
                        )
                        confirm_range = input(
                            f"  {Fore.RED}Type CONFIRM (uppercase) to proceed anyway: "
                            f"{Style.RESET_ALL}"
                        ).strip()
                        if confirm_range != "CONFIRM":
                            log_warn("Write cancelled (address out of range).")
                            continue

                    confirm = input(
                        f"  {Fore.RED}Write 0x{wval:08X} → 0x{waddr:08X}?  [y/N]: "
                        f"{Style.RESET_ALL}"
                    ).strip().lower()
                    if confirm == "y":
                        brom.brom_write32(waddr, wval)
                        log_ok(f"Written 0x{wval:08X} → 0x{waddr:08X}")
                    else:
                        log_warn("Write cancelled.")
                except ValueError:
                    log_warn("Invalid hex value.")
                except Exception as exc:
                    log_error(f"Write failed: {exc}")
        elif cmd.startswith("s "):
            _search_str(addr, cmd[2:].strip())
        elif cmd.startswith("x "):
            try:
                _search_dword(addr, int(cmd[2:].strip(), 16))
            except ValueError:
                log_warn("Usage:  x <hex_dword>  e.g.  x DEADBEEF")
        elif cmd == "i":
            cs = brom.chipset or {}
            print(
                f"\n  {Fore.CYAN}Chipset info:{Style.RESET_ALL}\n"
                f"  Name        : {cs.get('name', 'unknown')}\n"
                f"  SRAM base   : 0x{cs.get('sram_base', 0x00100000):08X}\n"
                f"  Payload addr: 0x{cs.get('payload_addr', 0x00200600):08X}\n"
                f"  UART base   : 0x{cs.get('uart', 0):08X}\n"
                f"  HW code     : 0x{brom.hw_code:04X}\n"
            )
        else:
            log_warn(f"Unknown command '{cmd}'.  "
                     "n/p/g/w/s/x/i/q — type 'q' to quit.")

    stability.stop()
    log_ok("BROM explorer closed.")
    return 0


# ===========================================================================
#  WORKFLOW — FORMAT PARTITION
# ===========================================================================

def run_format_partition(args: argparse.Namespace) -> int:
    """Zero-fill a single partition."""
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = args.debug
    VERBOSE_MODE = args.verbose or args.debug

    name = getattr(args, "format_partition", None)
    if not name:
        log_error("No partition name given for --format.")
        return 1

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw_dev, _usb_dev, brom, stability = result

    gpt = GPTReader(brom)
    if not gpt.read():
        stability.stop()
        return 1

    formatter = PartitionFormatter(brom, gpt, force=args.force)
    ok        = formatter.format_partition(name)

    stability.stop()
    return 0 if ok else 1


# ===========================================================================
#  WORKFLOW — WIPE USERDATA
# ===========================================================================

def run_wipe_userdata(args: argparse.Namespace) -> int:
    """
    Wipe userdata + metadata partitions with an extra explicit confirmation.

    Wipes: userdata, metadata (and persist if present).
    Requires typing the phrase 'WIPE USERDATA' to proceed.
    """
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = args.debug
    VERBOSE_MODE = args.verbose or args.debug

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw_dev, _usb_dev, brom, stability = result

    gpt = GPTReader(brom)
    if not gpt.read():
        stability.stop()
        return 1

    targets = [p for p in USERDATA_PARTITIONS if gpt.find(p)]
    if not targets:
        log_warn("No userdata partitions found in GPT.")
        stability.stop()
        return 0

    total_size = sum(
        (gpt.find(p) or type("", (), {"size_bytes": 0})()).size_bytes
        for p in targets
    )

    log_warn(
        f"This will permanently destroy all data in: "
        f"{', '.join(targets)} "
        f"({total_size // (1024**3):.1f} GB total)"
    )

    if not args.force:
        print(
            f"\n{Fore.RED}{Style.BRIGHT}"
            f"[DANGER] Type 'WIPE USERDATA' to permanently erase user data: "
            f"{Style.RESET_ALL}",
            end="",
        )
        if input().strip() != "WIPE USERDATA":
            log_warn("Wipe cancelled.")
            stability.stop()
            return 0

    # Auto-backup NVRAM before wipe — IMEI and RF calibration live here.
    # Losing this data causes permanent signal loss after the wipe.
    _chipset_lbl     = (brom.chipset or {}).get("name", f"0x{brom.hw_code:04X}")
    _nvram_backup_dir = BACKUP_DIR / _chipset_lbl
    _nvram_backup_dir.mkdir(parents=True, exist_ok=True)
    _auto_backup_nvram(brom, gpt, _nvram_backup_dir)

    formatter = PartitionFormatter(brom, gpt, force=True)
    all_ok    = True
    for name in targets:
        ok = formatter.format_partition(name)
        if not ok:
            log_error(f"Failed to wipe '{name}'.")
            all_ok = False

    stability.stop()
    if all_ok:
        log_ok("Userdata wipe complete.")
    return 0 if all_ok else 1


# ===========================================================================
#  WORKFLOW — FLASH ONLY
# ===========================================================================

def run_flash_only(args: argparse.Namespace) -> int:
    """Flash a single partition without dumping first."""
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = args.debug
    VERBOSE_MODE = args.verbose or args.debug

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw_dev, _usb_dev, brom, stability = result

    gpt = GPTReader(brom)
    if not gpt.read():
        stability.stop()
        return 1

    gpt.print_table()

    part_name  = args.flash_partition
    image_path = Path(args.flash_image)

    # Run pre-flash safety checklist
    if not _preflight_checklist(brom, gpt, part_name, image_path, BACKUP_DIR):
        stability.stop()
        return 1

    flasher = PartitionFlasher(brom, gpt, force=args.force)
    ok      = flasher.flash_partition(part_name, image_path)

    _al = ForgeAuditLog.get()
    if _al:
        _al.log_op("flash", partition=part_name,
                   image=str(image_path), ok=ok)

    stability.stop()
    return 0 if ok else 1


# ===========================================================================
#  WORKFLOW — REBOOT
# ===========================================================================

def run_reboot(args: argparse.Namespace) -> int:
    """Connect, initialise DA, send reboot command in specified mode."""
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = args.debug
    VERBOSE_MODE = args.verbose or args.debug

    mode = getattr(args, "reboot_mode", "normal") or "normal"
    valid_modes = ("normal", "recovery", "fastboot", "download")
    if mode not in valid_modes:
        log_error(f"Invalid reboot mode '{mode}'.  Choose: {valid_modes}")
        return 1

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw_dev, _usb_dev, brom, stability = result

    try:
        brom.reboot(mode)
    except Exception as exc:
        log_error(f"Reboot failed: {exc}")
        stability.stop()
        return 1

    stability.stop()
    return 0


# ===========================================================================
#  WORKFLOW — BATCH FLASH
# ===========================================================================

def run_batch_flash(args: argparse.Namespace) -> int:
    """
    Flash all *.img files from a directory, matching filenames to partition names.

    File matching: boot.img -> partition 'boot', recovery.img -> 'recovery', etc.
    Protected partitions are skipped automatically.
    """
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = args.debug
    VERBOSE_MODE = args.verbose or args.debug

    flash_dir = Path(getattr(args, "batch_flash", "."))
    if not flash_dir.is_dir():
        log_error(f"Batch flash directory not found: {flash_dir}")
        return 1

    images = sorted(flash_dir.glob("*.img"))
    if not images:
        log_error(f"No .img files found in {flash_dir}")
        return 1

    log_info(f"Batch flash directory: {flash_dir}")
    log_info(f"Found {len(images)} image(s):")
    for img in images:
        print(f"  {Fore.CYAN}{img.name}{Style.RESET_ALL}")

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw_dev, _usb_dev, brom, stability = result

    gpt = GPTReader(brom)
    if not gpt.read():
        stability.stop()
        return 1

    gpt.print_table()

    flasher  = PartitionFlasher(brom, gpt, force=args.force)
    results  : Dict[str, bool] = {}

    for img_path in images:
        part_name = img_path.stem   # boot.img -> boot

        if part_name.lower() in PROTECTED_PARTITIONS:
            log_warn(f"Skipping protected partition: {part_name}")
            results[part_name] = False
            continue

        if not gpt.find(part_name):
            log_warn(f"'{part_name}' not in GPT — skipping {img_path.name}")
            results[part_name] = False
            continue

        log_info(f"Flashing {img_path.name} -> '{part_name}'...")
        ok = flasher.flash_partition(part_name, img_path)
        results[part_name] = ok

        if not ok:
            # Stop immediately — a failed flash (especially a verify failure)
            # means the device is in an unknown state.  Flashing more
            # partitions on top of that can make recovery impossible.
            log_error(
                f"Flash of '{part_name}' FAILED — halting batch.\n"
                f"  Do not flash further partitions until the failed one\n"
                f"  is restored from backup."
            )
            stability.stop()
            ok_count = sum(1 for v in results.values() if v)
            log_done(f"Batch flash aborted: {ok_count}/{len(results)} partitions OK")
            return 2

    stability.stop()
    ok_count = sum(1 for v in results.values() if v)
    log_done(f"Batch flash: {ok_count}/{len(results)} partitions OK")
    return 0 if ok_count == len(results) else 2


# ===========================================================================
#  WORKFLOW — SCATTER FLASH
# ===========================================================================

def run_scatter(args: argparse.Namespace) -> int:
    """
    Parse a scatter file, display its contents, and optionally flash
    all downloadable entries (--scatter-flash).

    Scatter files are produced by SP Flash Tool and describe the
    partition layout and firmware file mapping for a specific device.
    """
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = args.debug
    VERBOSE_MODE = args.verbose or args.debug

    scatter_path = Path(getattr(args, "scatter", ""))
    if not scatter_path.exists():
        log_error(f"Scatter file not found: {scatter_path}")
        return 1

    scatter = ScatterParser(scatter_path)
    scatter.print_table()

    flashable = scatter.flashable()
    log_info(f"{len(flashable)} flashable entries in scatter file.")

    if not getattr(args, "scatter_flash", False):
        log_info("Pass --scatter-flash to actually flash these partitions.")
        return 0

    scatter_dir = scatter_path.parent

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    result = _setup_brom(args)
    if result is None:
        return 1
    _raw_dev, _usb_dev, brom, stability = result

    gpt = GPTReader(brom)
    if not gpt.read():
        stability.stop()
        return 1

    gpt.print_table()
    flasher  = PartitionFlasher(brom, gpt, force=args.force)
    results  : Dict[str, bool] = {}

    for entry in flashable:
        part_name = entry.get("partition_name", "")
        file_name = entry.get("file_name", "")
        img_path  = scatter_dir / file_name

        if not part_name or not file_name:
            continue

        if part_name.lower() in PROTECTED_PARTITIONS:
            log_warn(f"Scatter: skipping protected partition '{part_name}'")
            results[part_name] = False
            continue

        if not img_path.exists():
            log_warn(f"Scatter image not found: {img_path} — skipping '{part_name}'")
            results[part_name] = False
            continue

        log_info(
            f"[{len(results) + 1}/{len(flashable)}] "
            f"Scatter flashing '{part_name}' <- {file_name}..."
        )
        ok = flasher.flash_partition(part_name, img_path)
        results[part_name] = ok

        if not ok:
            log_error(
                f"Scatter flash of '{part_name}' FAILED — halting.\n"
                f"  Restore from backup before attempting further operations."
            )
            stability.stop()
            ok_count = sum(1 for v in results.values() if v)
            log_done(f"Scatter flash aborted: {ok_count}/{len(results)} partitions OK")
            return 2

    stability.stop()
    ok_count = sum(1 for v in results.values() if v)
    log_done(f"Scatter flash: {ok_count}/{len(results)} partitions OK")
    return 0 if ok_count == len(results) else 2


# ===========================================================================
#  KEY ACCESS SYSTEM
# ===========================================================================

# ── Configuration ──────────────────────────────────────────────────────────
KEY_ACCESS_TELEGRAM  = "GOODxVAMPIRE"          # Telegram username DMs go to
KEY_WHITELIST_URL    = (
    "https://raw.githubusercontent.com/"
    "projectgtp/androidForgeofficial/main/Key.txt"
)
KEY_PREFIX           = "AndroidForge-"
KEY_SUFFIX_LEN       = 8                        # chars after dash — 36^8 ≈ 2.8 trillion combos
KEY_NET_TIMEOUT      = 10                       # seconds for whitelist fetch

PAYLOAD_SOURCE_BASE  = (
    "https://raw.githubusercontent.com/"
    "bkerler/mtkclient/main/mtkclient/payloads/"
)
PAYLOAD_EXTRA_FILES  = [
    "da_x.bin", "da_xml.bin", "da_xml_64.bin",
    "pl.bin", "stage2.bin",
    "generic_dump_payload.bin",     "generic_loader_payload.bin",
    "generic_patcher_payload.bin",  "generic_preloader_dump_payload.bin",
    "generic_reboot_payload.bin",   "generic_sram_payload.bin",
    "generic_stage1_payload.bin",   "generic_uart_dump_payload.bin",
    "heapbait_arm.bin",             "heapbait_arm64.bin",
]


def _download_payload(filename: str) -> bool:
    """
    Download a single payload binary from the mtkclient GitHub mirror
    into PAYLOAD_DIR.  Returns True on success, False on any error.

    Security controls:
      • filename is validated to contain only safe characters (SEC-9)
      • Resolved destination is checked to stay inside PAYLOAD_DIR (SEC-9)
      • URL is validated against the trusted-host allowlist (SEC-10)
      • Downloaded payload is limited to 4 MiB (SEC-11)
    """
    # SEC-9: Validate filename — block traversal and shell meta-characters.
    if not re.match(r'^[a-zA-Z0-9_\-\.]{1,128}$', filename):
        log_warn(f"Skipping download: unsafe filename {filename!r}")
        return False
    if ".." in filename or filename.startswith("/"):
        log_warn(f"Skipping download: path traversal in filename {filename!r}")
        return False

    dest = PAYLOAD_DIR / filename
    # Confirm the resolved path is still inside PAYLOAD_DIR (symlink-safe)
    try:
        dest.resolve().relative_to(PAYLOAD_DIR.resolve())
    except ValueError:
        log_warn(f"Skipping download: resolved path escapes PAYLOAD_DIR: {dest}")
        return False

    url = PAYLOAD_SOURCE_BASE + filename

    # SEC-10: Validate URL is HTTPS to a trusted host.
    try:
        _assert_safe_url(url)
    except ValueError as exc:
        log_error(f"Refusing download — {exc}")
        return False

    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "androidForge/1.5"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            # SEC-11: Cap payload download at 4 MiB to prevent resource exhaustion.
            _MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
            data = resp.read(_MAX_PAYLOAD_BYTES + 1)
            if len(data) > _MAX_PAYLOAD_BYTES:
                log_error(
                    f"Payload {filename} exceeds {_MAX_PAYLOAD_BYTES // 1024} KiB "
                    f"size limit — refusing to write."
                )
                return False
        dest.write_bytes(data)
        log_ok(f"Downloaded: {filename} ({len(data)} bytes)")
        return True
    except urllib.error.HTTPError as exc:
        log_warn(f"HTTP {exc.code} — {filename} not available upstream.")
    except urllib.error.URLError as exc:
        log_warn(f"Network error downloading {filename}: {exc.reason}")
    except Exception as exc:
        log_warn(f"Download failed for {filename}: {exc}")
    return False


def run_download_payloads(args=None) -> int:
    """
    Download every known payload binary into PAYLOAD_DIR.
    Skips files that already exist and are non-empty.
    """
    chip_payloads = sorted({c["payload"] for c in CHIPSET_DB})
    all_files     = chip_payloads + [
        f for f in PAYLOAD_EXTRA_FILES if f not in chip_payloads
    ]
    total   = len(all_files)
    ok_ct   = 0
    skip_ct = 0
    fail_ct = 0

    print(
        f"\n  {Fore.CYAN}{Style.BRIGHT}Downloading {total} payload binaries "
        f"→ {PAYLOAD_DIR}{Style.RESET_ALL}"
    )
    print(f"  {Fore.WHITE}{Style.DIM}{'─' * _W}{Style.RESET_ALL}")

    for i, fname in enumerate(all_files, 1):
        dest = PAYLOAD_DIR / fname
        tag  = f"[{i:>2}/{total}]"
        if dest.exists() and dest.stat().st_size > 0:
            print(
                f"  {Fore.WHITE}{Style.DIM}{tag}  skip  {fname}{Style.RESET_ALL}"
            )
            skip_ct += 1
            continue
        print(
            f"  {Fore.CYAN}{tag}{Style.RESET_ALL}"
            f"  {Fore.WHITE}↓ {fname}{Style.RESET_ALL}",
            end="", flush=True,
        )
        if _download_payload(fname):
            size = (PAYLOAD_DIR / fname).stat().st_size
            print(f"  {Fore.GREEN}✓ {size} B{Style.RESET_ALL}")
            ok_ct += 1
        else:
            print(f"  {Fore.YELLOW}— not available{Style.RESET_ALL}")
            fail_ct += 1

    print(f"  {Fore.WHITE}{Style.DIM}{'─' * _W}{Style.RESET_ALL}")
    print(
        f"\n  {Fore.GREEN}{Style.BRIGHT}Done.{Style.RESET_ALL}"
        f"  {Fore.WHITE}Downloaded: {ok_ct}  "
        f"Already present: {skip_ct}  "
        f"Unavailable: {fail_ct}{Style.RESET_ALL}\n"
    )
    return 0


def _generate_device_key() -> str:
    """
    Produce a stable, device-specific key of the form AndroidForge-XXXXXXXX.

    Uses multiple hardware/OS fingerprint sources for stability.
    MAC address alone (uuid.getnode) changes when adapters switch or MAC
    randomization is on, so we layer in several more stable identifiers.

    Fingerprint sources (in priority order):
      • /etc/machine-id or /var/lib/dbus/machine-id  (Linux — most stable)
      • Windows MachineGuid from registry             (Windows — most stable)
      • platform.node()   — hostname
      • platform.system() — OS family
      • platform.machine()— CPU architecture
      • platform.version()— OS build version
      • uuid.getnode()    — MAC address (fallback, least stable)

    36^8 ≈ 2.8 trillion distinct values.
    """
    parts: List[str] = []

    # Linux: /etc/machine-id is written once at OS install, never changes
    for mid_path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            mid = Path(mid_path).read_text(encoding="utf-8").strip()
            if mid:
                parts.append(f"machine-id:{mid}")
                break
        except Exception:
            pass

    # Windows: MachineGuid is set at OS install time
    try:
        import winreg  # type: ignore
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
        ) as _k:
            guid, _ = winreg.QueryValueEx(_k, "MachineGuid")
            parts.append(f"win-guid:{guid}")
    except Exception:
        pass

    # macOS: IOPlatformUUID from ioreg
    if platform.system() == "Darwin":
        try:
            import subprocess as _sp
            out = _sp.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                timeout=3, stderr=_sp.DEVNULL,
            ).decode("utf-8", errors="ignore")
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    uid = line.split('"')[-2]
                    parts.append(f"ioreg:{uid}")
                    break
        except Exception:
            pass

    # Stable cross-platform fallbacks
    parts += [
        platform.node(),
        platform.system(),
        platform.machine(),
        platform.version(),
        str(os.getenv("USERNAME") or os.getenv("USER") or ""),
        str(uuid.getnode()),   # MAC — least stable, kept as tiebreaker
    ]

    raw    = "|".join(parts).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest().upper()
    suffix = "".join(c for c in digest if c.isalnum())[:KEY_SUFFIX_LEN]
    return f"{KEY_PREFIX}{suffix}"


def _fetch_whitelist() -> Optional[set]:
    """
    Download approved keys from GitHub.

    Returns a set of stripped, non-empty lines on success.
    Returns None on any network or HTTP error.
    """
    try:
        req = urllib.request.Request(
            KEY_WHITELIST_URL,
            headers={"User-Agent": "androidForge/1.5"},
        )
        with urllib.request.urlopen(req, timeout=KEY_NET_TIMEOUT) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        approved = {
            line.strip() for line in text.splitlines() if line.strip()
        }
        log_debug(f"Whitelist fetched: {len(approved)} approved key(s)")
        return approved
    except urllib.error.URLError as exc:
        log_debug(f"Whitelist fetch URLError: {exc}")
    except Exception as exc:
        log_debug(f"Whitelist fetch error: {exc}")
    return None


def _open_telegram(username: str, key: str = "") -> None:
    preset = ""
    if key:
        import urllib.parse
        msg    = f"Hi, my androidForge key is: {key} — please approve"
        preset = "?text=" + urllib.parse.quote(msg)

    tg_deep = f"tg://resolve?domain={username}"
    tg_url  = f"https://t.me/{username}{preset}"

    print(
        f"\n  {Fore.CYAN}Telegram link:{Style.RESET_ALL}  {tg_url}"
        f"\n  {Fore.YELLOW}(copy the link above if it does not open automatically){Style.RESET_ALL}"
    )
    try:
        opened = webbrowser.open(tg_url)
        if not opened:
            webbrowser.open(tg_deep)
    except Exception:
        pass


def check_key_access() -> bool:
    device_key = _generate_device_key()

    print(
        f"\n  {Fore.WHITE}{Style.DIM}Verifying access "
        f"·  {device_key}{Style.RESET_ALL}"
    )
    whitelist = _fetch_whitelist()

    if whitelist is not None and device_key in whitelist:
        KEY_FILE.write_text(device_key, encoding="utf-8")
        print(
            f"  {Fore.GREEN}{Style.BRIGHT}[OK]{Style.RESET_ALL}"
            f"  {Fore.WHITE}Access granted{Style.RESET_ALL}\n"
        )
        return True

    # Access blocked — compact inline header (logo already shown by main)
    print(
        f"\n  {Fore.MAGENTA}{Style.BRIGHT}"
        f"── Key Access {'─' * 44}{Style.RESET_ALL}"
    )

    if whitelist is None:
        print(
            f"\n  {Fore.YELLOW}[WARN] Could not reach the access server."
            f"\n         Check your internet connection and try again."
            f"{Style.RESET_ALL}"
        )
    else:
        print(
            f"\n  {Fore.RED}{Style.BRIGHT}ACCESS DENIED{Style.RESET_ALL}"
            f"\n  {Fore.YELLOW}Your key has not been approved yet.{Style.RESET_ALL}"
        )

    already_submitted = KEY_FILE.exists() and KEY_FILE.read_text(encoding="utf-8").strip() == device_key

    if already_submitted:
        print(
            f"\n{Fore.CYAN}{Style.BRIGHT}"
            "  ┌──────────────────────────────────────────────┐\n"
            "  │  Key submitted — waiting for approval        │\n"
            "  │                                              │\n"
            f"  │   {Fore.WHITE}{device_key:<44}{Fore.CYAN}│\n"
            "  │                                              │\n"
            "  │  1.  Resend key to Telegram                  │\n"
            "  │  2.  Exit                                    │\n"
            "  └──────────────────────────────────────────────┘"
            f"{Style.RESET_ALL}"
        )
    else:
        print(
            f"\n{Fore.CYAN}{Style.BRIGHT}"
            "  ┌──────────────────────────────────────────────┐\n"
            "  │  Access required                             │\n"
            "  │                                              │\n"
            "  │  1.  Generate key & request access           │\n"
            "  │  2.  Exit                                    │\n"
            "  └──────────────────────────────────────────────┘"
            f"{Style.RESET_ALL}"
        )

    while True:
        try:
            choice = input(
                f"\n  {Fore.WHITE}{Style.BRIGHT}Choose [1/2]: {Style.RESET_ALL}"
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

        if choice == "2":
            print(f"\n  {Fore.YELLOW}Exiting.{Style.RESET_ALL}")
            sys.exit(0)

        if choice == "1":
            break

        print(f"  {Fore.RED}Invalid choice — enter 1 or 2.{Style.RESET_ALL}")

    print(
        f"\n{Fore.YELLOW}{Style.BRIGHT}"
        "  ┌──────────────────────────────────────────────┐\n"
        "  │  Your device key:                            │\n"
        "  │                                              │\n"
        f"  │   {Fore.CYAN}{device_key:<44}{Fore.YELLOW}│\n"
        "  │                                              │\n"
        "  │  Send this key to the developer on Telegram. │\n"
        "  │  Once approved, run the tool again —         │\n"
        "  │  access will be granted instantly.           │\n"
        "  └──────────────────────────────────────────────┘"
        f"{Style.RESET_ALL}"
    )

    print(
        f"\n  {Fore.CYAN}Step 1:{Style.RESET_ALL}  Your key:"
        f"\n           {Fore.WHITE}{Style.BRIGHT}{device_key}{Style.RESET_ALL}"
        f"\n\n  {Fore.CYAN}Step 2:{Style.RESET_ALL}  Message the developer on Telegram:"
    )

    KEY_FILE.write_text(device_key, encoding="utf-8")

    _open_telegram(KEY_ACCESS_TELEGRAM, key=device_key)

    print(
        f"\n  {Fore.CYAN}Step 3:{Style.RESET_ALL}  After approval, run androidForge again."
        f"\n           Your key will be checked automatically.\n"
    )

    return False


# ===========================================================================
#  SEARCH ENGINE  (no USB needed)
# ===========================================================================

def _search_sla_risk(hw_code: int) -> str:
    """Return a short SLA/DAA bypass risk label for a chipset."""
    pre_sla  = {0x6572, 0x6580, 0x6582, 0x6592, 0x6595}
    low      = {0x6735, 0x6737, 0x6739, 0x6750, 0x6755,
                0x6757, 0x6758, 0x6761, 0x6762, 0x6763,
                0x6765, 0x6768, 0x6769, 0x8127, 0x8163,
                0x8167, 0x8173, 0x8321, 0x8765}
    medium   = {0x6771, 0x6779, 0x6785, 0x6789, 0x8183}
    if hw_code in pre_sla:
        return f"{Fore.GREEN}None  (pre-SLA era — unsigned payload OK){Style.RESET_ALL}"
    if hw_code in low:
        return f"{Fore.YELLOW}Low   (device-dependent — standard payload usually OK){Style.RESET_ALL}"
    if hw_code in medium:
        return f"{Fore.YELLOW}Med   (Helio G8x/G9x — signed payload may be needed){Style.RESET_ALL}"
    return     f"{Fore.RED}High  (Dimensity — Kamakiri-class payload often required){Style.RESET_ALL}"


def _search_ab_note(storage: str, hw_code: int) -> str:
    """Return an A/B slot support note."""
    pre_ab = {0x6572, 0x6580, 0x6582, 0x6592, 0x6595,
              0x6735, 0x6737, 0x6739}
    if hw_code in pre_ab:
        return "No  (too old — A-only partition layout)"
    if storage == "ufs":
        return "Yes (UFS Dimensity/Helio — modern A/B layout)"
    return "Likely on Android 9+ devices (check misc partition)"


def _search_matches(query: str) -> List[int]:
    """
    Return hw_codes from CHIPSET_DB whose chipset name, description,
    or known device list contains the query (case-insensitive).

    Special cases:
      • Pure hex  → "0x6765" or "6765" exact hw_code match
      • Pure int  → same as hex
      • "emmc" / "ufs"  → filter by storage type
      • Everything else  → substring match across name + description + devices
    """
    q = query.strip().lower()

    # ── Exact hw_code lookup (hex input: "0x6765" or "6765") ───────────────
    try:
        target = int(q, 16)
        if target in CHIPSET_DB:
            return [target]
    except ValueError:
        pass
    # ── Exact hw_code lookup (decimal input) ────────────────────────────────
    try:
        target = int(q)
        if target in CHIPSET_DB:
            return [target]
    except ValueError:
        pass

    # ── Substring search ───────────────────────────────────────────────────
    results: List[int] = []
    for hw_code, info in CHIPSET_DB.items():
        haystack = " ".join([
            info.get("name", ""),
            info.get("description", ""),
            info.get("storage", ""),
            " ".join(DEVICE_MAP.get(hw_code, [])),
        ]).lower()
        if q in haystack:
            results.append(hw_code)

    return sorted(results)


def _print_search_card(hw_code: int) -> None:
    """Print a single chipset capability card."""
    info    = CHIPSET_DB[hw_code]
    name    = info["name"]
    desc    = info["description"]
    storage = info["storage"].upper()
    payload = PAYLOAD_DIR / info["payload"]
    devices = DEVICE_MAP.get(hw_code, ["(no examples on record)"])

    payload_ok  = payload.exists()
    payload_tag = (
        f"{Fore.GREEN}Found  ({payload.name}){Style.RESET_ALL}"
        if payload_ok
        else f"{Fore.RED}Missing ({payload.name}){Style.RESET_ALL}"
    )

    # Service availability: most services need the payload
    def svc(label: str, needs_payload: bool = True,
            note: str = "", warn: bool = False) -> str:
        if not needs_payload:
            icon  = f"{Fore.GREEN}[YES]{Style.RESET_ALL}"
        elif payload_ok:
            icon  = f"{Fore.GREEN}[YES]{Style.RESET_ALL}"
        else:
            icon  = f"{Fore.YELLOW}[NEED PAYLOAD]{Style.RESET_ALL}"
        suffix = f"  {Fore.YELLOW}({note}){Style.RESET_ALL}" if note else ""
        warn_t = f"  {Fore.RED}⚠ {warn}{Style.RESET_ALL}" if warn else ""
        return f"    {icon}  {label}{suffix}{warn_t}"

    ab_note    = _search_ab_note(storage.lower(), hw_code)
    sla_note   = _search_sla_risk(hw_code)
    block_size = "4096 B (UFS)" if storage == "UFS" else "512 B (eMMC)"

    sep = f"{Fore.CYAN}{'─' * 66}{Style.RESET_ALL}"

    print(sep)
    print(
        f"  {Fore.CYAN}{Style.BRIGHT}{name}{Style.RESET_ALL}"
        f"  hw_code=0x{hw_code:04X}  storage={storage}  blocks={block_size}"
    )
    print(f"  {Fore.WHITE}{desc}{Style.RESET_ALL}")
    print()

    # ── Services ─────────────────────────────────────────────────────────
    print(f"  {Style.BRIGHT}Available services:{Style.RESET_ALL}")
    print(svc("Read security config (SBC/SLA/DAA flags)",
              needs_payload=False,
              note="--target-config — no payload required"))
    print(svc("List partitions (GPT table)"))
    print(svc("Dump partition(s) to file",
              note="--dump / --dump-all"))
    print(svc("Flash partition from image",
              note="--flash-only / --batch-flash / --scatter",
              warn="protected partitions are always blocked"))
    print(svc("Format / zero-erase partition",
              note="--format",
              warn="userdata requires --wipe-userdata"))
    print(svc("Verify partition vs image (SHA-256)",
              note="--verify-partition  read-only"))
    print(svc("Scatter-file flash (SP Flash Tool format)",
              note="--scatter --scatter-flash"))
    print(svc("Export full device info to JSON",
              note="--device-info"))
    print(svc("Reboot control (normal/recovery/fastboot/download)",
              note="--reboot"))

    # ── A/B Slots ────────────────────────────────────────────────────────
    ab_icon = (
        f"{Fore.GREEN}[YES]{Style.RESET_ALL}"
        if "Yes" in ab_note or "Likely" in ab_note
        else f"{Fore.YELLOW}[N/A]{Style.RESET_ALL}"
    )
    print(f"    {ab_icon}  Read A/B slot status      (--slot-info)")
    print(f"    {ab_icon}  Switch active A/B slot    (--switch-slot a|b)")
    print()

    # ── Security / notes ─────────────────────────────────────────────────
    print(f"  {Style.BRIGHT}Security / compatibility:{Style.RESET_ALL}")
    print(f"    SLA/DAA bypass risk : {sla_note}")
    print(f"    A/B slot support    : {ab_note}")
    print(f"    Payload on disk     : {payload_tag}")
    print()

    # ── Known devices (first 4, then summary) ────────────────────────────
    print(f"  {Style.BRIGHT}Known devices using this chipset:{Style.RESET_ALL}")
    for d in devices[:4]:
        print(f"    • {d}")
    if len(devices) > 4:
        print(f"    … and {len(devices) - 4} more")
    print()


def run_search(args: argparse.Namespace) -> int:
    """
    Search the chipset + device database by chipset name, hw_code,
    device name, brand, description keyword, or storage type.

    No USB connection required.  Key gate bypassed (informational only).

    Examples
    --------
      --search redmi          → all chipsets used in Redmi phones
      --search dimensity      → all Dimensity series chipsets
      --search 0x6765         → exact hw_code lookup
      --search ufs            → all UFS-storage chipsets
      --search "note 8 pro"   → device name substring
      --search samsung        → Samsung devices
    """
    query = getattr(args, "search", "").strip()
    if not query:
        log_error("--search requires a query.  Example: --search redmi")
        return 1

    print(
        f"\n{Fore.CYAN}{Style.BRIGHT}"
        f"androidForge — Device & Chipset Search Engine"
        f"{Style.RESET_ALL}"
    )
    print(
        f"  Database : {len(CHIPSET_DB)} chipsets  |  "
        f"{sum(len(v) for v in DEVICE_MAP.values())} device entries"
    )
    print(f"  Query    : {Fore.WHITE}{Style.BRIGHT}\"{query}\"{Style.RESET_ALL}\n")

    matches = _search_matches(query)

    if not matches:
        print(
            f"  {Fore.YELLOW}No results found for \"{query}\"."
            f"{Style.RESET_ALL}\n"
            f"  Try:\n"
            f"    • A chipset name     e.g. mt6765, helio, dimensity\n"
            f"    • A hw_code          e.g. 0x6765, 6765\n"
            f"    • A device brand     e.g. xiaomi, samsung, oppo, realme\n"
            f"    • A storage type     emmc  or  ufs\n"
            f"    • A model keyword    e.g. redmi note, galaxy a\n"
        )
        return 1

    print(
        f"  {Fore.GREEN}{Style.BRIGHT}"
        f"Found {len(matches)} chipset(s) matching \"{query}\":"
        f"{Style.RESET_ALL}\n"
    )

    for hw_code in matches:
        _print_search_card(hw_code)

    # ── Quick index at the bottom for multi-result queries ────────────────
    if len(matches) > 1:
        print(f"{Fore.CYAN}{'─' * 66}{Style.RESET_ALL}")
        print(
            f"\n  {Style.BRIGHT}Summary — {len(matches)} matching chipsets:{Style.RESET_ALL}"
        )
        for hw_code in matches:
            info    = CHIPSET_DB[hw_code]
            payload = PAYLOAD_DIR / info["payload"]
            tag     = (
                f"{Fore.GREEN}payload OK{Style.RESET_ALL}"
                if payload.exists()
                else f"{Fore.RED}no payload{Style.RESET_ALL}"
            )
            print(
                f"    0x{hw_code:04X}  "
                f"{Fore.CYAN}{info['name']:<10}{Style.RESET_ALL}  "
                f"{info['storage'].upper():<5}  "
                f"{info['description']:<38}  {tag}"
            )
        print()

    print(
        f"  {Fore.CYAN}Tip:{Style.RESET_ALL} Use "
        f"{Fore.WHITE}--list-chipsets{Style.RESET_ALL} for the full table, or "
        f"{Fore.WHITE}--target-config{Style.RESET_ALL} on a connected device\n"
        f"       to read live security flags (SBC/SLA/DAA) — no payload needed.\n"
    )
    return 0


# ===========================================================================
#  CHIPSET LIST  (no USB needed)
# ===========================================================================

def run_list_chipsets(_args: argparse.Namespace) -> int:
    """
    Print the full chipset support table — no USB connection required.
    Groups chipsets by era/family for easy reading.
    """
    print(
        f"\n{Fore.CYAN}{Style.BRIGHT}"
        f"androidForge v1.5 — Supported Chipsets ({len(CHIPSET_DB)} total)"
        f"{Style.RESET_ALL}"
    )
    print("-" * 72)
    print(
        f"{Fore.CYAN}{Style.BRIGHT}"
        f"  {'hw_code':<10} {'Name':<12} {'Storage':<8} Description"
        f"{Style.RESET_ALL}"
    )
    print("-" * 72)

    for hw_code in sorted(CHIPSET_DB):
        c       = CHIPSET_DB[hw_code]
        payload = PAYLOAD_DIR / c["payload"]
        have    = (
            f"{Fore.GREEN}payload OK{Style.RESET_ALL}"
            if payload.exists()
            else f"{Fore.RED}no payload{Style.RESET_ALL}"
        )
        print(
            f"  0x{hw_code:04X}     "
            f"{Fore.CYAN}{c['name']:<12}{Style.RESET_ALL}"
            f"{c['storage']:<8}"
            f"{c['description']:<34}  {have}"
        )

    print()
    log_info(
        f"Payload binaries go in: {PAYLOAD_DIR}\n"
        f"  Naming: <chipset_lower>_payload.bin  e.g. mt6765_payload.bin"
    )
    print()
    return 0


def run_target_config(args: argparse.Namespace) -> int:
    """
    Connect to BROM, read target config security register (0xD8), print and exit.

    Does NOT upload any payload — stops right after identification.
    This is useful for quickly finding out which security features are enabled
    before choosing which bypass technique or payload to use.
    """
    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = args.debug
    VERBOSE_MODE = args.verbose or args.debug

    if not HAS_USB:
        log_error("pyusb not installed.")
        return 1
    if not check_termux_usb():
        return 1

    raw_dev = find_mtk_device(timeout_s=args.wait_timeout)
    if raw_dev is None:
        return 1

    _claim_usb_interface(raw_dev)
    try:
        usb_dev = USBDevice(raw_dev)
    except RuntimeError as exc:
        log_error(f"USB endpoint error: {exc}")
        return 1

    brom = BROMProtocol(usb_dev)

    brom.enable_uart_log()

    if not brom.handshake():
        return 1

    hw_code = brom.get_hw_code()
    brom.get_hw_sw_ver()
    cfg = brom.get_target_config()

    print(
        f"\n{Fore.CYAN}{Style.BRIGHT}"
        f"Target Config — 0x{hw_code:04X} "
        f"({CHIPSET_DB.get(hw_code, {}).get('name', 'unknown')})"
        f"{Style.RESET_ALL}"
    )
    print("-" * 48)

    flag_info = {
        "sbc_enabled"    : ("SBC",  "Secure Boot Chain",          "Chain of trust enforced — all images must be signed"),
        "sla_enabled"    : ("SLA",  "Secure LA",                  "Payload auth required — use signed or Kamakiri payload"),
        "daa_enabled"    : ("DAA",  "Device Auth Agent",          "Device auth required — advanced bypass needed"),
        "sla_key_present": ("KEY",  "SLA Key in OTP",             "Device-unique auth key blown into OTP fuses"),
    }

    for key, (short, full, note) in flag_info.items():
        val   = cfg.get(key, False)
        color = Fore.RED if val else Fore.GREEN
        state = "ENABLED " if val else "disabled"
        print(
            f"  {color}{Style.BRIGHT}[{state}]{Style.RESET_ALL}  "
            f"{short:<5} {full:<26}  {note if val else ''}"
        )

    print()
    active = [k for k, v in cfg.items() if v is True and k != "raw"]
    if not active:
        log_ok("No security features active — standard unsigned payload will work.")
    else:
        log_warn(
            f"Security features active: {', '.join(active)}\n"
            f"  SLA/DAA active: use a Kamakiri-class signed payload\n"
            f"  SBC only: standard payload may work if BROM exception is present"
        )

    raw_cfg = cfg.get("raw", "N/A")
    print(f"  Raw config word: {raw_cfg}")
    print()
    return 0


def check_system_requirements() -> bool:
    """
    Display CPU, RAM, and disk readiness at startup.

    Checks:
      • CPU architecture  (x86_64 / ARM / ARM64)
      • CPU core count
      • Total RAM and available RAM
      • Available disk space in the current working directory

    Hard gate : < 4 GiB free  → prompt to abort
    Soft gate : < 8 GiB free  → warning only

    Returns False if the user chooses to abort; True otherwise.
    """
    GB     = 1024 ** 3
    MIN_GB = 4
    REC_GB = 8

    # ── CPU ──────────────────────────────────────────────────────────────────
    raw_arch = platform.machine().lower()
    if "aarch64" in raw_arch or "arm64" in raw_arch:
        arch = "ARM64"
    elif "arm" in raw_arch:
        arch = "ARM"
    elif raw_arch in ("x86_64", "amd64"):
        arch = "x86_64"
    elif "x86" in raw_arch or "i686" in raw_arch:
        arch = "x86 (32-bit)"
    else:
        arch = raw_arch.upper() or "Unknown"

    cores = os.cpu_count() or 0

    # ── RAM ───────────────────────────────────────────────────────────────────
    ram_total_b = 0
    ram_avail_b = 0
    try:
        import psutil as _psutil                    # type: ignore
        _vm         = _psutil.virtual_memory()
        ram_total_b = _vm.total
        ram_avail_b = _vm.available
    except Exception:
        # Fallback: /proc/meminfo (Linux / Android / Termux)
        try:
            with open("/proc/meminfo", "r") as _fh:
                for _line in _fh:
                    if _line.startswith("MemTotal:"):
                        ram_total_b = int(_line.split()[1]) * 1024
                    elif _line.startswith("MemAvailable:"):
                        ram_avail_b = int(_line.split()[1]) * 1024
        except Exception:
            pass

    # ── DISK ──────────────────────────────────────────────────────────────────
    cwd = Path.cwd()
    try:
        _du          = shutil.disk_usage(cwd)
        disk_free_b  = _du.free
        disk_total_b = _du.total
    except Exception:
        disk_free_b  = 0
        disk_total_b = 0

    disk_free_gb  = disk_free_b  / GB
    disk_total_gb = disk_total_b / GB
    ram_total_gb  = ram_total_b  / GB
    ram_avail_gb  = ram_avail_b  / GB

    # ── Colour helpers ────────────────────────────────────────────────────────
    def _ok(s):   return f"{Fore.GREEN}{Style.BRIGHT}{s}{Style.RESET_ALL}"
    def _warn(s): return f"{Fore.YELLOW}{Style.BRIGHT}{s}{Style.RESET_ALL}"
    def _fail(s): return f"{Fore.RED}{Style.BRIGHT}{s}{Style.RESET_ALL}"
    def _dim(s):  return f"{Fore.WHITE}{Style.DIM}{s}{Style.RESET_ALL}"
    def _hdr(s):  return f"{Fore.CYAN}{Style.BRIGHT}{s}{Style.RESET_ALL}"

    W = 60

    print(f"\n  {_hdr('──── System Requirements Check ' + '─' * 28)}")

    # ── System Hardware ───────────────────────────────────────────────────────
    print(f"\n  {_hdr('[ System Hardware ]')}")

    arch_tag = _ok(arch) if arch not in ("Unknown", "") else _warn(arch or "Unknown")
    print(f"  {'CPU Architecture':<28} {arch_tag}")

    core_tag = (_ok(str(cores)) if cores >= 2 else _warn(f"{cores}  (low core count)"))
    print(f"  {'CPU Cores':<28} {core_tag}")

    if ram_total_b:
        ram_total_str = f"{ram_total_gb:.1f} GiB"
        ram_avail_str = f"{ram_avail_gb:.1f} GiB available"
        ram_label     = f"{ram_total_str}  ({ram_avail_str})"
        ram_tag = _warn(ram_label + "  [LOW]") if ram_total_gb < 2 else _ok(ram_label)
    else:
        ram_tag = _dim("unavailable on this platform")
    print(f"  {'RAM':<28} {ram_tag}")

    # ── Storage Requirements ──────────────────────────────────────────────────
    print(f"\n  {_hdr('[ Storage Requirements ]')}")

    if disk_free_b:
        free_str  = f"{disk_free_gb:.1f} GiB free"
        total_str = f"{disk_total_gb:.1f} GiB total"
        if disk_free_gb >= REC_GB:
            disk_tag = _ok(f"{free_str} / {total_str}")
        elif disk_free_gb >= MIN_GB:
            disk_tag = _warn(
                f"{free_str} / {total_str}"
                f"  [recommend ≥{REC_GB} GiB for safe flashing]"
            )
        else:
            disk_tag = _fail(
                f"{disk_free_gb:.2f} GiB free / {total_str}"
                f"  [BELOW {MIN_GB} GiB minimum]"
            )
    else:
        disk_tag = _dim("unavailable")

    print(f"  {'Available Disk Space':<28} {disk_tag}")
    print(f"  {'Working Directory':<28} {_dim(str(cwd))}")
    print(f"  {'Minimum Required':<28} {_dim(f'{MIN_GB} GiB')}")
    print(f"  {'Recommended':<28} {_dim(f'{REC_GB} GiB+  (safe flashing)')}")

    print(f"\n  {'─' * W}")

    # ── Hard gate: < 4 GiB free ───────────────────────────────────────────────
    if disk_free_b and disk_free_gb < MIN_GB:
        print(
            f"\n  {_fail('WARNING:')} Free disk space is critically low "
            f"({disk_free_gb:.2f} GiB).\n"
            f"  Dump-all and flash operations may fail or corrupt device data.\n"
        )
        try:
            ans = input(
                f"  {Fore.YELLOW}Continue anyway?{Style.RESET_ALL} [y/N]: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans != "y":
            print(
                f"\n  {_fail('Aborted.')}  "
                f"Free up disk space and try again.\n"
            )
            return False

    # ── Soft gate: < 8 GiB free ──────────────────────────────────────────────
    elif disk_free_b and disk_free_gb < REC_GB:
        print(
            f"  {_warn('NOTE:')} Less than {REC_GB} GiB free — "
            f"large dump-all or batch-flash operations may fail mid-way.\n"
            f"  Consider freeing space before starting a full backup.\n"
        )

    return True


def check_dependencies() -> None:
    print(
        f"\n{Fore.CYAN}{Style.BRIGHT}"
        f"androidForge v1.5 — Dependency Status"
        f"{Style.RESET_ALL}"
    )
    print("-" * 42)
    try:
        import psutil as _psutil_chk   # noqa: F401
        _has_psutil = True
    except ImportError:
        _has_psutil = False
    deps = {
        "pyusb"    : HAS_USB,
        "pyserial" : HAS_SERIAL,
        "colorama" : HAS_COLOR,
        "tqdm"     : HAS_TQDM,
        "psutil"   : _has_psutil,   # used for RAM readout in system check
    }
    for name, present in deps.items():
        tag = (
            f"{Fore.GREEN}OK{Style.RESET_ALL}"
            if present
            else f"{Fore.RED}MISSING{Style.RESET_ALL}"
        )
        print(f"  {name:<14} {tag}")

    missing = [n for n, ok in deps.items() if not ok]
    if missing:
        print(
            f"\n{Fore.YELLOW}"
            f"Install: pip install {' '.join(missing)}"
            f"{Style.RESET_ALL}"
        )
    else:
        print(f"\n{Fore.GREEN}All dependencies satisfied.{Style.RESET_ALL}")
    print()


# ===========================================================================
#  CLI
# ===========================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="androidForge",
        description=(
            "androidForge v1.5 — Portable MediaTek BROM Dump, Flash & Management\n"
            "Inspired by mtkclient / SP Flash Tool / BROM forensic tools\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  List partitions:\n"
            "    python androidForge.py --list-partitions\n\n"
            "  Full device info (JSON export):\n"
            "    python androidForge.py --device-info\n\n"
            "  A/B slot status:\n"
            "    python androidForge.py --slot-info\n\n"
            "  Switch active slot to B:\n"
            "    python androidForge.py --switch-slot b\n\n"
            "  Dump auto-detected partitions:\n"
            "    python androidForge.py --dump\n\n"
            "  Dump all partitions:\n"
            "    python androidForge.py --dump-all\n\n"
            "  Verify partition vs local image:\n"
            "    python androidForge.py --verify-partition boot --image boot.img\n\n"
            "  Flash only:\n"
            "    python androidForge.py --flash-only --flash-partition boot"
            " --flash-image magisk_boot.img\n\n"
            "  Flash all images from directory:\n"
            "    python androidForge.py --batch-flash ./firmware/\n\n"
            "  Parse scatter file:\n"
            "    python androidForge.py --scatter scatter.txt\n\n"
            "  Flash from scatter file:\n"
            "    python androidForge.py --scatter scatter.txt --scatter-flash\n\n"
            "  Format (zero-fill) a partition:\n"
            "    python androidForge.py --format cache\n\n"
            "  Wipe userdata + metadata:\n"
            "    python androidForge.py --wipe-userdata\n\n"
            "  Reboot to recovery:\n"
            "    python androidForge.py --reboot recovery\n\n"
            "  Check dependencies:\n"
            "    python androidForge.py --check-deps\n"
        ),
    )

    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--dump",             action="store_true",
                      help="Dump specific/default partitions")
    mode.add_argument("--dump-all",         action="store_true",
                      help="Dump EVERY partition in the GPT")
    mode.add_argument("--list-partitions",  action="store_true",
                      help="Read GPT, print table, exit")
    mode.add_argument("--device-info",      action="store_true",
                      help="Print full device info and export to JSON")
    mode.add_argument("--slot-info",        action="store_true",
                      help="Read and display A/B slot status")
    mode.add_argument("--switch-slot",      metavar="SLOT",
                      help="Switch active A/B slot: a or b")
    mode.add_argument("--verify-partition", metavar="NAME",
                      help="SHA256 compare partition vs --image FILE (read-only)")
    mode.add_argument("--format",           metavar="NAME", dest="format_partition",
                      help="Zero-fill erase a partition (confirms before write)")
    mode.add_argument("--wipe-userdata",    action="store_true",
                      help="Zero-fill userdata + metadata (requires explicit phrase)")
    mode.add_argument("--flash-only",       action="store_true",
                      help="Flash a partition without dumping")
    mode.add_argument("--reboot",           metavar="MODE", dest="reboot_mode",
                      help="Reboot device: normal|recovery|fastboot|download")
    mode.add_argument("--batch-flash",      metavar="DIR",
                      help="Flash all *.img files from a directory")
    mode.add_argument("--scatter",          metavar="FILE",
                      help="Parse MTK scatter file (use --scatter-flash to flash)")
    mode.add_argument("--list-chipsets",    action="store_true",
                      help="Print all supported chipsets and payload status (no USB needed)")
    mode.add_argument("--search",           metavar="QUERY",
                      help="Search chipsets + devices by name, brand, hw_code, or keyword (no USB needed)")
    mode.add_argument("--target-config",   action="store_true",
                      help="Connect, read security flags (SBC/SLA/DAA), then exit — no payload uploaded")
    mode.add_argument("--check-deps",       action="store_true",
                      help="Show dependency status and exit")
    mode.add_argument("--disable-avb",      action="store_true",
                      help=(
                          "Disable Android Verified Boot: patches vbmeta flags "
                          "(HASHTREE_DISABLED | VERIFICATION_DISABLED) and zeroes "
                          "the auth block.  Auto-backs-up vbmeta before write.  "
                          "Required before flashing Magisk-patched boot on devices "
                          "with AVB2.0 (e.g. Oppo A16 / CPH2269 / MT6765)."
                      ))
    mode.add_argument("--root-device",      action="store_true",
                      help=(
                          "Interactive guided root workflow: dump active boot, "
                          "print Magisk patch instructions, disable AVB, flash "
                          "patched boot, reboot.  Minimum-footprint MTK root."
                      ))
    mode.add_argument("--watch",            action="store_true",
                      help="Poll USB every 200 ms for MTK BROM device; auto-trigger on detect.")
    mode.add_argument("--brom-explorer",    action="store_true", dest="brom_explorer",
                      help="[SHOCK] Interactive BROM SRAM hex viewer/writer via CMD_READ32.")
    mode.add_argument("--partition-map",    action="store_true", dest="partition_map",
                      help="Display proportional ASCII bar-chart of all GPT partitions.")
    mode.add_argument("--inspect-boot",     metavar="FILE",      dest="inspect_boot",
                      help="Parse a boot.img header and detect Magisk (offline, no device).")
    mode.add_argument("--nvram-parse",      metavar="FILE",      dest="nvram_parse",
                      help="Extract IMEI / WiFi+BT MAC from a raw NVRAM dump (offline).")
    mode.add_argument("--ota-extract",      metavar="FILE",      dest="ota_extract",
                      help="Extract partition images from OTA payload.bin or .zip (offline).")
    mode.add_argument("--recipe",           metavar="FILE",
                      help="Execute a JSON automation recipe (sequence of forge operations).")
    mode.add_argument("--watch-action",     metavar="ACTION",    dest="watch_action",
                      default=None,
                      help="Auto-trigger on watch detect: backup | info | root.")

    p.add_argument("--partitions",     metavar="LIST",
                   help="Comma-separated partitions to dump (default: boot,init_boot,vbmeta,recovery,dtbo)")
    p.add_argument("--flash-partition",metavar="NAME",
                   help="Partition name to flash")
    p.add_argument("--flash-image",    metavar="FILE",
                   help="Raw image to flash (use simg2img to convert sparse images first)")
    p.add_argument("--image",          metavar="FILE",
                   help="Local image file (used with --verify-partition)")
    p.add_argument("--scatter-flash",  action="store_true",
                   help="Actually flash entries from --scatter file")
    p.add_argument("--out",            metavar="FILE",
                   help="Output JSON path for --device-info")
    p.add_argument("--force",          action="store_true",
                   help="Skip interactive confirmations (use with care)")
    p.add_argument("--payload",        metavar="FILE",
                   help="Custom payload binary (overrides chipset auto-selection)")
    p.add_argument("--wait-timeout",   metavar="SECONDS", type=float, default=60.0,
                   help="Seconds to wait for BROM device (default: 60)")
    p.add_argument("--debug",          action="store_true",
                   help="Enable debug output and stack traces")
    p.add_argument("--verbose",        action="store_true",
                   help="Enable verbose USB I/O logging")

    return p


# ===========================================================================
#  LOGO
# ===========================================================================

def _print_logo() -> None:
    print(
        f"\n{Fore.MAGENTA}{Style.BRIGHT}"
        "  ╔═══════════════════════════════════════════════════════════╗\n"
        "  ║                                                           ║\n"
        "  ║    ░█████╗░███╗░░██╗██████╗░██████╗░░█████╗░██╗██████╗   ║\n"
        "  ║   ██╔══██╗████╗░██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗  ║\n"
        "  ║   ███████║██╔██╗██║██║░░██║██████╔╝██║░░██║██║██║░░██║  ║\n"
        "  ║   ██╔══██║██║╚████║██║░░██║██╔══██╗██║░░██║██║██║░░██║  ║\n"
        "  ║   ██║░░██║██║░╚███║██████╔╝██║░░██║╚█████╔╝██║██████╔╝  ║\n"
        "  ║   ╚═╝░░╚═╝╚═╝░░╚══╝╚═════╝ ╚═╝░░╚═╝░╚════╝ ╚═╝╚═════╝   ║\n"
        "  ║                                                           ║\n"
        f"  ║{Fore.CYAN}              F O R G E   v 1 . 5{Fore.MAGENTA}                          ║\n"
        f"  ║{Fore.WHITE}          by GOODxVAMPIRE  ·  MTK BROM Tool{Fore.MAGENTA}               ║\n"
        "  ║                                                           ║\n"
        "  ╚═══════════════════════════════════════════════════════════╝"
        f"{Style.RESET_ALL}\n"
    )


# ===========================================================================
#  INTERACTIVE MENU
# ===========================================================================

_W  = 62

def _menu_line(key: str, label: str, hint: str, kc=None, hc=None) -> str:
    kc  = kc  or (Fore.GREEN  + Style.BRIGHT)
    hc  = hc  or (Fore.WHITE  + Style.DIM)
    sep = f"{Fore.WHITE}{Style.DIM}·{Style.RESET_ALL}"
    return (
        f"  {Fore.WHITE}│{Style.RESET_ALL}  "
        f"{kc}[{key}]{Style.RESET_ALL}  "
        f"{Fore.WHITE}{Style.BRIGHT}{label:<30}{Style.RESET_ALL}  "
        f"{sep}  {hc}{hint}{Style.RESET_ALL}"
    )

def _menu_section(title: str, color=None) -> str:
    color = color or Fore.CYAN
    bar   = "─" * max(0, _W - len(title) - 3)
    return (
        f"\n  {color}{Style.BRIGHT}── {title} {bar}{Style.RESET_ALL}"
    )

def _menu_divider() -> str:
    return f"  {Fore.WHITE}{Style.DIM}{'─' * _W}{Style.RESET_ALL}"

def _sub_header(title: str) -> None:
    width = _W
    pad   = (width - len(title) - 2) // 2
    print(
        f"\n{Fore.CYAN}{Style.BRIGHT}"
        f"  ╔{'═' * (width)}╗\n"
        f"  ║{' ' * pad} {title} {' ' * (width - pad - len(title) - 1)}║\n"
        f"  ╚{'═' * (width)}╝"
        f"{Style.RESET_ALL}\n"
    )

def _ask(prompt: str, default: str = "") -> str:
    try:
        val = input(
            f"  {Fore.CYAN}›{Style.RESET_ALL} "
            f"{Fore.WHITE}{prompt}{Style.RESET_ALL}"
            + (f"  {Fore.WHITE}{Style.DIM}[{default}]{Style.RESET_ALL}" if default else "")
            + "  "
        ).strip()
        return val or default
    except (EOFError, KeyboardInterrupt):
        return ""

def _warn_box(lines: List[str]) -> None:
    w = max(len(l) for l in lines) + 4
    print(f"\n  {Fore.RED}{Style.BRIGHT}╔{'═' * w}╗")
    for l in lines:
        print(f"  ║  {l:<{w-2}}║")
    print(f"  ╚{'═' * w}╝{Style.RESET_ALL}")

def _ok_box(msg: str) -> None:
    w = len(msg) + 4
    print(
        f"\n"
        f"  {Fore.GREEN}{Style.BRIGHT}╔{'═' * w}╗\n"
        f"  ║  {msg}  ║\n"
        f"  ╚{'═' * w}╝"
        f"{Style.RESET_ALL}"
    )

def _cli_tip(cmd: str) -> None:
    print(
        f"\n  {Fore.WHITE}{Style.DIM}CLI equivalent: "
        f"{Fore.YELLOW}python androidForge.py {cmd}{Style.RESET_ALL}"
    )


def run_interactive_menu() -> int:
    parser     = build_parser()
    first_iter = True

    while True:
        if first_iter:
            first_iter = False
        else:
            _print_logo()

        print(_menu_section("READ-ONLY  ·  No writes to device", Fore.CYAN))
        print(_menu_line("1", "List Partitions",     "Show full GPT partition table"))
        print(_menu_line("2", "Device Info",         "Export chipset, storage, slots to JSON"))
        print(_menu_line("3", "Security Flags",      "Read SBC / SLA / DAA BROM registers"))
        print(_menu_line("4", "Search Chipsets",     "Find chipset by name, model or hw_code"))

        print(_menu_section("DUMP  ·  Read from device to disk", Fore.MAGENTA))
        print(_menu_line("5", "Dump Partitions",     "Dump boot/recovery/vbmeta/dtbo", Fore.MAGENTA + Style.BRIGHT))
        print(_menu_line("6", "Dump Everything",     "Full GPT backup — all partitions", Fore.MAGENTA + Style.BRIGHT))
        print(_menu_line("7", "Verify Partition",    "SHA256 compare device vs local image", Fore.MAGENTA + Style.BRIGHT))

        print(_menu_section("FLASH  ·  Write to device  [⚠ irreversible]", Fore.YELLOW))
        print(_menu_line("8", "Flash Partition",     "Write a single .img to named partition",  Fore.YELLOW + Style.BRIGHT, Fore.YELLOW + Style.DIM))
        print(_menu_line("9", "Batch Flash",         "Flash all .img files from a directory",   Fore.YELLOW + Style.BRIGHT, Fore.YELLOW + Style.DIM))
        print(_menu_line("A", "Scatter Flash",       "Flash using MTK SP Flash Tool .txt file", Fore.YELLOW + Style.BRIGHT, Fore.YELLOW + Style.DIM))

        print(_menu_section("MANAGE  ·  Device control  [⚠ destructive risk]", Fore.RED))
        print(_menu_line("B", "Format Partition",    "Zero-fill erase a single partition",  Fore.RED + Style.BRIGHT, Fore.RED + Style.DIM))
        print(_menu_line("C", "Wipe Userdata",       "Erase userdata + metadata partitions", Fore.RED + Style.BRIGHT, Fore.RED + Style.DIM))
        print(_menu_line("D", "A/B Slot Control",    "Read or switch active boot slot",      Fore.RED + Style.BRIGHT, Fore.RED + Style.DIM))
        print(_menu_line("E", "Reboot Device",       "Normal / Recovery / Fastboot / DL",   Fore.RED + Style.BRIGHT, Fore.RED + Style.DIM))

        print(_menu_section("SYSTEM", Fore.WHITE))
        print(_menu_line("F", "Check Dependencies",  "Verify pyusb, pyserial, colorama, tqdm",      Fore.WHITE + Style.BRIGHT, Fore.WHITE + Style.DIM))
        print(_menu_line("G", "List All Chipsets",   f"{len(CHIPSET_DB)} supported MTK chipsets + payload status",   Fore.WHITE + Style.BRIGHT, Fore.WHITE + Style.DIM))
        print(_menu_line("H", "Download All Payloads", "Fetch every .bin from mtkclient — auto-setup", Fore.GREEN + Style.BRIGHT, Fore.GREEN + Style.DIM))

        print(_menu_section("ROOT  ·  Unlock / AVB / Safety  [⚠ irreversible]", Fore.RED))
        print(_menu_line("I", "Disable AVB",         "Patch vbmeta flags → allow custom boot images",       Fore.RED    + Style.BRIGHT, Fore.RED    + Style.DIM))
        print(_menu_line("J", "Root Device",         "Guided Magisk root: dump → patch → flash → reboot",   Fore.RED    + Style.BRIGHT, Fore.RED    + Style.DIM))
        print(_menu_line("K", "Backup Critical",     "Dump boot/vbmeta/NVRAM/recovery in one shot",         Fore.MAGENTA + Style.BRIGHT, Fore.MAGENTA + Style.DIM))
        print(_menu_line("L", "Restore Boot/Un-root","Flash original boot from backup — removes Magisk",     Fore.YELLOW + Style.BRIGHT, Fore.YELLOW + Style.DIM))

        print(_menu_section("ADVANCED  ·  Analysis  ·  Automation  ·  Hardware debug", Fore.CYAN))
        print(_menu_line("M", "BROM Memory Explorer",  "[SHOCK] Live BROM SRAM hex viewer/writer via CMD_READ32",   Fore.CYAN  + Style.BRIGHT, Fore.CYAN  + Style.DIM))
        print(_menu_line("N", "Boot Image Inspector",  "Parse boot.img header + detect Magisk (offline)",            Fore.CYAN  + Style.BRIGHT, Fore.CYAN  + Style.DIM))
        print(_menu_line("O", "NVRAM Parser",          "Extract IMEI / WiFi+BT MAC from NVRAM dump (offline)",       Fore.CYAN  + Style.BRIGHT, Fore.CYAN  + Style.DIM))
        print(_menu_line("P", "Partition Map",         "ASCII bar-chart proportional view of all GPT partitions",    Fore.CYAN  + Style.BRIGHT, Fore.CYAN  + Style.DIM))
        print(_menu_line("Q", "OTA Extractor",         "Extract partition images from OTA payload.bin / .zip",       Fore.CYAN  + Style.BRIGHT, Fore.CYAN  + Style.DIM))
        print(_menu_line("R", "Run Recipe",            "Execute a JSON automation script (multi-step workflow)",     Fore.GREEN + Style.BRIGHT, Fore.GREEN + Style.DIM))
        print(_menu_line("S", "Watch for Device",      "Poll USB every 200 ms — auto-trigger on BROM detect",       Fore.GREEN + Style.BRIGHT, Fore.GREEN + Style.DIM))

        print(
            f"\n  {Fore.WHITE}{Style.DIM}{'─' * _W}{Style.RESET_ALL}"
            f"\n  {Fore.WHITE}│{Style.RESET_ALL}  "
            f"{Fore.WHITE}{Style.DIM}[0]  Exit{Style.RESET_ALL}"
            f"\n  {Fore.WHITE}{Style.DIM}{'─' * _W}{Style.RESET_ALL}"
        )

        try:
            choice = input(
                f"\n  {Fore.CYAN}{Style.BRIGHT}❯  {Style.RESET_ALL}"
                f"{Fore.WHITE}{Style.BRIGHT}Select option: {Style.RESET_ALL}"
            ).strip().upper()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {Fore.YELLOW}Goodbye.{Style.RESET_ALL}\n")
            return 0

        if choice == "0":
            print(f"\n  {Fore.YELLOW}Goodbye.{Style.RESET_ALL}\n")
            return 0

        # ── [1] List Partitions ──────────────────────────────────────────
        if choice == "1":
            _sub_header("List Partitions")
            _cli_tip("--list-partitions")
            run_list_partitions(parser.parse_args(["--list-partitions"]))

        # ── [2] Device Info ──────────────────────────────────────────────
        elif choice == "2":
            _sub_header("Device Info Export")
            _cli_tip("--device-info [--out device.json]")
            out = _ask("Save to JSON file? (press Enter to print to screen): ")
            argv = ["--device-info"]
            if out:
                argv += ["--out", out]
            run_device_info(parser.parse_args(argv))

        # ── [3] Security Flags ───────────────────────────────────────────
        elif choice == "3":
            _sub_header("Security Flags  ·  SBC / SLA / DAA")
            _cli_tip("--target-config")
            run_target_config(parser.parse_args(["--target-config"]))

        # ── [4] Search Chipsets ──────────────────────────────────────────
        elif choice == "4":
            _sub_header("Chipset Search")
            _cli_tip("--search <query>")
            q = _ask("Query (name / brand / hw_code / 'emmc' / 'ufs'): ")
            if not q:
                print(f"  {Fore.RED}No query entered — cancelled.{Style.RESET_ALL}")
            else:
                run_search(parser.parse_args(["--search", q]))

        # ── [5] Dump Partitions ──────────────────────────────────────────
        elif choice == "5":
            _sub_header("Dump Partitions")
            _cli_tip("--dump [--partitions boot,recovery,vbmeta,dtbo]")
            parts = _ask("Partition names (comma-sep) or Enter for defaults [boot,recovery,vbmeta,dtbo]: ")
            argv  = ["--dump"]
            if parts:
                argv += ["--partitions", parts]
            run_auto_workflow(parser.parse_args(argv))

        # ── [6] Dump Everything ──────────────────────────────────────────
        elif choice == "6":
            _sub_header("Full GPT Dump  ·  All Partitions")
            _cli_tip("--dump-all")
            print(
                f"\n  {Fore.YELLOW}{Style.BRIGHT}This will read every partition from the device."
                f"\n  Large storage may take several minutes.{Style.RESET_ALL}"
            )
            confirm = _ask("Proceed? [y/N]: ")
            if confirm.lower() != "y":
                print(f"  {Fore.YELLOW}Cancelled.{Style.RESET_ALL}")
            else:
                run_auto_workflow(parser.parse_args(["--dump-all"]))

        # ── [7] Verify Partition ─────────────────────────────────────────
        elif choice == "7":
            _sub_header("Verify Partition  ·  SHA256 Compare")
            _cli_tip("--verify-partition <name> --image <file>")
            pname  = _ask("Partition name: ")
            pimage = _ask("Local image file path: ")
            if not pname or not pimage:
                print(f"  {Fore.RED}Both fields required — cancelled.{Style.RESET_ALL}")
            else:
                run_verify_partition(parser.parse_args(
                    ["--verify-partition", pname, "--image", pimage]
                ))

        # ── [8] Flash Partition ──────────────────────────────────────────
        elif choice == "8":
            _sub_header("Flash Partition")
            _warn_box([
                "WRITE OPERATION — data will be overwritten on device.",
                "Make sure the image is correct before proceeding.",
            ])
            _cli_tip("--flash-only --flash-partition <name> --flash-image <file>")
            pname  = _ask("Partition name to flash (e.g. boot): ")
            pimage = _ask("Image file path (.img): ")
            if not pname or not pimage:
                print(f"  {Fore.RED}Both fields required — cancelled.{Style.RESET_ALL}")
            else:
                run_flash_only(parser.parse_args(
                    ["--flash-only", "--flash-partition", pname, "--flash-image", pimage]
                ))

        # ── [9] Batch Flash ──────────────────────────────────────────────
        elif choice == "9":
            _sub_header("Batch Flash  ·  Directory")
            _warn_box([
                "WRITE OPERATION — all matching .img files will be flashed.",
                "Protected partitions (preloader, lk, seccfg) are blocked.",
            ])
            _cli_tip("--batch-flash <directory>")
            d = _ask("Directory path containing .img files: ")
            if not d:
                print(f"  {Fore.RED}No path entered — cancelled.{Style.RESET_ALL}")
            else:
                run_batch_flash(parser.parse_args(["--batch-flash", d]))

        # ── [A] Scatter Flash ────────────────────────────────────────────
        elif choice == "A":
            _sub_header("Scatter Flash  ·  MTK SP Flash Tool Format")
            _cli_tip("--scatter <file> [--scatter-flash]")
            sf = _ask("Scatter file path (.txt): ")
            if not sf:
                print(f"  {Fore.RED}No file entered — cancelled.{Style.RESET_ALL}")
            else:
                do_flash = _ask("Flash entries now? [y/N]: ").lower() == "y"
                if do_flash:
                    _warn_box(["WRITE OPERATION — scatter entries will be flashed to device."])
                argv = ["--scatter", sf]
                if do_flash:
                    argv.append("--scatter-flash")
                run_scatter(parser.parse_args(argv))

        # ── [B] Format Partition ─────────────────────────────────────────
        elif choice == "B":
            _sub_header("Format Partition  ·  Zero-Fill Erase")
            _warn_box([
                "DESTRUCTIVE — all data in the partition will be zeroed.",
                "Protected partitions (preloader, lk, seccfg) are blocked.",
            ])
            _cli_tip("--format <partition>")
            pname = _ask("Partition name to zero-fill (e.g. userdata): ")
            if not pname:
                print(f"  {Fore.RED}No name entered — cancelled.{Style.RESET_ALL}")
            else:
                run_format_partition(parser.parse_args(["--format", pname]))

        # ── [C] Wipe Userdata ────────────────────────────────────────────
        elif choice == "C":
            _sub_header("Wipe Userdata")
            _warn_box([
                "DANGER — userdata and metadata will be permanently erased.",
                "All user apps, files and accounts on this device will be lost.",
            ])
            _cli_tip("--wipe-userdata")
            print(
                f"\n  {Fore.RED}{Style.BRIGHT}Type exactly:  "
                f"{Fore.WHITE}WIPE USERDATA{Fore.RED}  to confirm{Style.RESET_ALL}"
            )
            confirm = _ask("")
            if confirm != "WIPE USERDATA":
                print(f"  {Fore.YELLOW}Cancelled — phrase did not match.{Style.RESET_ALL}")
            else:
                run_wipe_userdata(parser.parse_args(["--wipe-userdata", "--force"]))

        # ── [D] A/B Slot Control ─────────────────────────────────────────
        elif choice == "D":
            _sub_header("A/B Slot Control")
            _cli_tip("--slot-info  |  --switch-slot [a|b]")
            print(
                f"\n  {Fore.CYAN}{Style.BRIGHT}"
                f"  [1]  Show current slot info\n"
                f"  [2]  Switch active slot to  A\n"
                f"  [3]  Switch active slot to  B\n"
                f"  [0]  Back{Style.RESET_ALL}"
            )
            sub = _ask("Select: ")
            if sub == "1":
                run_slot_info(parser.parse_args(["--slot-info"]))
            elif sub == "2":
                run_switch_slot(parser.parse_args(["--switch-slot", "a"]))
            elif sub == "3":
                _warn_box(["WRITE OPERATION — boot_ctrl in misc partition will be modified."])
                run_switch_slot(parser.parse_args(["--switch-slot", "b"]))
            elif sub != "0":
                print(f"  {Fore.RED}Invalid option.{Style.RESET_ALL}")

        # ── [E] Reboot Device ────────────────────────────────────────────
        elif choice == "E":
            _sub_header("Reboot Device")
            _cli_tip("--reboot [normal|recovery|fastboot|download]")
            print(
                f"\n  {Fore.CYAN}{Style.BRIGHT}"
                f"  [1]  Normal        — boot normally\n"
                f"  [2]  Recovery      — boot into recovery\n"
                f"  [3]  Fastboot      — boot into fastboot / bootloader\n"
                f"  [4]  Download      — MTK download / BROM mode\n"
                f"  [0]  Back{Style.RESET_ALL}"
            )
            sub      = _ask("Select: ")
            mode_map = {"1": "normal", "2": "recovery", "3": "fastboot", "4": "download"}
            if sub == "0":
                pass
            elif sub in mode_map:
                run_reboot(parser.parse_args(["--reboot", mode_map[sub]]))
            else:
                print(f"  {Fore.RED}Invalid option.{Style.RESET_ALL}")

        # ── [F] Check Dependencies ───────────────────────────────────────
        elif choice == "F":
            _sub_header("Dependency Check")
            _cli_tip("--check-deps")
            check_dependencies()

        # ── [G] List All Chipsets ─────────────────────────────────────────
        elif choice == "G":
            _sub_header("Supported Chipsets")
            _cli_tip("--list-chipsets")
            run_list_chipsets(parser.parse_args(["--list-chipsets"]))

        # ── [H] Download All Payloads ─────────────────────────────────────
        elif choice == "H":
            _sub_header("Download All Payloads")
            print(
                f"\n  {Fore.WHITE}Downloads every chipset payload binary from mtkclient"
                f"\n  into your local {Fore.CYAN}payloads/{Fore.WHITE} folder."
                f"\n  Already-present files are skipped automatically.{Style.RESET_ALL}"
            )
            confirm = _ask("\n  Start download? [y/N]: ")
            if confirm.lower() == "y":
                run_download_payloads()
            else:
                print(f"  {Fore.YELLOW}Cancelled.{Style.RESET_ALL}")

        # ── [I] Disable AVB ───────────────────────────────────────────────
        elif choice == "I":
            _sub_header("Disable AVB  ·  vbmeta Patcher")
            _warn_box([
                "WRITE OPERATION — vbmeta partition will be modified.",
                "Original vbmeta is auto-backed-up before any write.",
                "Required before flashing Magisk-patched boot on Oppo/Realme/Vivo.",
            ])
            _cli_tip("--disable-avb [--force]")
            print(
                f"\n  {Fore.WHITE}This patches the vbmeta partition to set\n"
                f"  HASHTREE_DISABLED | VERIFICATION_DISABLED flags (0x03).\n"
                f"  The original vbmeta is backed up automatically.\n"
                f"  Without this step, a Magisk-patched boot image will cause\n"
                f"  a 'Verification Error' bootloop on AVB2.0 devices.{Style.RESET_ALL}\n"
            )
            confirm = _ask("Proceed? [y/N]: ")
            if confirm.lower() == "y":
                run_disable_avb(parser.parse_args(["--disable-avb"]))
            else:
                print(f"  {Fore.YELLOW}Cancelled.{Style.RESET_ALL}")

        # ── [J] Root Device ───────────────────────────────────────────────
        elif choice == "J":
            _sub_header("Root Device  ·  Guided Magisk Workflow")
            _warn_box([
                "WRITE OPERATION — boot and optionally vbmeta will be modified.",
                "All writes are preceded by automatic partition backups.",
                "Tested workflow for MT6765 / Oppo A16 (CPH2269) and similar.",
            ])
            _cli_tip("--root-device")
            run_root_device(parser.parse_args(["--root-device"]))

        # ── [K] Backup Critical Partitions ────────────────────────────────
        elif choice == "K":
            _sub_header("Backup Critical Partitions")
            print(
                f"\n  {Fore.WHITE}Dumps the following to {Fore.CYAN}backup/<chipset>/{Fore.WHITE}:{Style.RESET_ALL}"
                f"\n  boot · vbmeta · recovery · nvram · nvdata · dtbo · lk"
                f"\n"
                f"\n  {Fore.YELLOW}{Style.BRIGHT}NVRAM holds your IMEI and radio calibration."
                f"\n  Back it up before ANY wipe or format operation.{Style.RESET_ALL}\n"
            )
            confirm = _ask("Proceed with critical backup? [y/N]: ")
            if confirm.lower() == "y":
                run_backup_critical(parser.parse_args([]))
            else:
                print(f"  {Fore.YELLOW}Cancelled.{Style.RESET_ALL}")

        # ── [L] Restore Boot / Un-root ────────────────────────────────────
        elif choice == "L":
            _sub_header("Restore Boot  ·  Un-root / Revert")
            _warn_box([
                "WRITE OPERATION — boot partition will be overwritten.",
                "Flashing the original stock boot removes Magisk root.",
                "Requires a backup in the backup/ directory (run [K] first).",
            ])
            run_restore_boot(parser.parse_args([]))

        # ── [M] BROM Memory Explorer ─────────────────────────────────────
        elif choice == "M":
            _sub_header("BROM Memory Explorer  ·  Live SRAM Hex Viewer")
            _cli_tip("--brom-explorer")
            print(
                f"\n  {Fore.CYAN}Reads live BROM SRAM via CMD_READ32 while the exploit "
                f"payload is active.\n"
                f"  You can browse memory, search strings/values, and write dwords.\n"
                f"\n  {Fore.YELLOW}{Style.BRIGHT}Research/advanced use only.  "
                f"Writing wrong values can crash the BROM session.{Style.RESET_ALL}\n"
            )
            confirm = _ask("Enter BROM Memory Explorer? [y/N]: ")
            if confirm.lower() == "y":
                run_brom_explorer(parser.parse_args([]))

        # ── [N] Boot Image Inspector ──────────────────────────────────────
        elif choice == "N":
            _sub_header("Boot Image Inspector  ·  Offline Analysis")
            _cli_tip("--inspect-boot <file>")
            print(
                f"\n  {Fore.WHITE}Parses an Android boot.img file and reports:\n"
                f"  • Header version (v0/v1/v2/v3-GKI)\n"
                f"  • Kernel version string and compression\n"
                f"  • OS version, board name, page size\n"
                f"  • {Fore.GREEN}Magisk detection{Style.RESET_ALL}"
                f"  (scans for magiskinit / magisk64 markers)\n"
            )
            run_boot_inspect(parser.parse_args([]))

        # ── [O] NVRAM Parser ──────────────────────────────────────────────
        elif choice == "O":
            _sub_header("NVRAM Parser  ·  Extract IMEI / MAC Addresses")
            _cli_tip("--nvram-parse <file>")
            print(
                f"\n  {Fore.WHITE}Scans a raw NVRAM dump (from [K] Backup Critical) and\n"
                f"  extracts IMEI values and WiFi/BT MAC addresses.\n"
                f"  No device connection required.\n"
            )
            run_nvram_parse(parser.parse_args([]))

        # ── [P] Partition Map ─────────────────────────────────────────────
        elif choice == "P":
            _sub_header("Partition Map  ·  Proportional ASCII Visualizer")
            _cli_tip("--partition-map")
            run_partition_map(parser.parse_args([]))

        # ── [Q] OTA Extractor ─────────────────────────────────────────────
        elif choice == "Q":
            _sub_header("OTA Payload Extractor")
            _cli_tip("--ota-extract <file>  [--out <dir>]")
            print(
                f"\n  {Fore.WHITE}Extracts partition images from an Android OTA package.\n"
                f"  Accepts a zipped OTA (.zip) or a bare payload.bin.\n"
                f"  REPLACE / REPLACE_XZ / REPLACE_BZ partitions are extracted.\n"
                f"  Delta (BSDIFF/IMGDIFF) partitions are listed but skipped.\n"
            )
            run_ota_extract(parser.parse_args([]))

        # ── [R] Run Recipe ────────────────────────────────────────────────
        elif choice == "R":
            _sub_header("Run Recipe  ·  JSON Automation Script")
            _cli_tip("--recipe <file.json>")
            print(
                f"\n  {Fore.WHITE}Executes a JSON recipe — an ordered sequence of androidForge\n"
                f"  operations run automatically: backup → disable_avb → flash → verify → reboot.\n"
                f"\n  Example recipe format:\n"
                f"  {Fore.WHITE}{Style.DIM}{{\n"
                f'    "name": "Root Oppo A16",\n'
                f'    "steps": [\n'
                f'      {{"action": "backup_critical"}},\n'
                f'      {{"action": "disable_avb"}},\n'
                f'      {{"action": "flash", "partition": "boot", "image": "patched.img"}},\n'
                f'      {{"action": "reboot", "mode": "normal"}}\n'
                f"    ]\n"
                f"  }}{Style.RESET_ALL}\n"
            )
            run_recipe(parser.parse_args([]))

        # ── [S] Watch for Device ──────────────────────────────────────────
        elif choice == "S":
            _sub_header("Watch for Device  ·  USB Auto-Detect")
            _cli_tip("--watch  [--watch-action backup|info|root]")
            print(
                f"\n  {Fore.WHITE}Polls USB every 200 ms for an MTK device in BROM mode.\n"
                f"  When detected, announces it.  Use --watch-action to auto-trigger\n"
                f"  backup / info / root immediately on detection.\n"
                f"\n  Put device into BROM mode:  hold Vol↑ while plugging USB.\n"
                f"  Press {Fore.YELLOW}Ctrl-C{Style.RESET_ALL} to cancel watching.\n"
            )
            run_watch_mode(parser.parse_args([]))

        else:
            print(
                f"\n  {Fore.RED}Unknown option  '{choice}'.{Style.RESET_ALL}"
                f"\n  {Fore.WHITE}{Style.DIM}Enter a key shown in the menu.{Style.RESET_ALL}"
            )

        _pause()

    return 0


def _pause() -> None:
    try:
        input(
            f"\n  {Fore.WHITE}{Style.DIM}{'─' * _W}{Style.RESET_ALL}"
            f"\n  {Fore.WHITE}{Style.DIM}Press Enter to return to menu...{Style.RESET_ALL}  "
        )
    except (EOFError, KeyboardInterrupt):
        pass


# ===========================================================================
#  ENTRY POINT
# ===========================================================================

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    global DEBUG_MODE, VERBOSE_MODE
    DEBUG_MODE   = args.debug
    VERBOSE_MODE = args.verbose or args.debug

    if DEBUG_MODE:
        _con_handler.setLevel(logging.DEBUG)

    if args.check_deps:
        _print_logo()
        check_dependencies()
        return 0

    if args.list_chipsets:
        _print_logo()
        return run_list_chipsets(args)

    if args.search:
        _print_logo()
        return run_search(args)

    no_mode_given = not any([
        args.dump, args.dump_all, args.list_partitions, args.device_info,
        args.slot_info, args.switch_slot, args.verify_partition,
        args.format_partition, args.wipe_userdata, args.flash_only,
        args.reboot_mode, args.batch_flash, args.scatter,
        args.target_config, args.disable_avb, args.root_device,
        getattr(args, "watch",          False),
        getattr(args, "brom_explorer",  False),
        getattr(args, "partition_map",  False),
        getattr(args, "inspect_boot",   None),
        getattr(args, "nvram_parse",    None),
        getattr(args, "ota_extract",    None),
        getattr(args, "recipe",         None),
    ])

    if no_mode_given:
        _print_logo()
        if not check_system_requirements():
            return 1
        if not check_key_access():
            return 1
        return run_interactive_menu()

    _print_logo()

    if not check_system_requirements():
        return 1

    if not check_key_access():
        return 1

    if args.target_config:
        return run_target_config(args)

    if args.disable_avb:
        return run_disable_avb(args)

    if args.root_device:
        return run_root_device(args)

    if args.list_partitions:
        return run_list_partitions(args)

    if args.device_info:
        return run_device_info(args)

    if args.slot_info:
        return run_slot_info(args)

    if args.switch_slot:
        return run_switch_slot(args)

    if args.verify_partition:
        return run_verify_partition(args)

    if args.format_partition:
        return run_format_partition(args)

    if args.wipe_userdata:
        return run_wipe_userdata(args)

    if args.reboot_mode:
        return run_reboot(args)

    if args.batch_flash:
        return run_batch_flash(args)

    if args.scatter:
        return run_scatter(args)

    if args.flash_only:
        if not (args.flash_partition and args.flash_image):
            parser.error(
                "--flash-only requires both --flash-partition and --flash-image"
            )
        return run_flash_only(args)

    if args.dump_all:
        return run_auto_workflow(args)

    if getattr(args, "watch", False):
        return run_watch_mode(args)

    if getattr(args, "brom_explorer", False):
        return run_brom_explorer(args)

    if getattr(args, "partition_map", False):
        return run_partition_map(args)

    if getattr(args, "inspect_boot", None):
        return run_boot_inspect(args)

    if getattr(args, "nvram_parse", None):
        return run_nvram_parse(args)

    if getattr(args, "ota_extract", None):
        return run_ota_extract(args)

    if getattr(args, "recipe", None):
        return run_recipe(args)

    # Default / --dump
    return run_auto_workflow(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[WARN] Interrupted by user.{Style.RESET_ALL}")
        sys.exit(130)
    except ForgeError as exc:
        log_error(f"Fatal error: {exc}")
        log_warn(f"Recovery hint: {exc.recovery}")
        if DEBUG_MODE:
            traceback.print_exc()
        sys.exit(1)
    except Exception as exc:
        log_error(f"Unhandled exception: {exc}")
        if DEBUG_MODE:
            traceback.print_exc()
        sys.exit(1)
