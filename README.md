# androidForge v1.2.0

A portable, command-line tool for managing MediaTek (MTK) Android devices via **BROM (Boot ROM)** mode. Supports dumping, flashing, formatting, and managing partitions and device configurations — all at the lowest hardware level, without requiring the device OS to be running.

> Inspired by [mtkclient](https://github.com/bkerler/mtkclient) and SP Flash Tool.

---

## Features

- **Partition Dumping** — Extract single or all partitions to disk (`--dump`, `--dump-all`)
- **Partition Flashing** — Write images to partitions with SP Flash Tool Scatter file support (`--flash-only`, `--batch-flash`, `--scatter`)
- **Partition Formatting** — Zero-fill erase partitions safely (`--format`, `--wipe-userdata`)
- **Partition Verification** — SHA256 readback comparison between local files and device (`--verify-partition`)
- **A/B Slot Management** — Read and switch Android A/B boot slots (`--slot-info`, `--switch-slot`)
- **Reboot Control** — Reboot into normal, recovery, fastboot, or download modes (`--reboot`)
- **Security Diagnostics** — Read BROM security registers (SBC, SLA, DAA flags) (`--target-config`)
- **Device Info Export** — Export chipset, storage type, slot config, and GPT to JSON (`--device-info`)
- **Chipset Search** — Built-in database to find supported chipsets and device models (`--search`)
- **Confirmation Gates** — All destructive write operations require explicit typed confirmation before any bytes are sent
- **Environment Check** — Confirms all required dependencies are installed and ready (`--check-deps`)

---

## Supported Platforms

| Platform | Notes |
|----------|-------|
| Windows  | Install MTK USB drivers from MediaTek, or use Zadig to bind WinUSB to VID=0x0E8D |
| Linux    | Add a udev rule for VID `0e8d` or run with `sudo` |
| macOS    | Run with `sudo` |
| Termux (Android OTG) | `pkg install python libusb` + Termux:USB from F-Droid |

---

## Requirements

- Python 3.8 or newer
- A MediaTek device in **BROM mode** (PID `0x0001` or `0x0003`)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/project gtp/androidForgeofficial.git
cd androidForgeofficial

# Install dependencies
pip install -r requirements.txt
```

**Linux udev rule (run once, no sudo needed after):**
```bash
echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="0e8d", MODE="0666"' \
  | sudo tee /etc/udev/rules.d/99-mtk.rules
sudo udevadm control --reload
```

**Verify your setup:**
```bash
python androidForge.py --check-deps
```

---

## Entering BROM Mode

BROM (Boot ROM) is the lowest-level USB mode on MediaTek devices. This tool **only** works in BROM mode.

**Standard method:**
1. Fully power off the device
2. Hold **Vol-Down** (some devices use Vol-Up)
3. While holding, connect the USB cable to your computer
4. Do not release until the device is detected

**Test Point method** (if Vol-Down doesn't work):
- Locate the BROM test point on the PCB, short it to GND while connecting USB

**Verify detection:**
```bash
# Linux/macOS
lsusb | grep "0e8d"

# Windows
Device Manager → Universal Serial Bus → MediaTek USB Port
```

---

## Usage

```
python androidForge.py [command] [options]
```

### Information & Diagnostics

```bash
python androidForge.py --identify              # Identify connected device
python androidForge.py --list-partitions       # List all GPT partitions
python androidForge.py --target-config         # Read SBC/SLA/DAA security flags
python androidForge.py --slot-info             # Show A/B slot status
python androidForge.py --device-info           # Export device info to JSON
python androidForge.py --device-info --out device.json
python androidForge.py --search mt6765         # Search chipset database
python androidForge.py --check-deps            # Verify dependencies
```

### Dump Partitions

```bash
python androidForge.py --dump boot             # Dump boot partition
python androidForge.py --dump-all              # Dump all partitions
python androidForge.py --dump boot --out boot.img
```

### Flash Partitions

```bash
python androidForge.py --flash-only boot --image boot.img
python androidForge.py --batch-flash ./images/          # Flash all images in a directory
python androidForge.py --scatter MT6765_Android_scatter.txt
python androidForge.py --scatter MT6765_Android_scatter.txt --scatter-flash
```

### Format & Erase

```bash
python androidForge.py --format userdata       # Zero-fill erase a partition
python androidForge.py --wipe-userdata         # Wipe userdata and cache
```

### Verify

```bash
python androidForge.py --verify-partition boot --image boot.img
```

### A/B Slot Control

```bash
python androidForge.py --slot-info             # Show current slot
python androidForge.py --switch-slot a         # Switch active slot to A
python androidForge.py --switch-slot b         # Switch active slot to B
```

### Reboot

```bash
python androidForge.py --reboot                # Reboot to normal
python androidForge.py --reboot recovery       # Reboot to recovery
python androidForge.py --reboot fastboot       # Reboot to fastboot
python androidForge.py --reboot download       # Reboot to download mode
```

### Global Flags

| Flag | Description |
|------|-------------|
| `--force` | Skip typed confirmation prompts (use in scripts) |
| `--verbose` | Enable detailed debug output |
| `--debug` | Full debug output with stack traces and USB I/O |
| `--out FILE` | Specify output file path |
| `--payload FILE` | Specify a custom bypass payload binary |
| `--wait-timeout N` | Seconds to wait for BROM device (default: 60) |

---

## Project Structure

```
androidForge/
├── androidForge.py     # Main tool (all logic)
├── requirements.txt    # Python dependencies
├── commands.txt        # Full command reference & user manual
├── payloads/           # MTK bypass payload binaries (.bin)
├── backup/             # Default location for dumped partition images
└── logs/               # Execution logs and JSON device exports
```

---

## Safety

- **Protected partitions** — Writes to `preloader`, `lk`, and `seccfg` are blocked by default to prevent bricking
- **Confirmation gates** — Write operations require typing a specific phrase (e.g. `ERASE`, `YES`, `WIPE USERDATA`) before executing
- **SHA256 verification** — Flash operations verify data integrity after writing
- **Access control** — Certain USB write operations require a hardware-locked developer key

> **Use this tool only on devices you own. You are fully responsible for any outcome.**

---

## Supported Chipsets

Run the built-in search to check compatibility:
```bash
python androidForge.py --search <chipset_or_model>
```

Common supported chipsets include MT6580, MT6735, MT6737, MT6750, MT6765, MT6768, MT6771, MT6779, MT6785, MT6853, MT6873, MT6877, MT6883, MT6885, MT6889, MT6893, and more.

---

## Author

**GOODxVAMPIRE**

---

## Disclaimer

This tool is intended for legitimate forensic, development, and personal device recovery use only. Misuse to bypass security on devices you do not own is illegal. The author assumes no liability for damages caused by improper use.
