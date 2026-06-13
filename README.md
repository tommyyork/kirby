# Kirby — Malware Response Scanner

Kirby is a modular malware analysis orchestrator for examining a mounted Windows disk image (typically a BitLocker-encrypted drive decrypted and mounted read-only on macOS). It runs **scan modules** against the target volume to find suspicious files, then optionally runs **analysis modules** to enrich those findings. Each module writes a Markdown report, and scan modules maintain a shared registry of flagged paths.

The intended workflow is:

1. Mount the target volume read-only (`mount_bitlocker.sh`).
2. Run scan modules with `-e` to populate `tmp/flagged.csv`.
3. Run analysis modules with `-a` to enrich flagged files (e.g. VirusTotal lookups).
4. Review Markdown reports in `output/` and the consolidated flag list in `tmp/flagged.csv`.

---

## Quick start

```bash
# One-time setup
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Mount the BitLocker volume (see mount_bitlocker.sh)
export BITLOCKER_RECOVERY_PASSWORD='...'
./mount_bitlocker.sh

# Scan, then analyze (verbose by default)
python kirby.py -t /Volumes/bitlocker -e Yara,oletools -a virustotal
```

External tools required depend on which modules you enable — see [Prerequisites](#prerequisites).

---

## Kirby CLI

```
usage: kirby.py [-h] [-t TARGET | -kext] [-e ENGINES] [-a ANALYSIS] [-o OUTPUT] [-s]
```

| Flag | Long form | Required | Default | Description |
|------|-----------|----------|---------|-------------|
| `-t` | `--target` | Yes* | — | Scan target directory (e.g. `/Volumes/bitlocker`) |
| `-kext` | — | No | off | Special target: enumerate installed kernel extensions on this Mac and pass them to scan engines |
| `-e` | `--engines` | No* | — | Comma-separated **scan** module names (e.g. `Yara,ClamAV,oletools`) |
| `-a` | `--analysis` | No* | — | Comma-separated **analysis** module names (e.g. `virustotal`) |
| `-o` | `--output` | No | `output/` | Directory for Markdown reports |
| `-s` | `--silent` | No | off | Suppress detailed progress logs and tqdm progress bars |

\*At least one of `-e` or `-a` must be provided. When running scan modules, provide either `-t` or `-kext` (not both).

Module names are case-insensitive. Scan modules run first, then analysis modules.

Verbose output (step-by-step logs and progress bars) is the **default**. Pass `-s` for minimal output.

### Examples

```bash
# Scan only
python kirby.py -t /Volumes/bitlocker -e Yara,oletools

# Analyze previously flagged files
python kirby.py -t /Volumes/bitlocker -a virustotal

# Full pipeline in one invocation
python kirby.py -t /Volumes/bitlocker -e Yara,oletools -a virustotal

# Scan installed kernel extensions on this Mac
python kirby.py -kext -e detect-it-easy,Yara
```

Each module produces `{module}.md` in the output directory (e.g. `output/yara.md`, `output/virustotal.md`).

### `-kext` special target

Use `-kext` instead of `-t` to scan kernel extensions installed on the local macOS system. Kirby enumerates `.kext` bundles under:

- `/Library/Extensions`
- `/System/Library/Extensions`
- `/Library/Apple/System/Library/Extensions`

It writes every file inside those bundles to `tmp/all_files` (with SHA-256 hashes in `tmp/sha256_hashes`) and passes that inventory to scan engines that read the file list (`detect-it-easy`, `oletools`, `mraptor`, etc.). YARA scans those kext directories recursively. The inventory is cached under `cache/kext/` and reused until bundle paths or modification times change.

`-kext` cannot be combined with `-t`.

---

## Shared behavior

When scan modules run, Kirby first builds or reuses a file inventory:

- **`tmp/all_files`** — one absolute path per line for every file on the target volume
- **`tmp/all_files.meta`** — volume fingerprint (UUID, device, size) used to skip re-indexing when the volume has not changed

Scan modules that flag suspicious files append to a shared CSV:

- **`tmp/flagged.csv`** — two columns: full file path, comma-separated list of scan modules that flagged it (e.g. `Yara,oletools`)

If multiple scan modules flag the same path, Kirby merges module names into the second column rather than duplicating rows.

Analysis modules read from `tmp/flagged.csv` rather than scanning the volume directly.

---

## Scan modules

Scan modules live under `modules/scan/` and are invoked with `-e`.

### Yara

Signature-based scanning using [Neo23x0's signature-base](https://github.com/Neo23x0/signature-base) YARA rules.

**What it does**

- Clones the ruleset on first run (if not already present under `modules/scan/yara/signature-base/`)
- Compiles `.yar` rules into a cached blob (`kirby-compiled.yarc`), recompiling when rules change
- Recursively scans the entire target directory with `yara`

**Output**

- `output/yara.md` — scan metadata and a table of all rule matches

**Flagged files (`tmp/flagged.csv`)**

- Every file that matches at least one YARA rule (tool name: `Yara`)

**Result filtering**

| Layer | Filtering |
|-------|-----------|
| Rules compiled | Excludes rule files listed in `external-variable-rules.txt` (rules that require external variables and cannot be compiled standalone) |
| Scan scope | No file-type filter — all files under the target are scanned recursively |
| Report / flagged output | **No severity filter** — any rule match is included |

**Configuration** (`modules/scan/yara/yara.conf`)

| Option | Description |
|--------|-------------|
| `ruleset` | Local directory name for the cloned ruleset (relative to `modules/scan/yara/`) |
| `ruleset_url` | Git URL to clone on first run |
| `rules_dir` | Subdirectory within the ruleset containing `.yar` files |
| `recursive` | When `true`, pass `-r` to `yara` for recursive scanning |

**Prerequisites:** `yara` and `yarac` on `PATH` (e.g. `brew install yara`)

---

### oletools

Macro and OLE analysis using [oletools](https://github.com/decalage2/oletools) `olevba` against Office/OLE documents from the file inventory.

**What it does**

- Reads paths from `tmp/all_files` (built by Kirby)
- Filters to configured Office/OLE extensions
- Runs `olevba` on each eligible file

**Output**

- `output/oletools.md` — **full output for every eligible file** scanned (including clean files and parse errors)

**Flagged files (`tmp/flagged.csv`)**

- Files where olevba output contains indicator rows for **Suspicious**, **AutoExec**, **IOC**, **Hex**, or **Base64** (tool name: `oletools`)

**Result filtering**

| Layer | Filtering |
|-------|-----------|
| Input files | Extension list in config, intersected with `tmp/all_files` |
| Report | **None** — all eligible files appear in the report |
| Flagged output | **Moderate** — only files with suspicious indicator types in olevba's analysis table; clean macros and unsupported-file errors are not flagged |

**Configuration** (`modules/scan/oletools/oletools.conf`)

| Option | Description |
|--------|-------------|
| `file_list` | Path to Kirby's file inventory (default: `tmp/all_files`) |
| `extensions` | Comma-separated Office/OLE extensions (`.doc`, `.docx`, `.xls`, `.ppt`, `.rtf`, `.msi`, etc.) |

**Prerequisites:** `oletools` installed in the project venv (`pip install -r requirements.txt`)

---

### RegRipper

Windows registry persistence analysis using [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0).

**What it does**

- Clones RegRipper on first run (if not already present under `modules/scan/regripper/RegRipper3.0/`)
- Builds a local Perl environment with `Parse::Win32Registry` and RegRipper's patched modules (`setup.sh`)
- Locates `SYSTEM`, `SOFTWARE`, and user-profile `NTUSER.DAT` hives on the mounted target volume
- Runs targeted RegRipper plugins for run keys, services, Winlogon, UserAssist, and AppCompatCache
- Summarizes suspect entries (RegRipper alerts plus launcher/path heuristics) in a Markdown report

**Output**

- `output/regripper.md` — summary of suspect registry entries by category

**Flagged files (`tmp/flagged.csv`)**

- Executable paths referenced by suspect registry entries that resolve to existing files on the target volume (tool name: `regripper`)

**Configuration** (`modules/scan/regripper/regripper.conf`)

| Option | Description |
|--------|-------------|
| `repo` | Local directory name for the cloned RegRipper repo |
| `repo_url` | Git URL to clone on first run |
| `system_hive` | Relative path to the SYSTEM hive under the target |
| `software_hive` | Relative path to the SOFTWARE hive under the target |
| `users_dir` | Relative path to the Users directory |
| `skip_user_profiles` | Profile folders to skip when searching for NTUSER.DAT |
| `categories` | Comma-separated persistence categories to analyze |

**Prerequisites:** `perl` and `cpan` on `PATH` (system Perl on macOS is sufficient). First run executes `setup.sh` to install Perl dependencies locally under `modules/scan/regripper/perl-lib/`.

---

### detect-it-easy

Packer and protector identification using [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) (`diec`) against executable-like files from the file inventory.

**What it does**

- Reads paths from `tmp/all_files` (built by Kirby)
- Filters to configured executable/script extensions (`.exe`, `.dll`, `.sys`, `.ps1`, `.dylib`, etc.) and, when `scan_macos_binaries` is enabled, extension-less Mach-O binaries under `Contents/MacOS/`
- Runs `diec` with the local signature database under `modules/scan/detect-it-easy/Detect-it-easy/`
- Flags files with packer, protector, cryptor, or related detection types

**Output**

- `output/detect-it-easy.md` — suspicious detections per flagged file

**Flagged files (`tmp/flagged.csv`)**

- Files where `diec` reports a detection type listed in `flag_types` (tool name: `detect-it-easy`)

**Configuration** (`modules/scan/detect-it-easy/detect-it-easy.conf`)

| Option | Description |
|--------|-------------|
| `diec` | Path to the `diec` binary (absolute, or relative to project root) |
| `database` | Primary signature database (`Detect-it-easy/db`) |
| `extra_database` | Extra signatures (`Detect-it-easy/db_extra`) |
| `custom_database` | Custom signatures (`Detect-it-easy/db_custom`) |
| `file_list` | Path to Kirby's file inventory (default: `tmp/all_files`) |
| `extensions` | Comma-separated extensions to scan |
| `scan_macos_binaries` | Include extension-less Mach-O binaries under `Contents/MacOS/` (default: `true`) |
| `flag_types` | Detection types that cause a file to be flagged |
| `require_non_heuristic` | Require at least one signature-based hit (type without leading `~`), not heuristic-only (default: `true`) |
| `ignore_heuristic_names` | Comma-separated heuristic detection names to never flag (e.g. `Generic`, `Obfuscation`) |
| `allow_heuristic_names` | Heuristic names that may flag even when `require_non_heuristic` is enabled (e.g. `Stealer`) |
| `skip_authenticode_heuristic_only` | Skip files whose only flaggable hits are heuristic and the binary is Authenticode-signed (default: `true`) |
| `heuristic_scan` | Pass `-u` to `diec` for heuristic scanning (default: `true`) |
| `deep_scan` | Pass `-d` for deep scan (default: `false`) |
| `aggressive_scan` | Pass `-g` for aggressive scan (default: `false`) |
| `hide_unknown` | Pass `-U` to hide unknown types (default: `true`) |

**Prerequisites:** `diec` on disk. The default config points at the official macOS arm64 release:

```bash
# Install from https://github.com/horsicq/DIE-engine/releases (die_mac_qt6_3.21_arm64.pkg)
# diec is installed at:
/Applications/DiE.app/Contents/MacOS/diec
```

To build `diec` locally from source instead, run:

```bash
source .venv/bin/activate
./modules/scan/detect-it-easy/build.sh
```

Then set `diec` in `detect-it-easy.conf` to `modules/scan/detect-it-easy/DIE-engine/build/release/diec`.

Signature data is cloned separately under `modules/scan/detect-it-easy/Detect-it-easy/` (the [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) database repo). Kirby passes these paths to `diec` via `-D`, `-E`, and `-C`, so the bundled signatures inside `DiE.app` are not used.

**False positive tuning:** Vendor binaries often trigger heuristic `~protection` hits (`Obfuscation`, `Anti analysis`, `Generic`) or `~malware` / `Anomalous build info`. The defaults above focus on named signature detections (e.g. `UPX`, `Crypto Obfuscator`) and skip heuristic-only hits on Authenticode-signed files. For stricter triage, keep `require_non_heuristic = true` and omit `protection` from `flag_types`. For broader coverage, add `protection` back or set `require_non_heuristic = false`. Cross-reference remaining flags with VirusTotal and YARA results in `tmp/flagged.csv`.

---

### ClamAV

Antivirus scanning via ClamAV. **Not yet implemented** — the module is a placeholder that writes an empty report.

**Output**

- `output/clamav.md` — currently empty

**Flagged files**

- None (flagging hook is in place for future use; tool name will be `ClamAV`)

**Configuration** (`modules/scan/clamav/clamav.conf`)

| Option | Description |
|--------|-------------|
| `database` | ClamAV signature database path |
| `recursive` | Intended for recursive scanning when implemented |

**Prerequisites (planned):** ClamAV installed and signatures updated (`brew install clamav`)

---

## Analysis modules

Analysis modules live under `modules/analysis/` and are invoked with `-a`. They operate on files already flagged by scan modules in `tmp/flagged.csv`.

### VirusTotal

Looks up SHA256 hashes for files flagged by scan modules and retrieves enrichment data from the VirusTotal API.

**What it does**

- Reads file paths from `tmp/flagged.csv`
- Computes SHA256 for each flagged file that still exists on disk
- Writes hashes to `tmp/virustotal-hashes` (`sha256<TAB>path`)
- Looks up each hash in VirusTotal (`GET /api/v3/files/{sha256}`)
- Caches API responses in `cache/virustotal-cache.db` (SQLite) to avoid repeat lookups
- Logs a one-line summary to the terminal after each lookup

**Output**

- `output/virustotal.md` — VirusTotal enrichment for each flagged file analyzed, including which scan modules flagged it

**Flagged files**

- Does not write to `tmp/flagged.csv` (analysis modules consume the flag list rather than contributing to it)

**Result filtering**

| Layer | Filtering |
|-------|-----------|
| Input files | Only paths listed in `tmp/flagged.csv` that still exist on disk |
| VirusTotal lookup | All flagged files are looked up (cache-first) |
| Report | **None** — all analyzed files appear in the report with their VirusTotal response or error |

**Configuration** (`modules/analysis/virustotal/virustotal.conf`)

| Option | Description |
|--------|-------------|
| `flagged_csv` | Path to the shared flag list (default: `tmp/flagged.csv`) |
| `hashes_output` | Path for the hash list (default: `tmp/virustotal-hashes`) |
| `cache_db` | SQLite cache path (default: `cache/virustotal-cache.db`) |
| `api_delay_seconds` | Minimum seconds between VirusTotal API requests (default: `15`, suited to free-tier rate limits) |

**Environment:** set `VIRUSTOTAL_API_KEY` in `.env` at the project root (or in the environment).

---

### sleuthkit-mactime

Builds a filesystem MAC-time timeline from the BitLocker-encrypted device using locally built Sleuth Kit tools (`tsk_gettimes` and `mactime`). Sleuth Kit decrypts the volume natively via `-k`; dislocker is not used for this module.

**What it does**

- Reads the BitLocker partition from `TARGET_DEVICE` in `modules/analysis/sleuthkit-mactime/sleuthkit.conf`, unless `-t` is already a block device or disk image (e.g. `/dev/disk7s3`)
- Runs `tsk_gettimes -k <recovery password>` under `sudo` for raw device access
- Pipes the body file into `mactime`, filtered to the `END_DATE` / `DURATION` window from `sleuthkit-mactime.conf`

**Output**

- `output/sleuthkit-mactime.md` — timeline metadata and mactime output for the selected window

**Flagged files**

- Does not read or write `tmp/flagged.csv`

**Configuration**

Timeline window (`modules/analysis/sleuthkit-mactime/sleuthkit-mactime.conf`):

| Option | Description |
|--------|-------------|
| `END_DATE` | End of the timeline window (`NONE` = today at run time) |
| `DURATION` | Hours before `END_DATE` to include (default: `72`) |
| `sleuthkit_prefix` | Local Sleuth Kit install prefix (default: `modules/analysis/sleuthkit-mactime/install`) |
| `timezone` | Optional timezone for mactime (`-z`), e.g. `EST5EDT` |

Device and credentials (`modules/analysis/sleuthkit-mactime/sleuthkit.conf`):

| Option | Description |
|--------|-------------|
| `TARGET_DEVICE` | Block device or raw image (e.g. `/dev/disk7s3`). **Takes priority over `-t`** when set |
| `BITLOCKER` | `true` when the image is BitLocker-encrypted (`tsk_gettimes -k`); `false` for decrypted raw images |
| `BITLOCKER_RECOVERY_PASSWORD` | Recovery password with dashes. Required when `BITLOCKER = true`. May also be set via the `BITLOCKER_RECOVERY_PASSWORD` environment variable |

When `TARGET_DEVICE` is unset, `-t` may be a mount point. Kirby tries to infer the block device (including dislocker-backed mounts at `/Volumes/bitlocker`) and reads `BITLOCKER_RECOVERY_PASSWORD` from `sleuthkit.conf` when dislocker is detected.

If the device cannot be determined and `TARGET_DEVICE` is not set, Kirby reports a user-friendly error asking you to configure `sleuthkit.conf`.

**Prerequisites:** Build Sleuth Kit locally:

```bash
./modules/analysis/sleuthkit-mactime/build_sleuthkit.sh
```

Requires `sudo` when reading raw block devices. Verify the partition with `diskutil list` (typically the 1 TB "Microsoft Basic Data" slice).

**Usage**

```bash
# Use TARGET_DEVICE from sleuthkit.conf
.venv/bin/python kirby.py -t /Volumes/bitlocker -a sleuthkit-mactime

# Or pass the block device directly
.venv/bin/python kirby.py -t /dev/disk7s3 -a sleuthkit-mactime
```

---

## Output artifacts

| Path | Description |
|------|-------------|
| `output/{module}.md` | Per-module Markdown report |
| `tmp/all_files` | Full file inventory for the target volume |
| `tmp/flagged.csv` | Consolidated list of flagged paths and which scan modules flagged them |
| `tmp/virustotal-hashes` | SHA256 hashes of flagged files analyzed by VirusTotal |
| `cache/virustotal-cache.db` | VirusTotal API response cache |
| `output/sleuthkit-mactime.md` | MAC-time timeline from Sleuth Kit |

---

## Prerequisites

### Mounting the target volume

See `mount_bitlocker.sh` and `build_dislocker.sh`. Requires:

- dislocker (built from source)
- macFUSE with system extension enabled
- ntfs-3g-mac for read-only NTFS mounting

Set `BITLOCKER_RECOVERY_PASSWORD` before running the mount script. The decrypted volume is typically available at `/Volumes/bitlocker`.

### Python

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Per-module external tools

| Module | Type | External dependency |
|--------|------|---------------------|
| Yara | Scan | `yara`, `yarac` |
| oletools | Scan | Included via pip |
| RegRipper | Scan | `perl`, `cpan` (first-run setup) |
| detect-it-easy | Scan | `diec` (official pkg or local build via `build.sh`) |
| ClamAV | Scan | Not yet used |
| VirusTotal | Analysis | VirusTotal API key in `.env` |
| sleuthkit-mactime | Analysis | Local Sleuth Kit build; `sudo` for raw device access |

---

## Project layout

```
kirby.py              # CLI orchestrator
kirby_log.py          # Logging and progress helpers
kirby_flagged.py      # Shared flagged-file registry
modules/
  scan/
    yara/             # YARA signature scanning
    oletools/         # Office macro analysis
    regripper/        # Windows registry persistence analysis
    detect-it-easy/   # Detect It Easy packer/protector scanning
    clamav/           # ClamAV (placeholder)
  analysis/
    virustotal/       # VirusTotal hash enrichment
    sleuthkit-mactime/  # Sleuth Kit MAC timeline, local build, and sleuthkit.conf
output/               # Markdown reports
tmp/                  # File inventory, flagged.csv, hash lists
cache/                # VirusTotal cache database
```
