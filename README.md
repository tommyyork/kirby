# Kirby — Malware Response Scanner

Kirby is a modular malware analysis orchestrator for examining a mounted Windows disk image (typically a BitLocker-encrypted drive decrypted and mounted read-only on macOS). It runs **scan modules** against the target volume to find suspicious files, optionally runs **analysis modules** to enrich those findings, and can run **rescue modules** to copy safe user documents off the volume. Each module writes a Markdown report, and scan modules maintain a shared registry of flagged paths.

The intended workflow is:

1. Mount the target volume read-only (`mount_bitlocker.sh`).
2. Run scan modules with `-e` to populate `tmp/<name>/flagged.csv`.
3. Run analysis modules with `-a` to enrich flagged files (e.g. VirusTotal lookups).
4. Optionally run rescue modules with `-r` to copy user-owned documents after macro checks.
5. Review Markdown reports in `output/<name>/` and the consolidated flag list in `tmp/<name>/flagged.csv`.

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
python kirby.py -t /Volumes/bitlocker -n bitlocker -e yara,oletools -a virustotal
```

External tools required depend on which modules you enable — see [Prerequisites](#prerequisites).

---

## Kirby CLI

```
usage: kirby.py [-h] [-t TARGET] [-kext] [-e ENGINES] [-a ANALYSIS] [-r RESCUE] [-n NAME] [-o OUTPUT] [-s]
```

| Flag | Long form | Required | Default | Description |
|------|-----------|----------|---------|-------------|
| `-t` | `--target` | Yes* | — | Scan target: directory, specific file path, disk image, or block device (e.g. `/Volumes/bitlocker`, `/Volumes/Windows/Users/jane/file.exe`) |
| `-kext` | — | No | off | Also scan installed kernel extensions on this Mac; without `-t`, kexts are the only scan target |
| `-e` | `--engines` | No* | — | Comma-separated **scan** module names (e.g. `yara,clamav,oletools`) |
| `-a` | `--analysis` | No* | — | Comma-separated **analysis** module names (e.g. `virustotal`) |
| `-r` | `--rescue` | No* | — | Comma-separated **rescue** module names (e.g. `simple-rescue`) |
| `-n` | `--name` | No | `default_namespace` | Namespace for this run; working files go in `tmp/<name>/`, reports in `output/<name>/` |
| `-o` | `--output` | No | `output/` | Base output directory; reports go in `<output>/<name>/` |
| `-s` | `--silent` | No | off | Suppress detailed progress logs and tqdm progress bars |

\*At least one of `-e`, `-a`, or `-r` must be provided. When running scan or rescue modules, provide `-t`, `-kext`, or both.

Module names are case-insensitive. Scan modules run first, then rescue modules, then analysis modules.

Verbose output (step-by-step logs and progress bars) is the **default**. Pass `-s` for minimal output.

### Target naming (`-n`)

Each run uses a **namespace** (`-n`) that groups working files and reports. When `-n` is omitted, Kirby uses `default_namespace` (`tmp/default_namespace/`, `output/default_namespace/`). Pass `-n` explicitly to separate cases — for example `laptop_ssd` for one machine's drive and `usb_stick` for another.

The same namespace can be reused across multiple mount points or devices. Each scan appends to `tmp/<name>/flagged.csv`, so one namespace can accumulate flagged paths from many locations. During analysis, `-t` still filters that list to paths under the provided target (or to the exact file when `-t` is a file path).

### Single-file targets

Pass a **file path** to `-t` to run scan modules against that one file only. Kirby writes the path to `tmp/<name>/all_files` and passes it to inventory-driven engines (`detect-it-easy`, `oletools`, `mraptor`, etc.). YARA scans the file directly (without recursion). Registry-oriented modules such as RegRipper still expect a directory or volume mount and are not useful with a single-file target.

```bash
# Scan one executable with Detect It Easy
python kirby.py -t /Volumes/Windows/Users/riley/Downloads/ChromeSetup.exe -n laptop_ssd -e die

# Combine with other inventory-based engines
python kirby.py -t /Volumes/Windows/Users/riley/Downloads/report.docm -n laptop_ssd -e die,mraptor,oletools
```

Use `-n` to keep reports and `flagged.csv` under a stable namespace (e.g. `laptop_ssd`) rather than the default `default_namespace`.

### Examples

```bash
# Scan only
python kirby.py -t /Volumes/bitlocker -n bitlocker -e yara,oletools

# Named namespace — working files in tmp/laptop_ssd/, reports in output/laptop_ssd/
python kirby.py -t /Volumes/Windows -n laptop_ssd -e detect-it-easy,mraptor,regripper,yara

# Scan a second volume into the same namespace (merges into tmp/laptop_ssd/flagged.csv)
python kirby.py -t /Volumes/OtherDrive -n laptop_ssd -e yara

# Analyze only paths under /Volumes/Windows from that shared flag list
python kirby.py -t /Volumes/Windows -n laptop_ssd -a virustotal

# Full pipeline in one invocation
python kirby.py -t /Volumes/bitlocker -n bitlocker -e yara,oletools -a virustotal

# Rescue user documents from a Windows volume (macro-checked Office files)
python kirby.py -t /Volumes/Windows -n laptop_ssd -r simple-rescue

# Scan installed kernel extensions on this Mac only
python kirby.py -kext -n kext -e detect-it-easy,yara

# Scan a mounted volume and local kernel extensions in one run
python kirby.py -t /Volumes/Windows -kext -n laptop_ssd -e yara,clamav
```

Each module produces `{module}.md` under the target output directory (e.g. `output/laptop_ssd/yara.md`, `output/laptop_ssd/virustotal.md`).

### `-kext` kernel extension scanning

Use `-kext` to include kernel extensions installed on the local macOS system. Kirby enumerates `.kext` bundles under:

- `/Library/Extensions`
- `/System/Library/Extensions`
- `/Library/Apple/System/Library/Extensions`

**`-kext` alone** scans only those kext bundles. Kirby writes every file inside them to `tmp/<name>/all_files` (use `-n kext` or another namespace; otherwise `default_namespace`), with SHA-256 hashes in `tmp/<name>/sha256_hashes`. The inventory is cached under `cache/kext/` and reused until bundle paths or modification times change.

**`-kext` with `-t`** scans the `-t` target first, then appends the kext inventory to the same `tmp/<name>/all_files`. Inventory-driven engines (`detect-it-easy`, `oletools`, `mraptor`, etc.) scan the combined list. Path-based engines (`yara`, `clamav`) scan the `-t` target and the kext directories separately. Analysis with `-a` includes flagged paths from both the target and kexts when `-kext` is set.

Registry-oriented modules such as `regripper` and rescue modules such as `simple-rescue` operate on the `-t` target only; kext paths in the merged inventory are ignored when they fall outside the mounted volume.

---

## Shared behavior

When scan or rescue modules run, Kirby first builds or reuses a file inventory, then publishes it under `tmp/<name>/`:

- **`tmp/<name>/all_files`** — one absolute path per line for files under the current `-t` target
- **`tmp/<name>/all_files.meta`** — fingerprint used to skip re-indexing when the target has not changed
- **`tmp/<name>/sha256_hashes`** — tab-separated path and SHA-256 digest for indexed files

**Directory targets** use a **volume-level** cache under `cache/volumes/<mount>/_root/`. Kirby walks the mount point once, then filters paths when `-t` is a subdirectory. Scanning `/Volumes/Windows/Users` after `/Volumes/Windows` reuses the same cache.

**Single-file targets** skip volume indexing: Kirby hashes the file and writes one line to `tmp/<name>/all_files`. The fingerprint in `all_files.meta` tracks path, size, and modification time.

Scan modules that flag suspicious files append to a shared CSV:

- **`tmp/<name>/flagged.csv`** — path, comma-separated scan modules that flagged it, and optional SHA-256 hash

If multiple scan modules flag the same path, Kirby merges module names into the second column rather than duplicating rows. Scanning different volumes with the same `-n` merges into the same `flagged.csv`.

Analysis modules read from `tmp/<name>/flagged.csv`. When `-t` is provided, only paths under that target are analyzed (written to `tmp/<name>/flagged-scoped.csv` for the run). When `-kext` is also set, flagged kernel extension paths are included in that scoped analysis list.

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

- `output/<name>/yara.md` — scan metadata and a table of all rule matches

**Flagged files (`tmp/<name>/flagged.csv`)**

- Every file that matches at least one YARA rule (tool name: `yara`)

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

- Reads paths from `tmp/<name>/all_files` (built by Kirby)
- Filters to configured Office/OLE extensions
- Runs `olevba` on each eligible file

**Output**

- `output/<name>/oletools.md` — **full output for every eligible file** scanned (including clean files and parse errors)

**Flagged files (`tmp/<name>/flagged.csv`)**

- Files where olevba output contains indicator rows for **Suspicious**, **AutoExec**, **IOC**, **Hex**, or **Base64** (tool name: `oletools`)

**Result filtering**

| Layer | Filtering |
|-------|-----------|
| Input files | Extension list in config, intersected with `tmp/<name>/all_files` |
| Report | **None** — all eligible files appear in the report |
| Flagged output | **Moderate** — only files with suspicious indicator types in olevba's analysis table; clean macros and unsupported-file errors are not flagged |

**Configuration** (`modules/scan/oletools/oletools.conf`)

| Option | Description |
|--------|-------------|
| `file_list` | Path to Kirby's file inventory (default: `tmp/<name>/all_files`) |
| `extensions` | Comma-separated Office/OLE extensions (`.doc`, `.docx`, `.xls`, `.ppt`, `.rtf`, `.msi`, etc.) |

**Prerequisites:** `oletools` installed in the project venv (`pip install -r requirements.txt`)

---

### mraptor

Malicious macro detection using [oletools](https://github.com/decalage2/oletools) **MacroRaptor** against VBA-capable Office files from the file inventory.

**What it does**

- Reads paths from `tmp/<name>/all_files` (built by Kirby)
- Filters to configured VBA-capable Office extensions (`.docm`, `.xlsm`, `.pptm`, etc.)
- Validates file headers when enabled (skips mislabeled or Recycle Bin sidecar files)
- Runs `mraptor` on each eligible file; exit code `20` indicates suspicious macro behavior

**Output**

- `output/<name>/mraptor.md` — suspicious macro detections per flagged file

**Flagged files (`tmp/<name>/flagged.csv`)**

- Files where mraptor reports suspicious macro behavior (tool name: `mraptor`)

**Configuration** (`modules/scan/mraptor/mraptor.conf`)

| Option | Description |
|--------|-------------|
| `file_list` | Path to Kirby's file inventory (default: `tmp/<name>/all_files`) |
| `extensions` | Comma-separated VBA-capable Office extensions |
| `exclude_recycle_bin_sidecars` | Skip `$Recycle.Bin` `$I*` metadata files (default: `true`) |
| `validate_file_headers` | Require OLE/OpenXML/SLK header signatures (default: `true`) |
| `show_matches` | Pass `-m` to include matched heuristic strings in output (default: `true`) |

**Prerequisites:** `oletools` / `mraptor` in the project venv (`pip install -r requirements.txt`)

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

- `output/<name>/regripper.md` — summary of suspect registry entries by category

**Flagged files (`tmp/<name>/flagged.csv`)**

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

Module name alias: `die` (e.g. `-e die` is equivalent to `-e detect-it-easy`).

**What it does**

- Reads paths from `tmp/<name>/all_files` (built by Kirby)
- Filters to configured executable/script extensions (`.exe`, `.dll`, `.sys`, `.ps1`, `.dylib`, etc.) and, when `scan_macos_binaries` is enabled, extension-less Mach-O binaries under `Contents/MacOS/`
- Runs `diec` with the local signature database under `modules/scan/detect-it-easy/Detect-it-easy/`
- Flags files with packer, protector, cryptor, or related detection types

**Output**

- `output/<name>/detect-it-easy.md` — suspicious detections per flagged file

**Flagged files (`tmp/<name>/flagged.csv`)**

- Files where `diec` reports a detection type listed in `flag_types` (tool name: `detect-it-easy`)

**Configuration** (`modules/scan/detect-it-easy/detect-it-easy.conf`)

| Option | Description |
|--------|-------------|
| `diec` | Path to the `diec` binary (absolute, or relative to project root) |
| `database` | Primary signature database (`Detect-it-easy/db`) |
| `extra_database` | Extra signatures (`Detect-it-easy/db_extra`) |
| `custom_database` | Custom signatures (`Detect-it-easy/db_custom`) |
| `file_list` | Path to Kirby's file inventory (default: `tmp/<name>/all_files`) |
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

**False positive tuning:** Vendor binaries often trigger heuristic `~protection` hits (`Obfuscation`, `Anti analysis`, `Generic`) or `~malware` / `Anomalous build info`. The defaults above focus on named signature detections (e.g. `UPX`, `Crypto Obfuscator`) and skip heuristic-only hits on Authenticode-signed files. For stricter triage, keep `require_non_heuristic = true` and omit `protection` from `flag_types`. For broader coverage, add `protection` back or set `require_non_heuristic = false`. Cross-reference remaining flags with VirusTotal and YARA results in `tmp/<name>/flagged.csv`.

---

### ClamAV

Antivirus scanning via ClamAV `clamdscan` against the scan target (directory, single file, kext roots, or a combination of `-t` and `-kext`).

**What it does**

- Starts a dedicated Kirby `clamd` instance using `modules/scan/clamav/clamd.conf` (not Homebrew's `/opt/homebrew/etc/clamav/clamd.conf`); the active config is written to `modules/scan/clamav/run/clamd.conf` with the `database` path from `clamav.conf`
- Runs `clamdscan --fdpass` against `-t` (or each kext root when using `-kext`, or both when `-t` and `-kext` are combined)
- Writes the full scan transcript to `output/<name>/clamdscan.log`
- Flags every file reported as `FOUND`

**Output**

- `output/<name>/clamav.md` — summary table of detections
- `output/<name>/clamdscan.log` — full clamdscan log for the run

**Flagged files (`tmp/<name>/flagged.csv`)**

- Every file where clamdscan reports a virus signature (tool name: `clamav`)

**Configuration**

Module settings (`modules/scan/clamav/clamav.conf`):

| Option | Description |
|--------|-------------|
| `database` | ClamAV signature database directory (default: `/opt/homebrew/var/lib/clamav`) |
| `clamd_config` | Path to the Kirby clamd config, relative to the module directory (default: `clamd.conf`) |

Daemon settings (`modules/scan/clamav/clamd.conf`):

| Setting | Description |
|---------|-------------|
| `DatabaseDirectory` | Signature database path (should match `database` in `clamav.conf`) |
| `TCPSocket` / `TCPAddr` | Local Kirby clamd listener (default: `127.0.0.1:13374`) |
| `MaxScanSize` / `MaxFileSize` | Archive and per-file scan limits |

**Prerequisites:** ClamAV installed and signatures updated:

```bash
brew install clamav
freshclam   # or: sudo freshclam
```

The module starts `clamd` automatically when it is not already listening on the Kirby socket/port.

---

## Analysis modules

Analysis modules live under `modules/analysis/` and are invoked with `-a`. They operate on files already flagged by scan modules in `tmp/<name>/flagged.csv`.

### VirusTotal

Looks up SHA256 hashes for files flagged by scan modules and retrieves enrichment data from the VirusTotal API.

**What it does**

- Reads file paths from `tmp/<name>/flagged.csv`
- Computes SHA256 for each flagged file that still exists on disk
- Writes hashes to `tmp/<name>/virustotal-hashes` (`sha256<TAB>path`)
- Looks up each hash in VirusTotal (`GET /api/v3/files/{sha256}`)
- Caches API responses in `cache/virustotal-cache.db` (SQLite) to avoid repeat lookups
- Logs a one-line summary to the terminal after each lookup

**Output**

- `output/<name>/virustotal.md` — VirusTotal enrichment for each flagged file analyzed, including which scan modules flagged it

**Flagged files**

- Does not write to `tmp/<name>/flagged.csv` (analysis modules consume the flag list rather than contributing to it)

**Result filtering**

| Layer | Filtering |
|-------|-----------|
| Input files | Only paths listed in `tmp/<name>/flagged.csv` that still exist on disk |
| VirusTotal lookup | All flagged files are looked up (cache-first) |
| Report | **None** — all analyzed files appear in the report with their VirusTotal response or error |

**Configuration** (`modules/analysis/virustotal/virustotal.conf`)

| Option | Description |
|--------|-------------|
| `flagged_csv` | Path to the shared flag list (default: `tmp/<name>/flagged.csv`) |
| `hashes_output` | Path for the hash list (default: `tmp/<name>/virustotal-hashes`) |
| `cache_db` | SQLite cache path (default: `cache/virustotal-cache.db`) |
| `api_delay_seconds` | Minimum seconds between VirusTotal API requests (default: `15`, suited to free-tier rate limits) |

**Environment:** set `VIRUSTOTAL_API_KEY` in `.env` at the project root (or in the environment).

---

### signatures

Code signature verification for flagged executables using `codesign`, `osslsigncode`, `exiftool`, and `strings`.

**What it does**

- Reads flagged paths from `tmp/<name>/flagged.csv` (or the scoped list when `-t` is provided)
- Filters to configured executable-like extensions (`.exe`, `.dll`, `.sys`, etc.)
- On macOS, runs `codesign -dv --verbose=4` and `codesign --verify --strict --verbose=2`
- On Windows PE files, runs `osslsigncode verify` when available
- Collects Authenticode and PE metadata via `exiftool`; dumps leading strings on verification failure

**Output**

- `output/<name>/signatures.md` — per-file signature verification results

**Flagged files**

- Does not write to `tmp/<name>/flagged.csv`

**Configuration** (`modules/analysis/signatures/signatures.conf`)

| Option | Description |
|--------|-------------|
| `flagged_csv` | Path to the shared flag list (default: `tmp/<name>/flagged.csv`) |
| `extensions` | Executable-like extensions to analyze from flagged paths |
| `strings_limit` | Lines of `strings` output when verification fails (default: `10`) |

**Prerequisites:** `codesign` (macOS), optional `osslsigncode` (`brew install osslsigncode`), `exiftool`, and `strings` on `PATH`.

---

### sleuthkit-mactime

Builds a filesystem MAC-time timeline from the BitLocker-encrypted device using locally built Sleuth Kit tools (`tsk_gettimes` and `mactime`). Sleuth Kit decrypts the volume natively via `-k`; dislocker is not used for this module.

**What it does**

- Reads the BitLocker partition from `TARGET_DEVICE` in `modules/analysis/sleuthkit-mactime/sleuthkit.conf`, unless `-t` is already a block device or disk image (e.g. `/dev/disk7s3`)
- Runs `tsk_gettimes -k <recovery password>` under `sudo` for raw device access
- Pipes the body file into `mactime`, filtered to the `END_DATE` / `DURATION` window from `sleuthkit-mactime.conf`

**Output**

- `output/<name>/sleuthkit-mactime.md` — timeline metadata and mactime output for the selected window

**Flagged files**

- Does not read or write `tmp/<name>/flagged.csv`

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
.venv/bin/python kirby.py -t /Volumes/bitlocker -n bitlocker -a sleuthkit-mactime

# Or pass the block device directly
.venv/bin/python kirby.py -t /dev/disk7s3 -n bitlocker -a sleuthkit-mactime
```

---

## Rescue modules

Rescue modules live under `modules/rescue/` and are invoked with `-r`. They operate on the same file inventory as scan modules (`tmp/<name>/all_files`) and require a mounted target (`-t`). `-kext` alone is not sufficient for rescue modules.

### simple-rescue

Copy user-owned documents, spreadsheets, images, and email files from a Windows volume after screening VBA-capable Office files with **mraptor**.

**What it does**

1. Detect whether the target is a **Windows** or **macOS** volume (`Windows/` vs `System/Library` layout). macOS rescue is stubbed and reports without copying files.
2. On Windows volumes, discover non-default user profiles under `Users/` (profiles with `NTUSER.DAT`, skipping Default/Public/All Users).
3. Filter the indexed file list to files under each profile that match configured document, spreadsheet, image, or email extensions.
4. Write the candidate list to `tmp/<name>/simple-rescue-candidates.txt`.
5. Run **mraptor** against VBA-capable Office files in the candidate set; block copy of suspicious files.
6. Copy safe files to `output/<name>/simple-rescue/<User>/<relative-path>` preserving profile-relative paths.

**Output**

- `output/<name>/simple-rescue.md` — summary report
- `output/<name>/simple-rescue/report.md` — full report with inclusion criteria, user profiles, excluded files (with mraptor output), and copied files
- `output/<name>/simple-rescue/<User>/...` — rescued files
- `tmp/<name>/simple-rescue-candidates.txt` — temporary candidate file list

**Flagged files (`tmp/<name>/flagged.csv`)**

- VBA-capable files flagged by mraptor during rescue are appended with tool name `mraptor`

**Inclusion criteria**

| Layer | Filtering |
|-------|-----------|
| Volume type | Windows volumes only (macOS stub) |
| User profiles | Non-default profiles under `Users/` with `NTUSER.DAT` |
| Ownership | Files under the profile directory, excluding configured skip paths |
| Content scope | Configured user content directories (Desktop, Documents, etc.) |
| File types | Document, spreadsheet, image, or email extensions from config |
| Macro safety | VBA-capable Office files must pass mraptor (exit code ≠ 20) |

**Configuration** (`modules/rescue/simple-rescue/simple-rescue.conf`)

| Option | Description |
|--------|-------------|
| `file_list` | Indexed file list (default `tmp/<name>/all_files`; Kirby passes the per-target path) |
| `users_dir` | Relative path to Windows `Users` directory |
| `skip_user_profiles` | Default/system profiles to skip |
| `user_content_dirs` | Profile subdirectories to include (empty = entire profile except skips) |
| `skip_profile_paths` | Profile-relative paths to exclude |
| `document_extensions` | Document file extensions |
| `spreadsheet_extensions` | Spreadsheet file extensions |
| `image_extensions` | Image file extensions |
| `email_extensions` | Email file extensions |
| `mraptor_config` | Path to mraptor scan module config |
| `mraptor_show_matches` | Pass `-m` to mraptor for matched heuristic strings |

**Prerequisites:** Same as the mraptor scan module (`oletools` via pip or `.venv/bin/mraptor`).

**Usage**

```bash
python kirby.py -t /Volumes/Windows -n laptop_ssd -r simple-rescue
```

---

## Output artifacts

| Path | Description |
|------|-------------|
| `output/<name>/{module}.md` | Per-module Markdown report for the named target run |
| `output/<name>/simple-rescue/report.md` | Full simple-rescue report (copied files, criteria, excluded files) |
| `output/<name>/simple-rescue/<User>/...` | Rescued user files copied by simple-rescue |
| `tmp/<name>/simple-rescue-candidates.txt` | Candidate file list built by simple-rescue |
| `tmp/<name>/all_files` | Full file inventory for the current scan target |
| `tmp/<name>/flagged.csv` | Consolidated list of flagged paths and which scan modules flagged them |
| `tmp/<name>/flagged-scoped.csv` | Target-filtered subset of `flagged.csv` used during analysis |
| `tmp/<name>/virustotal-hashes` | SHA256 hashes of flagged files analyzed by VirusTotal |
| `output/<name>/clamdscan.log` | Full ClamAV clamdscan transcript |
| `cache/virustotal-cache.db` | VirusTotal API response cache |
| `output/<name>/sleuthkit-mactime.md` | MAC-time timeline from Sleuth Kit |

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
| yara | Scan | `yara`, `yarac` |
| oletools | Scan | Included via pip |
| mraptor | Scan | Included via pip (oletools) |
| regripper | Scan | `perl`, `cpan` (first-run setup) |
| detect-it-easy | Scan | `diec` (official pkg or local build via `build.sh`) |
| clamav | Scan | `clamav`, `freshclam`; Kirby uses `modules/scan/clamav/clamd.conf` |
| VirusTotal | Analysis | VirusTotal API key in `.env` |
| signatures | Analysis | `codesign`, optional `osslsigncode`, `exiftool`, `strings` |
| sleuthkit-mactime | Analysis | Local Sleuth Kit build; `sudo` for raw device access |
| simple-rescue | Rescue | mraptor / oletools (via pip) |

---

## Project layout

```
kirby.py              # CLI orchestrator
kirby_paths.py        # Per-target tmp/ and output/ path helpers
kirby_log.py          # Logging and progress helpers
kirby_flagged.py      # Shared flagged-file registry
kirby_index.py        # Volume and single-file inventory caching
kirby_target.py       # Target path resolution helpers
modules/
  scan/
    yara/             # YARA signature scanning
    oletools/         # Office macro analysis (olevba)
    mraptor/           # Malicious macro detection (MacroRaptor)
    regripper/        # Windows registry persistence analysis
    detect-it-easy/   # Detect It Easy packer/protector scanning
    clamav/           # ClamAV clamdscan integration
  analysis/
    virustotal/       # VirusTotal hash enrichment
    signatures/       # PE / Authenticode signature verification
    sleuthkit-mactime/  # Sleuth Kit MAC timeline, local build, and sleuthkit.conf
  rescue/
    simple-rescue/    # Copy user documents after mraptor macro checks
output/               # Markdown reports (one subdirectory per target run)
tmp/                  # Per-target working files (tmp/<name>/)
cache/                # Volume inventory and VirusTotal API cache
```
