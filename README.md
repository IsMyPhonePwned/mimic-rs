# Mimic

**Mimic** is a next-generation antivirus engine in Rust: high-speed parallel file scanning with ClamAV signatures, YARA-X rules, VirusTotal integration, built-in exploit detection, WASM plugins, SQLite persistence, and a web dashboard.

---

## Features

- **High-speed parallel scanning** — Rayon thread pool, thousands of files per second; progress bar for directory scans and a 0–100% loading bar for ClamAV databases
- **ClamAV signature compatibility** — Full support for hash, body, logical, PE-section, container, and bytecode databases (see [ClamAV signature support](#clamav-signature-support))
- **YARA-X rules** — Compile and scan with `.yar`/`.yara` rule files via [yara-x](https://github.com/VirusTotal/yara-x)
- **Exploit detection** — [mimic-detect](crates/mimic-detect) as a WASM plugin (DNG, RTF, TTF, RAR, PDF, ZIP CVE); compile and load via `--plugin`
- **VirusTotal (mimic-vt)** — Built-in plugin; load with `--plugin path/mimic-vt.wasm` (and `--vt-key` or `MIMIC_VT_KEY`). Hash-only lookups. Not loaded by default.
- **WASM plugins** — Load `.wasm` files via `--plugin` (e.g. mimic-detect)
- **Security hardening** — Optional sandboxed worker subprocess with privilege drop, resource limits, seccomp (Linux), seatbelt (macOS)
- **SQLite persistence** — Save scan sessions, results, and statistics
- **Web dashboard + REST API** — Browse results, upload files, search by hash, view stats
- **JSON verdict output** — One JSON object per file for pipeline integration
- **“Why did it match?”** — Signature and plugin threats include a short reason (e.g. hash/body match, LDB condition); CLI prints `why: ...` under each threat; web dashboard shows it in the “Why?” decision panel

---

## Build

```bash
cargo build --release
```

Binary: `target/release/mimic`.

**Requirements:** Rust 1.70+; for sandboxing: Linux (seccomp) or macOS (seatbelt). Optional: `clamscan` for benchmarking.

### Mimic browser (WASM scanner in the browser)

From the repository root, build the WASM bundles and start a local static server (default port **8765**):

```bash
./scripts/run-mimic-browser.sh
```

Options are passed through to [`crates/mimic-browser/build-and-run.sh`](crates/mimic-browser/build-and-run.sh): `--release`, `--build` (build only), `--run` (serve only). Set **`MIMIC_BROWSER_PORT`** to change the port. You need **wasm-pack** and **Python 3** (or Python) for `http.server`.

---

## Testing exploit detection (mimic-detect) with `cargo run`

Exploit detection is provided by the **mimic-detect** WASM plugin. Build it once, then point the CLI at a file or directory with **`--no-signatures`** if you only want mimic-detect (no ClamAV DB). Use **`--plugin`** with the path to `mimic_detect.wasm`.

```bash
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown -p mimic-detect

# Single sample (from the workspace root; adjust paths to your samples)
cargo run --release -p mimic-cli -- --no-signatures \
  --plugin target/wasm32-unknown-unknown/release/mimic_detect.wasm \
  /path/to/sample.zip

# Directory of samples (recursive)
cargo run --release -p mimic-cli -- -r --no-signatures \
  --plugin target/wasm32-unknown-unknown/release/mimic_detect.wasm \
  /path/to/samples

# Machine-readable JSON (one object per file)
cargo run --release -p mimic-cli -- --no-signatures --json \
  --plugin target/wasm32-unknown-unknown/release/mimic_detect.wasm \
  /path/to/file
```

When **`mimic_detect.wasm`** is loaded, the engine also runs native **`mimic_detect::analyze`** on each file so CLI / JSON show structured threats (**id**, **description**, **reference**), not only the generic `plugin:mimic_detect` line. Combine with **`-d`** / **`--db`** when you also want ClamAV signatures.

---

## Quick start

```bash
# Scan a directory with ClamAV signatures (progress bar during DB load + scan)
mimic /path/to/scan -r -d scripts/clamav-db

# With YARA rules
mimic /path/to/scan -r -d scripts/clamav-db -y rules/

# Start the web dashboard (optionally with ClamAV DB path and clean DB at startup)
mimic --db-file mimic.db serve --listen 0.0.0.0:8080   # or: serve --db /path/to/clamav-db --clean-db
mimic serve --db /path/to/clamav-db --plugin target/wasm32-unknown-unknown/release/mimic_detect.wasm --clean-db --listen 0.0.0.0:8080
```

---

## CLI usage

| Option | Short | Description |
|--------|--------|-------------|
| `--db <PATH>` | `-d` | ClamAV database path (file or directory). Repeatable. |
| `--yara <PATH>` | `-y` | YARA rule file or directory. Repeatable. |
| `--recursive` | `-r` | Recurse into subdirectories. |
| `--threads <N>` | `-j` | Number of scanning threads (0 = auto). Default: 0. |
| `--max-size <MB>` | | Max file size in MB (0 = no limit). Default: 256. |
| `--extensions <list>` | `-e` | Comma-separated extensions to scan (empty = all). |
| `--json` | | Output one JSON line per file. |
| `--quiet` | `-q` | Only show infected/suspicious files. |
| `--no-mimic` | | Disable mimic exploit detection. |
| `--no-signatures` | | Disable ClamAV signature scanning. |
| `--plugin <PATH>` | | WASM plugin file or directory. Repeatable. |
| `--sandbox` | | Enable sandboxed worker processes (see [Security](#security--sandboxing)). |
| `--vt-key <KEY>` | | VirusTotal API key (or `MIMIC_VT_KEY` env). |
| `--db-file <PATH>` | | SQLite path for results. Default: `mimic.db`. |
| `--verbose` | `-v` | Increase log level (-v, -vv, -vvv). |

**Option names are shared across binaries:** `mimic`, `mimic serve`, and `mimic-mcp` use the same option names for the same features so you can keep compatibility between invocations (e.g. `--db`, `--yara`, `--plugin`, `--max-size`, `--vt-key`, `--listen`).

**Examples:**

```bash
mimic /path/to/dir -r -d /var/lib/clamav -d clamav-db
mimic /path/to/dir -r -y rules/ --json
mimic /path/to/dir -r -e dng,rtf,ttf,pdf,rar -j 8
mimic /path/to/dir -r --plugin ./plugins --vt-key YOUR_KEY
mimic /path/to/dir -r -q --db-file results.db
```

**Comparison with clamscan:** Mimic runs both ClamAV signatures and built-in exploit detection (DNG, RTF, TTF, PDF, RAR, ZIP). For ClamAV-only behaviour use `--no-mimic`. For details on where detection may differ (text targets, bytecode, LDB count/diversity, TDB FileSize), see [Implementation notes (vs ClamAV)](#implementation-notes-vs-clamav).

---

## Technical architecture

```
                    ┌─────────────────────────────────────────────────────────────┐
                    │                        mimic-cli                              │
                    │  (args, progress, serve subcommand, scan summary)             │
                    └───────────────────────────┬─────────────────────────────────┘
                                                 │
                    ┌────────────────────────────▼────────────────────────────────┐
                    │                      mimic-engine                            │
                    │  thread pool OR worker pool │ load DBs │ dispatch per file   │
                    └──┬──────────┬──────────┬───┴──────────┬──────────┬─────────┘
                       │          │          │              │          │
         ┌─────────────▼──┐  ┌────▼────┐  ┌─▼─────────┐  ┌─▼──────┐  ┌▼──────────┐
         │ mimic-signatures│  │mimic-   │  │ mimic-    │  │mimic-   │  │mimic-     │
         │ (ClamAV HDB/NDB│  │detect   │  │ yara-x    │  │wasm     │  │sandbox    │
         │ /LDB/CDB, AC)  │  │(exploit)│  │ (rules)   │  │(plugins)│  │(workers)  │
         └────────────────┘  └─────────┘  └───────────┘  └─────────┘  └───────────┘
                    │
         ┌──────────▼──────────┬─────────────┬────────────┐
         │    mimic-core       │  mimic-db   │  mimic-vt  │
         │ (Verdict, Config)  │ (SQLite)    │ (hash API) │
         └────────────────────┴─────────────┴────────────┘
```

### Crate layout

| Crate | Purpose |
|-------|---------|
| **mimic-core** | Shared types: `Verdict`, `ScanResult`, `ScanVerdict`, `ThreatInfo`, `MimicThreat`, `YaraMatch`, `ScanConfig`, `MimicError`, `ThreatSeverity`. |
| **mimic-signatures** | ClamAV database loader (CVD/CLD extraction, parallel parse), hash/body/LDB/CDB matchers, Aho-Corasick automatons, file-type detection. |
| **mimic-detect** | Exploit detection (DNG, RTF, TTF, RAR, PDF, ZIP CVE); compiled to WASM and loaded as a plugin (no built-in). |
| **mimic-wasm** | WASM plugin loader (wasmtime); invokes `scan(ptr, len)` and merges verdicts. |
| **mimic-vt** | Built-in plugin; load with `--plugin path/mimic-vt.wasm`. VirusTotal v3 API client, hash-only lookups. Requires `--vt-key` when loaded. |
| **mimic-db** | SQLite: sessions, scan records, stats; used by CLI and web API. |
| **mimic-web** | Axum server: static dashboard, REST API, CORS; 512 MB default body limit. Dashboard: plugins list, scan results with decision details (“Why?”), VT result per file when configured, copy SHA256. With `--sandbox`, uploads are scanned via sandbox (temp file + worker). |
| **mimic-engine** | Orchestration: loads DBs, builds thread pool (or worker pool if `--sandbox`), dispatches files to scanners (signatures → mimic → YARA → WASM). |
| **mimic-sandbox** | Sandbox policy, worker pool (long-lived subprocesses), privilege drop, resource limits, seccomp (Linux), seatbelt (macOS). |
| **mimic-cli** | CLI (clap), `serve` subcommand, progress bars, scan summary. |
| **mimic-browser** | In-browser WASM scanner: ClamAV signatures, **mimic-detect** and **VirusTotal (mimic-vt)** built-in by default; YARA-like rules optional. One-click load fetches **data/clamav-db.zip** only from the same origin (no fetch to ClamAV or other external sites). You can also drop a `.zip` of signature files. Everything runs in the browser. |
| **mimic-mcp** | MCP server for LLMs: **scan_file** and **scan_bytes** over stdio or HTTP/HTTPS. Build with `--features http` and `--listen ADDR`; add `--features https` and `--tls-cert`/`--tls-key` for TLS. Use `-v`/`-vv` for debug/trace logging. |

**mimic-browser: run locally** — From the repo root: `./scripts/run-mimic-browser.sh` (see [Mimic browser](#mimic-browser-wasm-scanner-in-the-browser) under Build).

**mimic-browser: creating the signature zip** — One-click only loads from **data/clamav-db.zip**. From `crates/mimic-browser` run `./scripts/zip-data.sh` to create `www/data/clamav-db.zip` (excluding `.sign`/`.cdiff`/`.txt`). The one-click button then fetches and extracts it in the browser.

### Scan modes

- **In-process (default):** One Rayon thread pool. Each thread reads the file from disk, computes MD5/SHA256, then runs the full pipeline (ClamAV → mimic → YARA → WASM) on the same process. No isolation; fastest.
- **Sandbox (`--sandbox`):** A pool of **N** long-lived worker subprocesses (N = thread count). The main process does **not** read files; instead it sends `(file_path, max_size)` to a worker over stdin. The worker (hardened with seccomp/seatbelt and privilege drop) reads the file, computes hashes, and returns `(size, md5, sha256)` or an error on stdout. The main process then **re-reads the file** in-process to run signatures, mimic, YARA, and WASM. So with sandbox: read happens twice (once in worker for hashes, once in parent for scanning), but execution of untrusted file content is confined to the worker. The same flow applies to **single-file** scans (e.g. web uploads): when sandbox is enabled, the server writes the upload to a temp file, calls the sandboxed worker for that path, then runs the full analysis in-process; the result path shown to the user is the original filename.

**In-process (default):**

```
  ┌────────────┐     read file      ┌──────────────────────────────────────────────────┐
  │   Disk     │ ──────────────────► │  Rayon worker (same process)                    │
  │  /path/file│                     │  MD5/SHA256 → ClamAV → mimic → YARA → WASM      │
  └────────────┘                     │  → ScanResult                                    │
                                     └──────────────────────────────────────────────────┘
```

**Sandbox (`--sandbox`):**

```
  ┌────────────┐    JSON request     ┌─────────────────────┐
  │  Parent    │ ──────────────────► │  Worker (subprocess)│   read file, hash only
  │  (mimic)   │   path, max_size    │  seccomp/seatbelt    │ ──► size, md5, sha256
  └─────┬──────┘                     └──────────┬──────────┘
        │                                       │
        │◄──────────── JSON response ───────────┘
        │  size, md5, sha256 (no content)
        │
        ▼  parent re-reads file from disk
  ┌──────────────────────────────────────────────────┐
  │  ClamAV → mimic → YARA → WASM (in parent)         │
  │  → ScanResult                                     │
  └──────────────────────────────────────────────────┘
```

### Scanning pipeline (per file)

For each file, the engine runs (when enabled):

1. **Read file** — In-process: direct read. Sandbox: worker reads and returns size + MD5/SHA256; parent then reads the same path for analysis.
2. **Hash** — MD5 and SHA256 computed once (in-process or in worker).
3. **ClamAV signatures** — See [Signature matching phases](#signature-matching-phases).
4. **Mimic exploit detection** — DNG/RTF/TTF/RAR/PDF/ZIP CVE checks (e.g. Zombie ZIP CVE-2026-0866).
5. **YARA-X** — Rule compilation and matching.
6. **WASM plugins** — Each plugin’s `scan` called; verdicts merged (Infected > Suspicious > Clean > Error).

Result: `ScanResult` with `path`, `size_bytes`, `sha256`, `md5`, `scan_verdict` (signature_threats, mimic_threats, yara_matches), `scan_duration_us`, `error`.

```
  file bytes
       │
       ▼
  ┌─────────┐    ┌─────────────┐    ┌──────────┐    ┌─────────┐    ┌──────┐
  │  Hash   │───►│  ClamAV     │───►│  mimic-  │───►│ YARA-X  │───►│ WASM │
  │ MD5/SHA │    │  (HDB/NDB/  │    │  detect  │    │ (rules) │    │plugins│
  │         │    │   LDB/…)    │    │ (exploit)│    │         │    │       │
  └─────────┘    └─────────────┘    └──────────┘    └─────────┘    └───┬───┘
       │                │                  │               │            │
       └────────────────┴──────────────────┴───────────────┴────────────┘
                                         │
                                         ▼
                              merge verdicts → ScanResult
```

### ClamAV signature support

| Extension | Type | Description |
|-----------|------|-------------|
| `.cvd`, `.cld` | Container | Digitally signed archive; unpacked to inner `.hdb`, `.ndb`, etc. |
| `.hdb` | Hash | Whole-file MD5: `MD5:Size:Name`. |
| `.hsb` | Hash | Whole-file SHA256 (or SHA1): `Hash:Size:Name`. |
| `.mdb` | Hash | PE section MD5: `SectionSize:MD5:Name`. |
| `.msb` | Hash | PE section SHA256: `SectionSize:SHA256:Name`. |
| `.ndb` | Body | Extended signatures: name, target type, offset, hex pattern (fixed or wildcard). |
| `.ldb`, `.ldu` | Logical | Boolean combinations of subsignatures; target type filtering. |
| `.cdb` | Container | Container metadata (e.g. filename) signatures. |
| `.fp`, `.sfp` | Whitelist | False-positive: MD5 or SHA256 to ignore. |
| `.cbc` | Bytecode | Counted in “Known viruses”; not executed (no bytecode VM). |

**Total “Known viruses”** in the summary = sum of all loaded signature counts (MD5 + SHA256 + MDB + MSB + NDB fixed + NDB wildcard + LDB + CDB + bytecode), comparable to ClamAV’s reported count.

### Signature loading (0–100% progress bar)

When you pass `-d` with database paths, loading runs in five phases with a single 0–100% progress bar:

```
  -d path(s)
       │
       ▼
  ┌────────────┐  0–5%   ┌────────────┐  5–15%  ┌────────────┐  15–80%
  │ Read files │ ──────► │ Extract    │ ──────► │ Parse      │
  │ (CVD/raw)  │         │ CVD/CLD    │         │ (parallel) │
  └────────────┘         └────────────┘         └──────┬─────┘
                                                      │
  90–100%  ┌────────────┐  80–90%  ┌────────────┐    │
  ┌───────►│ Build AC   │◄─────────│ Merge into │◄───┘
  │        │ automatons │          │ hash/body/ │
  │        └────────────┘          │ ldb/cdb    │
  │                               └────────────┘
  └──► "[*] signatures loaded: …"
```

| Phase | Progress | Description |
|-------|----------|-------------|
| 1 | 0–5% | Read all database files in parallel (CVD/CLD and/or raw .hdb, .ndb, etc.). |
| 2 | 5–15% | Extract CVD/CLD containers; flatten to “signature units” (one per inner file). |
| 3 | 15–80% | Parse all units in parallel (Rayon); each unit updates the bar. |
| 4 | 80–90% | Merge parsed results into global hash_db, body_db, ldb_db, cdb_db. |
| 5 | 90–100% | Build Aho-Corasick automatons (body_db, ldb_db) and LDB eligible-rule sets. |

**CVD/CLD format:** A `.cvd`/`.cld` file is a 512-byte header (version, build time, signature count) followed by a gzipped tarball. The tarball contains inner files such as `main.ldb`, `main.ndb`, etc. Each inner file is decompressed and parsed as the corresponding signature type; its entries become “signature units” fed into the merge phase.

Then the line `[*] signatures loaded: …` is printed with per-type counts and total.

### Signature matching phases

Inside the ClamAV matcher, for each file (in order):

1. **Whole-file hash (O(1))** — Lookup MD5 and SHA256 (with size) in hash DB; FP/SFP whitelist applied.
2. **Body (NDB)** — One Aho-Corasick pass over file bytes. Fixed patterns and “atom” subpatterns from wildcards are in the same automaton; full wildcard verification only on atom hit. **Target-type filtering:** NDB rules with target 0 (“any”) are **not** applied to files detected as ASCII, HTML, or Mail (to avoid false positives on source code and text; we do not implement ClamAV text normalization). Other target types (PE, ELF, etc.) match only when file type equals the rule’s target.
3. **Logical (LDB)** — File type detected once (PE, ELF, Mach-O, PDF, OLE2, Flash, Graphics, HTML, Mail, ASCII, Java, Any). Rules are pre-partitioned by target type; only eligible rules are evaluated. **Logic expressions** support `&`, `|`, parentheses, and **count modifiers**: `0>5` (subsig 0 must match more than 5 times), `(0|1)>7,7` (block 0|1 must have total count >7 **and** at least 7 **distinct** subsigs matching). TDB constraints **FileSize:min-max** are enforced (file size must lie in range). Subsigs: fixed + wildcard-atom in one AC pass; linear wildcards (un-atomizable) only for eligible rules. Per-subsig **match counts** (not just hit/miss) are tracked so count/diversity conditions align with ClamAV.
4. **PE section hashes (MDB/MSB)** — Only if the file is PE; sections parsed, each section’s raw bytes hashed (MD5/SHA256) and looked up.

**File type detection** (magic bytes / heuristics): PE (MZ + PE\0\0), ELF (\x7FELF), Mach-O, PDF (%PDF), Java (CAFEBABE), OLE2 (D0CF11E0…), Flash (FWS/CWS/ZWS), Graphics (PNG, JPEG, GIF, BMP, TIFF), HTML (tags in first 1 KiB), Mail (From / Return-Path / etc.), ASCII (mostly printable). LDB rules targeting ASCII/HTML/Mail are skipped (ClamAV-style text normalization not implemented).

### Defaults and configuration

- **Threads:** 0 = `std::thread::available_parallelism()` (or 4 fallback).
- **Max file size:** 256 MiB (configurable via `--max-size`; 0 = no limit). Files over the limit are skipped with an error verdict.
- **Extensions:** Empty = all files; otherwise only listed extensions are scanned.
- **Sandbox:** Off by default; use `--sandbox` to enable worker-based scanning.

### Implementation notes (vs ClamAV)

- **Bytecode (.cbc):** Counted in “Known viruses” but **not executed**; no bytecode VM. Signatures that rely on bytecode are effectively disabled.
- **Text targets (ASCII/HTML/Mail):** NDB and LDB rules with target “any” (0) are **not** run on files classified as ASCII, HTML, or Mail, to avoid false positives; ClamAV uses normalization we do not implement.
- **LDB count and diversity:** Expressions like `(0|1|2)>7,7` require both total match count >7 and at least 7 distinct subsigs; this is enforced so results align with clamscan on typical databases (e.g. botnet/iot rules that need many distinct strings).
- **TDB FileSize:** If a rule’s Target Description Block specifies `FileSize:min-max`, the file’s size must lie in that range or the rule is skipped.
- **Subsig offset prefixes (EP+, SL+, etc.):** Subsigs that use ClamAV offset anchors (entry point, section, etc.) are currently **skipped** during load if the pattern cannot be parsed as plain hex; such rules may not fire.

---

## Security & sandboxing

With `--sandbox`, file reads and hashing run in a **pool of long-lived worker subprocesses**. Each worker is hardened once at startup and serves many scan requests over stdin/stdout (JSON). The worker returns only path, size, MD5, SHA256 (no file content over IPC). The main process re-reads each file from disk and runs signatures, YARA, mimic, and WASM in-process on that content.

```
  Parent process                          Worker 1    Worker 2   …
  ┌────────────────────────────────┐     ┌────────┐   ┌────────┐
  │  File list                     │     │ stdin  │   │ stdin  │
  │  ┌────┐ ┌────┐ ┌────┐          │     │ stdout │   │ stdout │
  │  │ f1 │ │ f2 │ │ f3 │ …        │     └───┬────┘   └───┬────┘
  │  └──┬─┘ └──┬─┘ └──┬─┘          │         │           │
  │     │      │      │   round-    │   read  │    read   │
  │     │      │      │   robin     │   hash  │    hash   │
  │     ▼      ▼      ▼             │         │           │
  │  ┌─────────────────────┐        │   JSON  │    JSON   │
  │  │ Worker pool         │ ──────┼──► req  │◄──► req   │
  │  │ (dispatch by index) │ ◄──────┼── resp  │    resp   │
  │  └──────────┬──────────┘        │  (path, │   (path,  │
  │             │                   │  size,  │   size,   │
  │             ▼                   │  md5,   │   md5,    │
  │  Parent re-reads file, runs     │  sha256)│   sha256) │
  │  ClamAV + mimic + YARA + WASM   │     │           │
  └────────────────────────────────┘     ▼           ▼
                                    seccomp/   seccomp/
                                    seatbelt   seatbelt
```

### SandboxPolicy (defaults)

| Field | Default | Description |
|-------|---------|-------------|
| `drop_uid` / `drop_gid` | 65534 (nobody) | UID/GID after reading the file (Linux/macOS). |
| `timeout_secs` | 30 | CPU time limit per worker (RLIMIT_CPU). |
| `max_memory_bytes` | 512 MiB | RLIMIT_AS (address space). |
| `enable_seccomp` | true | Linux: restrict syscalls (see below). |
| `enable_seatbelt` | true | macOS: sandbox profile applied via `sandbox-exec`. |

### Linux seccomp-bpf (allowed syscalls)

When `enable_seccomp` is true, only these syscalls are allowed in the worker:

`read`, `write`, `close`, `fstat`, `mmap`, `mprotect`, `munmap`, `brk`, `openat`, `lseek`, `getpid`, `exit_group`, `futex`, `clock_gettime`, `sched_yield`, `getrandom`, `sigaltstack`, `rt_sigaction`, `rt_sigprocmask`.

All others result in EPERM.

### macOS seatbelt

The worker runs under a profile that denies by default and allows: process-exec, process-fork, sysctl-read, mach-lookup; file-read for `/usr/lib`, `/System`, `/dev/urandom`, and optionally an `allowed_read_dir`; file-write only to `/dev/null`.

### Worker pool

- **Size:** Number of workers = configured thread count (same as `-j`).
- **Dispatch:** Round-robin by file index: file index `i` goes to worker `i % N`. Each worker is a long-lived child; parent sends one JSON line per request and reads one JSON line per response.
- **Lifecycle:** Fork → apply resource limits → setuid/setgid → (Linux) seccomp → (macOS) seatbelt is applied by parent via env before exec. Worker then loops: read one line from stdin (JSON), read file from disk, compute MD5/SHA256, write one line to stdout (JSON). No file content is sent over IPC; only path, size, hashes, and optional error string.

**IPC protocol (JSON, one message per line):**

- **Request (parent → worker):** `{"id": u64, "file_path": string, "max_size": u64}`  
- **Response (worker → parent):** `{"id": u64, "file_path": string, "size": u64, "md5": string, "sha256": string, "data_b64": null, "error": string|null}`  
  (`data_b64` is reserved; parent re-reads the file for scanning.)

### Sandbox logging

With `--sandbox`, use `RUST_LOG` to see worker and pool activity (worker stderr is inherited by the parent):

- `RUST_LOG=info` — Pool creation, worker spawn, worker ready, shutdown.
- `RUST_LOG=mimic_sandbox=debug` — Per-request dispatch (path, slot, request_id) and responses (size, error).
- `RUST_LOG=mimic_engine=debug` — Which files are sent to which worker slot and worker response timing.

CLI `-v` / `-vv` also increase log level for the main process; the worker process is started with a default verbosity so its lifecycle messages appear when the main process is run with `-v` or higher.

---

## Web dashboard & REST API

```
  Browser                    mimic serve (Axum)
  ┌──────────────┐           ┌─────────────────────────────────────┐
  │ GET /        │ ◄────────►│ static dashboard (HTML/JS in binary)│
  │ GET /api/*   │   JSON    │ GET/POST /api/stats, sessions,      │
  │ POST /api/   │           │   scan, search, vt/:sha256         │
  │   scan       │           │ SQLite (mimic.db) for persistence   │
  └──────────────┘           └─────────────────────────────────────┘
```

Start:

```bash
mimic --db-file mimic.db serve --listen 0.0.0.0:8080   # or: serve --db /path/to/clamav-db --plugin /path/to/plugin.wasm --vt-key KEY -vvv
```

- **Dashboard:** `GET /` serves static HTML/JS from the binary; UI loads sessions and records from the REST API, supports hash search, VirusTotal lookup (if key set), and one-click ClamAV DB load (browser fetches **data/clamav-db.zip** from same origin only—no external fetch—extract and load in-browser). Scan results show threats (ClamAV, mimic-detect, YARA) with details, optional VirusTotal section when VT is configured, and a copy-SHA256 button. “Why?” expands decision details (signatures, plugin, YARA, VT).
- **Backend:** Axum; one shared SQLite handle (`mimic.db`); 512 MB max body per request (multipart or JSON). CORS allows all origins.
- **Options after `serve`:** Use `--vt-key KEY` for VirusTotal and `-v` / `-vv` / `-vvv` for verbose logging (same as the classic CLI; e.g. `mimic serve -vvv --listen 0.0.0.0:8080`). Use `--sandbox` so that **each uploaded file** is written to a temp file and scanned via the sandboxed worker (same isolation as directory scans).
- **VT in scan response:** When VirusTotal is loaded (`--plugin .../mimic-vt.wasm`) and `--vt-key` is set, each file uploaded via `POST /api/scan` or `POST /api/scan/bytes` is looked up by hash after scanning; the response includes a `vt` object per result (found, positives/total, detections, permalink).

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Dashboard (static HTML). |
| `GET` | `/api/stats` | Database statistics (files, infected, bytes scanned, etc.). |
| `GET` | `/api/sessions` | List scan sessions. Query: `limit`, `offset`. |
| `GET` | `/api/sessions/:id/records` | Records for a session. Query: `limit`, `offset`. |
| `GET` | `/api/records/infected` | List infected records. Query: `limit`, `offset`. |
| `GET` | `/api/search?hash=<SHA256 or MD5>` | Lookup by hash. |
| `POST` | `/api/scan` | Multipart form: upload one or more files; optional query `session_id`. Returns `session_id` and `results` (array of `ScanResult`-like objects; each may include `vt` when VT is configured). With `--sandbox`, each file is written to a temp path and scanned via the sandboxed worker. |
| `POST` | `/api/scan/bytes` | JSON: `{ "filename": "...", "data_base64": "..." }`. Creates a session, runs one scan, returns single scan result (with optional `vt` when VT is configured). With `--sandbox`, uses temp file + sandboxed scan. |
| `GET` | `/api/vt/:sha256` | VirusTotal hash report (requires VT API key configured at server start). |

Responses are JSON; errors use HTTP status codes and a body like `{ "error": "..." }`.

---

## VirusTotal integration

- **Hash-only:** No file upload; only MD5/SHA256 of scanned files are looked up (when `--vt-key` or `MIMIC_VT_KEY` is set).
- **CLI:** Optional VT phase after scanning; results can be stored in DB and shown in summary.
- **Web API:** `GET /api/vt/{sha256}` for on-demand lookup. When VT is configured, **each file** submitted via `POST /api/scan` or `POST /api/scan/bytes` is looked up automatically; the JSON result includes a `vt` field (found, positives, total, detections, permalink) so the dashboard can show VT in the “Why?” decision details and in the threats column.

### Building mimic-vt

**mimic-vt** is a Rust library in the workspace; it is compiled automatically when you build the CLI or the full project.

**Build the WASM plugin (mimic-vt.wasm):**

The crate can be built as a minimal WASM plugin stub so you have a real file to pass to `--plugin`. The host uses its built-in VT client when this plugin is loaded; the .wasm itself only exports `scan(ptr, len) -> 0` (always clean).

```bash
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown -p mimic-vt --no-default-features
```

The plugin is produced at:

`target/wasm32-unknown-unknown/release/mimic_vt.wasm`

Use it as-is (the CLI accepts both `mimic-vt.wasm` and `mimic_vt.wasm` as the filename), or copy/rename to `mimic-vt.wasm`:

```bash
cp target/wasm32-unknown-unknown/release/mimic_vt.wasm ./mimic-vt.wasm
mimic serve --plugin ./mimic-vt.wasm --vt-key YOUR_KEY --listen 0.0.0.0:8080
```

**Build the library only (for the CLI binary):**

```bash
cargo build --release   # includes mimic-vt as a dependency
cargo build -p mimic-vt   # build the crate in library mode (default features)
```

### How to load mimic-vt (built-in plugin)

**mimic-vt** is a **built-in plugin** (like YARA): it is not loaded by default. Load it like any other plugin with `--plugin path/mimic-vt.wasm` (recognized by filename `mimic-vt.wasm`; the file does not need to exist). Set `--vt-key` or `MIMIC_VT_KEY` to enable lookups. It appears in the dashboard’s “Available Plugins & Scanners” list. You **activate** it by providing an API key:

1. **Web server (`mimic serve`):** pass `--plugin path/mimic-vt.wasm` and `--vt-key` so the dashboard and `GET /api/vt/:sha256` can perform lookups.
2. **CLI (file/dir scan):** pass `--plugin path/mimic-vt.wasm` and `--vt-key` (or `MIMIC_VT_KEY`) to enable VT hash lookups.

**Examples:**

```bash
# Load VirusTotal for the web dashboard (filename must be mimic-vt.wasm)
mimic serve --plugin ./mimic-vt.wasm --vt-key YOUR_VIRUSTOTAL_API_KEY --listen 0.0.0.0:8080

# Or use the environment variable
export MIMIC_VT_KEY=YOUR_VIRUSTOTAL_API_KEY
mimic serve --plugin ./mimic-vt.wasm --listen 0.0.0.0:8080

# Load VT for a directory scan
mimic /path/to/files -r --plugin ./mimic-vt.wasm --vt-key YOUR_VIRUSTOTAL_API_KEY
```

Without a plugin path whose filename is `mimic-vt.wasm`, the VT client is not loaded. With `--plugin .../mimic-vt.wasm` but no `--vt-key`, the dashboard shows “VirusTotal: not configured (set --vt-key)” until a key is set. Get an API key at [VirusTotal](https://www.virustotal.com/gui/join-us).

---

## MCP server (for LLMs)

The **mimic-mcp** crate is an [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) server that exposes Mimic scanning to LLM clients (Claude Desktop, Cursor, Windsurf, etc.). It can run on **stdio** (default) or over **HTTP** (Streamable HTTP transport) so clients can connect via API.

| Tool | Description |
|------|-------------|
| **scan_file** | Scan a file on disk. Argument: `path` (string). Returns full `ScanResult` (verdict, hashes, threats, match reasons). |
| **scan_bytes** | Scan in-memory content. Arguments: `filename` (string), `data_base64` (base64-encoded bytes). Returns full `ScanResult`. |
| **scan_directory** | Scan all files in a directory. Arguments: `path` (string), `recursive` (bool, default true). Returns list of `ScanResult` plus summary (total, infected, suspicious, clean). |
| **scan_paths** | Scan a list of file paths. Argument: `paths` (array of strings). Returns list of `ScanResult`. |
| **get_engine_info** | Return engine info: matcher stats, plugin names, signatures_loaded, yara_loaded, sandbox_enabled, max_file_size, source_stats (per-file signature counts). |
| **signature_lookup** | Short description of a ClamAV signature by `name` (malware ID) or `type` (e.g. hash-md5, body-ndb, logical-ldb). Explains signature types; no per-signature metadata stored in engine. |

**How to scan a file in chat (LM Studio, Claude, Cursor, etc.):** The model does **not** get access to files you attach in the UI. To scan a file you must **send the file path in your message** so the model can call `scan_file`. For example:

- *"Scan this file for malware: C:\\Users\\me\\Downloads\\document.pdf"* (Windows)
- *"Scan this file for malware: /home/user/Downloads/document.pdf"* (Linux/macOS)

The model will call the `scan_file` tool with that path and show you the verdict. Use an **absolute path** (or a path relative to the working directory of the mimic-mcp process). If you only paste or attach a file without a path, the model will correctly say it has no access to attachments and will ask for a path or base64 content.

**Build and run:**

```bash
cargo build --release -p mimic-mcp
./target/release/mimic-mcp -d /path/to/clamav-db -y /path/to/yara --plugin /path/to/mimic_detect.wasm
```

Options: `-d` / `--db` (ClamAV DB path, repeatable), `-y` / `--yara` (YARA path), `--plugin` (WASM plugin), `--max-size` (MB). By default the server uses **stdio**: it reads from stdin and writes to stdout; configure your LLM client to run this binary and communicate via stdio.

**HTTP (API) mode:** Build with the `http` feature and pass `--listen ADDR` to expose MCP over the [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#streamable-http) transport. Clients can then connect to `http://ADDR/mcp` with POST (JSON-RPC), GET (SSE), and DELETE (session). Use `-v` for debug or `-vv` for trace logging. Example:

```bash
cargo build --release -p mimic-mcp --features http
./target/release/mimic-mcp -d /path/to/clamav-db --listen 127.0.0.1:8010 -v
# MCP endpoint: http://127.0.0.1:8010/mcp
```

**HTTPS:** Build with `--features https` and use `--listen` to serve over TLS. If you omit `--tls-cert` and `--tls-key`, a self-signed certificate is generated automatically (valid for localhost, 127.0.0.1, ::1). To use your own certificate:

```bash
cargo build --release -p mimic-mcp --features https
# Auto-generated self-signed cert (no extra args):
./target/release/mimic-mcp -d /path/to/clamav-db --listen 127.0.0.1:8443
# Or provide your own PEM cert and key:
./target/release/mimic-mcp -d /path/to/clamav-db --listen 127.0.0.1:8443 --tls-cert cert.pem --tls-key key.pem
# MCP endpoint: https://127.0.0.1:8443/mcp
```

Use the same tools (`scan_file`, `scan_bytes`) over the API; any MCP client that supports Streamable HTTP can target this URL (e.g. programmatic or LLM backends that prefer HTTP over stdio). The first startup can take a while while the ClamAV database loads.

**Example client config (Claude Desktop `claude_desktop_config.json`):**

```json
{
  "mcpServers": {
    "mimic": {
      "command": "/path/to/mimic-mcp",
      "args": ["-d", "/var/lib/clamav", "-y", "/path/to/rules"]
    }
  }
}
```

The LLM can then call the `scan_file` or `scan_bytes` tool to check files for malware and receive structured verdicts and threat details.

**LM Studio:** LM Studio (0.3.17+) supports MCP and uses the same `mcp.json` style as Cursor. Open **Program** tab → **Install** → **Edit mcp.json** and add the `mimic` entry inside `mcpServers` (only the inner content, as per LM Studio’s instructions).

- **Stdio (recommended):** LM Studio will start mimic-mcp as a subprocess. Use the full path to your binary and your ClamAV DB path:

```json
"mimic": {
  "command": "/full/path/to/mimic-mcp",
  "args": ["-d", "/path/to/clamav-db", "-y", "/path/to/yara"]
}
```

  Replace `/full/path/to/mimic-mcp` with e.g. `target/release/mimic-mcp` from your Mimic repo, and set `-d` / `-y` to your signature paths. After saving `mcp.json`, the Mimic tools appear in the chat; you can ask the model to scan a file and it will call `scan_file` or `scan_bytes`.

- **HTTP:** Alternatively, run mimic-mcp as an HTTP server in a terminal (`mimic-mcp -d /path/to/db --listen 127.0.0.1:8010`), then in `mcp.json` add:

```json
"mimic": {
  "url": "http://127.0.0.1:8010/mcp"
}
```

---

## Sync ClamAV signatures & benchmark

- **Sync:** `python3 scripts/sync_clamav.py [OUTPUT_DIR]` — uses `freshclam` or `cvdupdate` (ClamAV CDN blocks direct HTTP).
- **Benchmark:** `./scripts/benchmark_clamav.sh [SCAN_DIR] [CLAMAV_DB_DIR]` — requires `clamscan`; prints time, throughput (files/s, MB/s), and speedup ratio vs ClamAV.

---

## WASM plugin ABI

- Plugins are loaded from paths given by `--plugin` (files or directories of `.wasm` files).
- Each plugin must export:
  - **Memory:** linear memory.
  - **`scan(ptr: i32, len: i32) -> i32`** — receives pointer and length to file bytes in memory; returns `0` = clean, `1` = suspicious, `2` = infected.
- Engine calls each plugin with the file content and merges verdicts (infected overrides suspicious overrides clean).

### Compiling plugins

**1. Rust plugin (e.g. mimic-detect)**

Install the WASM target and build the crate as a dynamic library for `wasm32`:

```bash
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown -p mimic-detect
```

The plugin is produced at:

`target/wasm32-unknown-unknown/release/mimic_detect.wasm`

Load it with the CLI or engine config:

```bash
mimic /path/to/scan -r --plugin target/wasm32-unknown-unknown/release/mimic_detect.wasm
```

Or point to a directory of `.wasm` files:

```bash
mimic /path/to/scan -r --plugin target/wasm32-unknown-unknown/release/
```

**2. Minimal WAT example**

A trivial “always clean” plugin is in the repo. Compile and load it with:

```bash
wat2wasm examples/plugin_example.wat -o examples/plugin_example.wasm
mimic /path -r --plugin examples/plugin_example.wasm
```

(`wat2wasm` is from the [WebAssembly Binary Toolkit](https://github.com/WebAssembly/wabt).)

**3. Custom Rust plugin**

Create a crate with `[lib]` including `crate-type = ["cdylib", "rlib"]`, and a `#[no_mangle] pub extern "C" fn scan(ptr: i32, len: i32) -> i32` that reads the buffer at `ptr`/`len` and returns 0 (clean), 1 (suspicious), or 2 (infected). Build with `cargo build --release --target wasm32-unknown-unknown -p your_plugin` and pass the resulting `.wasm` to `--plugin`.

---

## Debug logging

- **CLI:** `-v` = info, `-vv` = debug, `-vvv` = trace. With `-vvv`, only **mimic** crates are set to trace (dependencies like wasmtime stay at warn) so you see mimic logs without flood. Controls the main process (DB load, engine init, scan phases).
- **RUST_LOG:** Overrides the CLI filter. Use it to include or silence specific crates, e.g.:
  - `RUST_LOG=debug` — all crates at debug.
  - `RUST_LOG=mimic_signatures=debug,mimic_engine=info` — signatures debug, engine info.
  - `RUST_LOG=mimic_sandbox=debug` — sandbox pool and worker request/response details.
  - `RUST_LOG=trace` — full trace for every crate (noisy; wasmtime etc. will flood).

Useful for: ClamAV (files loaded, CVD headers, signature counts), YARA (rule files, compile), engine (thread pool, in-process vs sandbox path, per-file dispatch, scan phases), mimic_wasm (per-plugin scan start/done and verdict), sandbox (pool creation, worker spawn, privilege drop, seccomp/seatbelt, per-request IPC).

---

## License

Apache-2.0.
