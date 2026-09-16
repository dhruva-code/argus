# Kali Linux

Kali gets first-class handling from `install.sh`/`doctor.sh` (§47 of the
installer spec), not best-effort Ubuntu treatment.

## What's different from a generic Debian install

- **Preinstalled security tools are respected.** Kali ships `nmap`, and
  often older or newer builds of some ProjectDiscovery/OSS tools, at
  `/usr/bin`. `install.sh` never overwrites those — Argus-managed tools
  (installed via `go install`, an upstream script, or a release tarball)
  always land in `ARGUS_TOOLS_BIN_DIR` (default `~/.local/bin`), a separate
  location from Kali's own package-managed binaries.
- **No repository changes.** `install.sh` never adds a third-party APT
  source or modifies `/etc/apt/sources.list*` on Kali — everything it
  installs via `apt` comes from Kali's existing repositories, and
  Argus-managed tools bypass `apt` entirely (Go toolchain / release
  binaries).
- **Duplicate-binary detection.** When a tool name resolves to more than one
  executable on `$PATH` (e.g. `/usr/bin/nmap` and a newer one you built
  yourself), `doctor.sh --tools` reports every location found and which one
  currently wins on `$PATH`, rather than silently picking one:

  ```
  [WARN] multiple 'nmap' binaries found on this system:
      /usr/bin/nmap        Nmap version 7.94
      /usr/local/bin/nmap  Nmap version 7.98
  [INFO] PATH currently resolves 'nmap' -> /usr/bin/nmap
  ```

  Resolve it deterministically by reordering `$PATH` yourself, or removing
  the one you don't want — Argus won't guess for you.

## Install

```bash
sudo apt update              # Kali's own index — install.sh does this itself too
git clone <repo-url> Argus && cd Argus
./install.sh
./run.sh
```

Kali already has Python 3.11+, `build-essential`-equivalent tooling, and
often Go — `install.sh` detects and reuses all of it rather than reinstalling.
It also installs/configures Ollama + a Qwen model (skip with `--no-ai`) and
creates the bootstrap admin account automatically — see
[INSTALL.md](INSTALL.md) and [AI.md](AI.md). There is no setup wizard to
click through; log in with the printed bootstrap credentials.

## sudo

Kali's default user typically already has passwordless `sudo`. `install.sh`
only invokes `sudo` for actual system-package installs (`apt-get install`)
and starting a native `systemd` service — never for running the application
itself. If your Kali install doesn't have passwordless sudo configured,
you'll be prompted normally by `sudo` when needed.

## Known considerations

- Kali's rolling-release model means `apt` package versions move fast;
  `config/tools.yaml`'s `minimum_version` is deliberately conservative so a
  slightly newer Kali-packaged tool still passes health checks.
- If you run Argus's own scan tooling *and* use Kali's preinstalled copies
  for manual work, expect both to show up in `doctor.sh --tools`'s
  duplicate-binary report — that's expected, not an error.
