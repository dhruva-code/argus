# Parrot Security OS

Parrot gets the same first-class treatment as Kali (§48) — it is **not**
assumed to behave like Ubuntu just because both are Debian-based.

## Detection

`scripts/lib/os_detection.sh` reads `/etc/os-release` directly rather than
guessing; Parrot identifies itself as `ID=parrot`, which `install.sh` and
`doctor.sh` recognize explicitly (`OS_IS_PARROT=1`), separately from both
`kali` and generic `debian`.

```bash
./doctor.sh --check | head -10
```

```
SYSTEM
[OK]   Parrot Security OS (X.Y)
...
```

## What's different from a generic Debian install

- **Preinstalled security tools are respected**, exactly as on Kali — Parrot
  also ships a substantial toolset (including `nmap`) at `/usr/bin`.
  Argus-managed tools install to `ARGUS_TOOLS_BIN_DIR` (default
  `~/.local/bin`), never overwriting or shadowing Parrot's own copies.
- **No repository changes.** `install.sh` installs only from Parrot's
  existing APT sources; it never adds or edits
  `/etc/apt/sources.list*`.
- **Duplicate-binary detection** runs identically to Kali — see
  [KALI.md](KALI.md#what-is-different-from-a-generic-debian-install) for the
  exact output shape; the same `doctor.sh --tools` report applies here.
- **AnonSurf / Tor-related network tooling**: if you have AnonSurf active,
  outbound connectivity checks (`doctor.sh --network`) and any active
  reconnaissance you run through Argus will go through whatever routing
  AnonSurf has configured. This is a Parrot system feature, not something
  Argus manages — be deliberate about whether you want scan traffic routed
  through it, since some target authorization terms require traffic from a
  disclosed, stable source IP.

## Install

```bash
git clone <repo-url> Argus && cd Argus
./install.sh
./run.sh
```

## Known considerations

- Parrot's package versions can lag or lead Debian stable depending on the
  release channel you're tracking (`stable` vs `testing`/`rolling`);
  `config/tools.yaml`'s `minimum_version` pins are set conservatively enough
  to pass on either.
- Parrot Home vs Parrot Security editions both work — the difference is
  which security tools are preinstalled, not anything `install.sh` branches
  on. Missing tools are simply installed by `install.sh` as usual.
