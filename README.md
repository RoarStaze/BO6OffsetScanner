# BO6 Offset Scanner

A small **offline/static PE signature scanner** for Call of Duty: Black Ops 6 reverse-engineering workflows.

The main workflow is intentionally simple:

1. Choose a BO6 executable or PE dump you are authorized to analyze.
2. Choose a JSON signature database.
3. Click **Scan**.
4. Review resolved, missing, or ambiguous signatures.
5. Export the current RVAs as JSON or a C++ header.

> This project does not attach to the live BO6 process, bypass Ricochet, inject code, or modify online gameplay.

## Why this exists

Game updates frequently move RVAs. Stable byte signatures can often relocate the same function/data reference in a new build. The scanner records both the previous RVA and the newly resolved RVA so an update can be reviewed as a delta rather than rediscovered manually.

## Features

- Tkinter GUI with a single **Scan** action.
- PE32/PE32+ section parsing.
- IDA-style byte signatures with `?` / `??` wildcards.
- Optional section-scoped scans, e.g. `.text`.
- Direct match resolution.
- x86/x64 `rel32` target resolution for relative CALL/JMP/RIP-relative-style references.
- Expected-match validation to flag ambiguous signatures.
- Previous-RVA tracking and delta display.
- SHA-256 fingerprinting of each analyzed build.
- JSON export with scan metadata.
- C++ header export for resolved RVAs.
- CLI scanner for automation and CI.

## Requirements

- Python 3.10+
- Tkinter (included with standard Windows Python installers)

No third-party Python packages are required.

## Run

```bash
python app.py
```

Or from the command line:

```bash
python tools/scan_cli.py path/to/game.exe config/signatures.json --json offsets.json --cpp offsets.hpp
```

## Signature database

Copy `config/signatures.example.json` to `config/signatures.json` and replace the example entries with signatures you are authorized to use.

A direct match:

```json
{
  "name": "SomeSymbol",
  "pattern": "48 89 ?? ?? 57 48 83 EC ??",
  "section": ".text",
  "expectedMatches": 1,
  "previousRva": "0x123456",
  "resolver": { "kind": "match", "addend": 0 }
}
```

A relative target:

```json
{
  "name": "SomeCallTarget",
  "pattern": "E8 ?? ?? ?? ?? 48 8B",
  "section": ".text",
  "expectedMatches": 1,
  "resolver": {
    "kind": "rel32",
    "displacementOffset": 1,
    "nextInstructionOffset": 5,
    "addend": 0
  }
}
```

For `rel32`, the scanner computes:

```text
target_rva = match_rva + nextInstructionOffset + signed_disp32 + addend
```

## Status meanings

- `resolved` — match count met expectations and the RVA was calculated.
- `missing` — no match was found; the signature likely changed or the wrong build/file was selected.
- `ambiguous` — the pattern matched a different number of locations than expected.
- `error` — the signature or resolver configuration could not be evaluated.

## Updating after a patch

The intended maintenance loop is:

```text
old build + known signature database
              |
              v
        new BO6 PE/dump
              |
          click Scan
              |
   +----------+-----------+
   |          |           |
resolved   missing    ambiguous
   |          |           |
new RVA   inspect/re-  strengthen
          signature    signature
```

A scanner cannot guarantee that a stale signature will magically discover a semantically changed function. Missing/ambiguous entries are deliberately surfaced instead of guessing an offset.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Attribution

This project was inspired by the public `iamtherealcat/coddumper` BO6 signature-scanner concept. That repository is MIT-licensed. This implementation is a clean offline/static rewrite and does not copy its live-process scanning path or redistribute its BO6-specific signature database.

See `THIRD_PARTY_NOTICES.md`.

## License

MIT. See `LICENSE`.
