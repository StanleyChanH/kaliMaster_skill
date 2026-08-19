# Contributing to kali-master

Thanks for your interest in improving this skill! This guide covers the two
main contribution paths.

## Ways to contribute

- **Fix a wrong command** — CLI flags change over time; if a documented command
  fails on current Kali, a fix is the most valuable PR you can make.
- **Update stale data** — tools get added/removed upstream on kali.org.
- **Improve a domain reference** — better decision tables, missing tactics,
  clearer practical notes.
- **Add examples** — real-world usage patterns (authorized engagements, CTF
  write-ups) distilled into command blocks.

## Workflow

1. Fork & branch:
   ```bash
   git checkout -b fix/<short-description>
   ```
2. Make your change. Files you are most likely to touch:
   - `kali-master/references/*.md` — domain docs (keep the three-section
     structure: 快速决策表 / 核心工具详解 / 其余工具速查)
   - `kali-master/SKILL.md` — routing & principles (entry file; keep it lean)
   - `build/` — data pipeline (see [build/README.md](build/README.md))
3. **Rules for commands:**
   - Must be real and executable on current Kali rolling.
   - Placeholders use angle brackets: `<target>`, `<domain>`, `<hash>`.
   - Verify against the tool's official docs or `-h` output — never from memory
     alone.
4. Run the health check locally:
   ```bash
   python build/integrity_check.py
   ```
   CI runs the same check on every PR; it must pass.
5. Commit with a concise message and open a PR describing what changed and how
   you verified it.

## Rebuilding data from kali.org

```bash
cd build
python fetch_pages.py     # scrape (re-run safe, 12 workers)
python parse_pages.py     # HTML -> structured JSON
python split_shards.py    # per-domain shards
python gen_index.py       # regenerate tool-index.md
```

Note: domain reference docs (`references/*.md`) are authored content, not
generated — after rebuilding data, diff shards against the docs manually.

## Commit style

- Imperative mood: `fix gospider thread-flag semantics`, not `fixed`
- One logical change per commit.
- For command fixes, include how you verified the new flag set (man page,
  upstream README, `-h` output, etc.).

## Reporting issues

Include: the exact command, the file & line, the Kali version
(`cat /etc/os-release`), and the tool version (`<tool> --version`).

## License

By contributing, you agree your contributions are licensed under the repo's
[MIT license](LICENSE).
