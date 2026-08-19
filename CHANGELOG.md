# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1/);
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

### Added
- `install.sh` — one-command install (user-level or `--project`)
- Monthly data-refresh GitHub Action: re-scrapes kali.org, opens a refresh PR
- Community health files: `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CITATION.cff`
- README installation / maintenance / contributing sections (bilingual)
- 13 `good first issue` i18n tasks + tracking issue for translating the
  domain references to English

### Fixed
- Tool-index generator emitted each domain section once per tool (4 MB /
  24k lines); now one section per domain — 540 lines, 470 unique rows
- Stale size note in SKILL.md; index-lookup guidance now uses the Grep tool
  consistently
- Example-count claim corrected to the verified figure (144 tools with
  official usage examples)
- Refresh workflow: same-month reruns now force-push the branch and tolerate
  an already-open PR; PR no longer sweeps in transient fetch artifacts
- CI / integrity check now assert index uniqueness (no duplicated rows,
  exactly 13 domain sections)

## [1.0.0] — 2026-08-18

### Added
- 470-tool dataset scraped from official kali.org/tools (16 ATT&CK tactic
  categories, official usage examples for 144 tools, full apt install info)
- `kali-master` skill: entry router (SKILL.md), 13 domain references,
  3 workflow playbooks, full tool index, environment self-check script
- Build pipeline: fetch → parse → shard → index regeneration + one-command
  integrity check
- CI workflow (integrity + index-format checks)
- Bilingual README (English primary, README.zh-CN.md)
- Issue/PR templates (bug = command correction, tool request)
- Release v1.0.0

### Quality
- All 16 documents independently verified; 61 command errors found and fixed
  (outdated flags, swapped options, CLI breaking changes)
