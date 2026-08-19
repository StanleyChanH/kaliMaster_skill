# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1/);
versioning follows [SemVer](https://semver.org/).

## [1.0.0] — 2026-08-18

### Added
- 470-tool dataset scraped from official kali.org/tools (16 ATT&CK tactic
  categories, 337 official usage examples, full apt install info)
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
