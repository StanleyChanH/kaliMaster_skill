# Security Policy

## Scope

This repository ships **documentation and orchestration guidance** (a Claude
Code skill). It contains no executable attack code — commands documented here
invoke standard Kali Linux tools that users run themselves.

## Reporting a vulnerability in this repo

If you find a security issue in the repo itself (e.g., a malicious pattern in
scripts, unsafe install flow):

1. Prefer **private reporting**: use GitHub's *Report a vulnerability*
   (Security → Advisories) on this repository.
2. If unavailable, open an issue titled `security:` with no exploit details
   and wait for a maintainer reply before sharing more.

## Responsible use

The skill is for **authorized** testing only (see README). Misuse reports,
requests to attack third parties, or questions about unauthorized access will
be closed without answer.

## Tool-command accuracy

Documented commands can lag behind upstream CLI changes. Wrong-flag reports
are treated as bugs — use the *Bug report* issue template and include your
Kali/tool version.
