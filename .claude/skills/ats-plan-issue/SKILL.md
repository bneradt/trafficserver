---
name: ats-plan-issue
description: Read a GitHub issue with gh and produce an implementation and verification plan for ATS.
---

# Plan an Issue Fix

Using `gh`, read the issue and produce an implementation plan.

- Understand the issue description and inspect relevant code paths.
- Plan tests for the fix (Catch2 and/or autest as appropriate). See `../ats-writing-autests/SKILL.md`.
- Plan the production code changes.
- Include build and verification steps using `../ats-build-ats/SKILL.md` and `../ats-run-autests/SKILL.md`.

Unless asked otherwise, do not post comments to the issue.
