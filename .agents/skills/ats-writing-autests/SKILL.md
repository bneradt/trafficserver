---
name: ats-writing-autests
description: Guidance for adding Apache Traffic Server autests, with a preference for replay-based end-to-end tests.
---

# Write ATS AuTests

Use this skill when adding or planning end-to-end test coverage in Apache Traffic Server.

For comprehensive documentation on writing autests, see:

- `doc/developer-guide/testing/autests.en.rst`

Most test coverage comes from end-to-end autests in `tests/gold_tests`.
When adding a new end-to-end test, prefer `Test.ATSReplayTest()` with
configuration and traffic defined in `replay.yaml`.
