---
name: ats-run-autests
description: Run Apache Traffic Server AuTests correctly via autest.sh from build/tests.
---

# Run AuTests

AuTests are end-to-end tests. They are Python-based but must be run through
`autest.sh`, not by invoking Python directly.

After build/install (see `../ats-build-ats/SKILL.md`), run tests from `build/tests`:

```bash
cd build/tests
./autest.sh --sandbox /tmp/sb --clean=none -f <test_name_without_.test.py>
```

Example for `show_ssl_multicert.test.py`:

```bash
cd build/tests
./autest.sh --sandbox /tmp/sb --clean=none -f show_ssl_multicert
```
