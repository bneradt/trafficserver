# Run AuTests

AuTests are end-to-end tests. They are Python-based but must be run through
`autest.sh`, not by invoking Python directly.

After build/install (see @build-ats.md), run tests from `build/tests`:

```bash
cd build/tests
./autest.sh --sandbox /tmp/sb --clean=none -f <test_name_without_.test.py>
```

Example for `show_ssl_multicert.test.py`:

```bash
cd build/tests
./autest.sh --sandbox /tmp/sb --clean=none -f show_ssl_multicert
```
