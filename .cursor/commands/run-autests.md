# Run the autests

The autests are automated end to end tests, see @writing-autests.mdc.

They are not run via directly calling the python interpreter, despite being .py
files. That won't work. Rather they must be run via the autest.sh script in the
build directory.

After building and installing ATS (see @build-ats.md):

```
cd build/tests
./autest.sh --sandbox /tmp/sb --clean=none -f test_name...
```

The `test_name` passed there is the name of the autest without the .test.py
exension. Thus, to run the `show_ssl_multicert.test.py` test, you would:


```
cd build/tests
./autest.sh --sandbox /tmp/sb --clean=none -f show_ssl_multicert
```
