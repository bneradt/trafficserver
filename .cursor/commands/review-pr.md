# Review a PR

Using gh, view the contents of the PR. Some good things to check for:

[ ] Expensive pass by copy rather than reference or pointer.
[ ] Opportunities for using modern C++ features.
[ ] Opportunities for using the lib/libswoc/ API, such as TextView.
[ ] Resource leaks
[ ] Duplicated code

And any other generic software issues you might see or issues with the
domain-specific patch.

Do not modify the PR, however. Only report back to me. I'll explicitly
ask you when I want you to add comments to a PR.
