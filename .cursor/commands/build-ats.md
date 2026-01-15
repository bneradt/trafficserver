# Build Apache Traffic Server

ATS is a cmake project that I build using ninja.

- I have helper scripts in ~/bin/ to run the initial cmake command and build it.
- Subsequent builds, after the `build` directory is created can be built simply with cmake --build

## First build

Use this generally for the initial build:
~/bin/build_ats

Use this if unit tests are required:
~/bin/build_ats_ut

## Subsequent builds

If the `build` directory exists already, then don't waste time with a full
cmake -B command via those `build_ats` scripts. Simply do the following:

```
cmake --build build
cmake --install build
```

## Formatting

Before doing any commit, make sure the code is formatted. A pre-commit hook
will prevent the commit if it is not formatted.

```
cmake --build build --target format
```

## Docs Build

Doc builds are easier:

```
cmake -B docs-build --preset ci-docs
cmake --build docs-build --target generate_docs -v
```
