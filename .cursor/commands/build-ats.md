# Build Apache Traffic Server

ATS is a CMake project typically built with Ninja.

- Helper scripts may exist in `~/bin/` for initial setup.
- Once `build/` exists, prefer incremental builds with `cmake --build build`.

## First build

Preferred (if available):

```bash
~/bin/build_ats
```

If unit-test setup is required:

```bash
~/bin/build_ats_ut
```

Fallback if helper scripts are unavailable:

```bash
cmake -B build
cmake --build build
cmake --install build
```

## Subsequent builds

If `build/` already exists, avoid full reconfigure unless needed:

```bash
cmake --build build
cmake --install build
```

## Formatting

Before committing, run formatting:

```bash
cmake --build build --target format
```

## Docs Build

To generate docs:

```bash
cmake -B docs-build --preset ci-docs
cmake --build docs-build --target generate_docs -v
```
