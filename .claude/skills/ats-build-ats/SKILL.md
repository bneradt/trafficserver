---
name: ats-build-ats
description: Build, install, format, and generate docs for Apache Traffic Server using CMake workflows.
---

# Build Apache Traffic Server

ATS is a CMake project typically built with Ninja.

- Helper scripts may exist in `~/bin/` for initial setup.
- Once `build/` exists, prefer incremental builds with `cmake --build build`.

## Container + worktree path mismatch

Work is often done from a shared directory between the host and a docker
container running a version of the docker container that CI uses. Build are
done in the container, while modifications are done on the host. The ~/bin
scripts mentioned below are in the docker container, so keep that in mind.

If this checkout is a git worktree created on the host (for example under
`/Users/...`) but built from a docker container mount (for example
`/home/bneradt/shared/...`), git metadata lookups can fail during CMake
configure. In that case, set git path env vars to container-visible paths before
invoking build commands:

```bash
export GIT_DIR=/home/bneradt/shared/ts_asf/.git/worktrees/targeted_cache_control
export GIT_COMMON_DIR=/home/bneradt/shared/ts_asf/.git
export GIT_WORK_TREE=/home/bneradt/shared/targeted_cache_control
```

Then run the normal build (`~/bin/build_ats` or direct `cmake` commands).

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
