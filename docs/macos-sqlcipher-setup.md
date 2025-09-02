# macOS setup for Diesel + SQLCipher

This project uses Diesel (SQLite backend) with SQLCipher for DB-level encryption. On macOS, the easiest path is Homebrew.

## Prerequisites

- Xcode Command Line Tools installed
- Homebrew installed

## Install SQLCipher

```bash
brew install sqlcipher
```

Optionally, confirm the library:

```bash
pkg-config --modversion sqlcipher
```

## Environment for cargo builds

Tell libsqlite3-sys/rusqlite/diesel to use pkg-config and prefer SQLCipher.

```bash
export LIBSQLITE3_SYS_USE_PKG_CONFIG=1
export PKG_CONFIG_PATH="/opt/homebrew/opt/sqlcipher/lib/pkgconfig:/usr/local/opt/sqlcipher/lib/pkgconfig:$PKG_CONFIG_PATH"
```

If you are on Intel Macs, replace `/opt/homebrew` with `/usr/local`.

You generally do NOT need to set SQLITE3_INCLUDE_DIR or SQLITE3_LIB_DIR on macOS when using pkg-config.

## Verify symbols (optional)

```bash
otool -L $(pkg-config --variable=libdir sqlcipher)/libsqlcipher.dylib
```

## Build + tests (core only)

```bash
cargo test -p stump_core --no-run
```

If you see sqlite3_serialize/sqlite3_deserialize unresolved, double-check PKG_CONFIG_PATH points to sqlcipher’s pkgconfig directory and that LIBSQLITE3_SYS_USE_PKG_CONFIG=1 is exported in the same shell.

## Runtime verification

- Start the server and unlock; Diesel will issue `PRAGMA key` as the first statement and verify `cipher_version`.
- In logs, you should see a successful pool acquisition and migrations applied.

## Notes

- On Linux, install `libsqlcipher-dev` or distro equivalent and set `LIBSQLITE3_SYS_USE_PKG_CONFIG=1` similarly.
- On Windows, vcpkg is supported but requires aligning features; building and testing on macOS first is recommended.
