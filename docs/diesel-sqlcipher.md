# Diesel + SQLCipher Setup

This project uses Diesel (SQLite backend) with SQLCipher for full database encryption at rest.

## Linking against SQLCipher

Ensure the runtime links to SQLCipher rather than stock SQLite. Common options:

- Linux (Debian/Ubuntu): `apt-get install libsqlcipher-dev` then set `LIBSQLITE3_SYS_USE_PKG_CONFIG=1` so `libsqlite3-sys` finds `sqlcipher` via pkg-config.
- macOS (Homebrew): `brew install sqlcipher` then export `PKG_CONFIG_PATH="$(brew --prefix)/opt/sqlcipher/lib/pkgconfig"` and set `LIBSQLITE3_SYS_USE_PKG_CONFIG=1`.
- Windows: Install SQLCipher binaries and ensure they are discoverable by the linker. You may need to provide a custom `pkg-config` file or link directives.

Verify at runtime: we query `PRAGMA cipher_version;` when acquiring connections. If this fails, SQLCipher is not available or the key is incorrect.

## Connection initialization

We run `PRAGMA key = "x'<HEX>'";` as the first operation on every new connection. Only after the key is set, we enable `foreign_keys`, set `journal_mode=WAL`, and other PRAGMAs.

## Migrations

Migrations are managed via `diesel_migrations`. For now the schema is empty; add migration files under `core/migrations` as needed.
