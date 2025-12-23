-- AlterTable
ALTER TABLE "users" ADD COLUMN "encrypted_x25519_private" TEXT;
ALTER TABLE "users" ADD COLUMN "keypair_created_at" DATETIME;
ALTER TABLE "users" ADD COLUMN "x25519_password_salt" TEXT;
ALTER TABLE "users" ADD COLUMN "x25519_private_nonce" TEXT;
ALTER TABLE "users" ADD COLUMN "x25519_public_key" TEXT;

-- CreateTable
CREATE TABLE "library_encryption_metadata" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "library_id" TEXT NOT NULL,
    "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" DATETIME NOT NULL,
    "crypto_version" INTEGER NOT NULL DEFAULT 1,
    "verification_tag" BLOB NOT NULL
);

-- CreateTable
CREATE TABLE "secure_library_access" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "user_id" TEXT NOT NULL,
    "library_id" TEXT NOT NULL,
    "encrypted_lmk" TEXT NOT NULL,
    "lmk_ephemeral_public" TEXT NOT NULL,
    "lmk_nonce" TEXT NOT NULL,
    "granted_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "granted_by" TEXT NOT NULL,
    "revoked_at" DATETIME,
    "revoked_by" TEXT
);

-- CreateTable
CREATE TABLE "revoked_jwts" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "jti" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "revoked_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revoked_by" TEXT NOT NULL,
    "reason" TEXT,
    "expires_at" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "crypto_audit_log" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "event_type" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "target_type" TEXT,
    "target_id" TEXT,
    "ip_address" TEXT,
    "user_agent" TEXT,
    "details" TEXT,
    "succeeded" BOOLEAN NOT NULL DEFAULT true,
    "error_message" TEXT,
    "timestamp" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- RedefineTables
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_library_configs" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "convert_rar_to_zip" BOOLEAN NOT NULL DEFAULT false,
    "hard_delete_conversions" BOOLEAN NOT NULL DEFAULT false,
    "default_reading_dir" TEXT NOT NULL DEFAULT 'ltr',
    "default_reading_mode" TEXT NOT NULL DEFAULT 'paged',
    "default_reading_image_scale_fit" TEXT NOT NULL DEFAULT 'height',
    "generate_file_hashes" BOOLEAN NOT NULL DEFAULT false,
    "generate_koreader_hashes" BOOLEAN NOT NULL DEFAULT false,
    "process_metadata" BOOLEAN NOT NULL DEFAULT true,
    "library_pattern" TEXT NOT NULL DEFAULT 'SERIES_BASED',
    "watch" BOOLEAN NOT NULL DEFAULT true,
    "thumbnail_config" BLOB,
    "ignore_rules" BLOB,
    "library_id" TEXT
);
INSERT INTO "new_library_configs" ("convert_rar_to_zip", "default_reading_dir", "default_reading_image_scale_fit", "default_reading_mode", "generate_file_hashes", "generate_koreader_hashes", "hard_delete_conversions", "id", "ignore_rules", "library_id", "library_pattern", "process_metadata", "thumbnail_config", "watch") SELECT "convert_rar_to_zip", "default_reading_dir", "default_reading_image_scale_fit", "default_reading_mode", "generate_file_hashes", "generate_koreader_hashes", "hard_delete_conversions", "id", "ignore_rules", "library_id", "library_pattern", "process_metadata", "thumbnail_config", coalesce("watch", true) AS "watch" FROM "library_configs";
DROP TABLE "library_configs";
ALTER TABLE "new_library_configs" RENAME TO "library_configs";
CREATE TABLE "new_media" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "size" BIGINT NOT NULL,
    "extension" TEXT NOT NULL,
    "pages" INTEGER NOT NULL,
    "updated_at" DATETIME NOT NULL,
    "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "modified_at" DATETIME,
    "deleted_at" DATETIME,
    "hash" TEXT,
    "koreader_hash" TEXT,
    "path" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'READY',
    "is_encrypted" BOOLEAN NOT NULL DEFAULT false,
    "encrypted_filename" TEXT,
    "encryption_nonce" TEXT,
    "encryption_tag" TEXT,
    "original_file_size" BIGINT,
    "padded_file_size" BIGINT,
    "encrypted_path" TEXT,
    "encryption_completed_at" DATETIME,
    "series_id" TEXT,
    CONSTRAINT "media_series_id_fkey" FOREIGN KEY ("series_id") REFERENCES "series" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
INSERT INTO "new_media" ("created_at", "deleted_at", "extension", "hash", "id", "koreader_hash", "modified_at", "name", "pages", "path", "series_id", "size", "status", "updated_at") SELECT "created_at", "deleted_at", "extension", "hash", "id", "koreader_hash", "modified_at", "name", "pages", "path", "series_id", "size", "status", "updated_at" FROM "media";
DROP TABLE "media";
ALTER TABLE "new_media" RENAME TO "media";
CREATE TABLE "new_libraries" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "path" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'READY',
    "last_scanned_at" DATETIME,
    "updated_at" DATETIME NOT NULL,
    "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "emoji" TEXT,
    "config_id" TEXT NOT NULL,
    "job_schedule_config_id" TEXT,
    "is_secure" BOOLEAN NOT NULL DEFAULT false,
    "encryption_status" TEXT NOT NULL DEFAULT 'NOT_ENCRYPTED',
    "encrypted_at" DATETIME,
    "encryption_started_at" DATETIME,
    "total_files" INTEGER NOT NULL DEFAULT 0,
    "encrypted_files" INTEGER NOT NULL DEFAULT 0,
    "encryption_progress" REAL NOT NULL DEFAULT 0.0,
    "encryption_error" TEXT,
    CONSTRAINT "libraries_config_id_fkey" FOREIGN KEY ("config_id") REFERENCES "library_configs" ("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "libraries_job_schedule_config_id_fkey" FOREIGN KEY ("job_schedule_config_id") REFERENCES "job_schedule_configs" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
INSERT INTO "new_libraries" ("config_id", "created_at", "description", "emoji", "id", "job_schedule_config_id", "last_scanned_at", "name", "path", "status", "updated_at") SELECT "config_id", "created_at", "description", "emoji", "id", "job_schedule_config_id", "last_scanned_at", "name", "path", "status", "updated_at" FROM "libraries";
DROP TABLE "libraries";
ALTER TABLE "new_libraries" RENAME TO "libraries";
CREATE UNIQUE INDEX "libraries_name_key" ON "libraries"("name");
CREATE UNIQUE INDEX "libraries_path_key" ON "libraries"("path");
CREATE UNIQUE INDEX "libraries_config_id_key" ON "libraries"("config_id");
PRAGMA foreign_key_check;
PRAGMA foreign_keys=ON;

-- CreateIndex
CREATE UNIQUE INDEX "library_encryption_metadata_library_id_key" ON "library_encryption_metadata"("library_id");

-- CreateIndex
CREATE UNIQUE INDEX "secure_library_access_user_id_library_id_key" ON "secure_library_access"("user_id", "library_id");

-- CreateIndex
CREATE UNIQUE INDEX "revoked_jwts_jti_key" ON "revoked_jwts"("jti");

-- CreateIndex
CREATE INDEX "revoked_jwts_jti_idx" ON "revoked_jwts"("jti");

-- CreateIndex
CREATE INDEX "revoked_jwts_expires_at_idx" ON "revoked_jwts"("expires_at");

-- CreateIndex
CREATE INDEX "crypto_audit_log_event_type_idx" ON "crypto_audit_log"("event_type");

-- CreateIndex
CREATE INDEX "crypto_audit_log_user_id_idx" ON "crypto_audit_log"("user_id");

-- CreateIndex
CREATE INDEX "crypto_audit_log_timestamp_idx" ON "crypto_audit_log"("timestamp");
