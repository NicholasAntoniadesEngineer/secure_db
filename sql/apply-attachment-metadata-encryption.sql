-- ============================================================================
-- H-6: ENCRYPT ATTACHMENT METADATA AT REST (run ONCE in the SQL Editor)
-- ============================================================================
-- Audit finding H-6: message_attachments stored file_name, mime_type and the
-- EXACT file_size in PLAINTEXT ("stored unencrypted for querying"), so a curious /
-- compromised server could read original filenames, MIME types and exact byte
-- counts of every attachment despite the file BYTES being E2E-encrypted. Filenames
-- routinely carry the most sensitive content (e.g. "divorce_settlement.pdf"), and
-- the exact size enables known-file fingerprinting against the encrypted blob.
--
-- THE FIX (client side, see messaging/services/attachmentService.js):
--   * file_name + mime_type + exact file_size are sealed CLIENT-SIDE into an
--     encrypted_metadata blob (XSalsa20-Poly1305 under the conversation's INVARIANT
--     attachment KEK — the same key the file key is wrapped with, W3-2), with a
--     separate metadata_nonce.
--   * the server only ever sees file_size_bucket — a COARSE, rounded-UP size — so
--     no exact byte count leaks.
--   * the old plaintext columns are NO LONGER written by current clients.
--
-- THIS MIGRATION (server side): make the schema accept the new shape WITHOUT
-- breaking the rows that already exist.
--   * ADD file_size_bucket / encrypted_metadata / metadata_nonce (nullable).
--   * RELAX the NOT NULL on the legacy file_name / file_size / mime_type columns so
--     new clients can stop writing them. The legacy columns are KEPT (nullable) so
--     pre-migration rows stay readable (the client falls back to them).
--
-- ADDITIVE / IDEMPOTENT ONLY. This migration NEVER drops a table, never rewrites or
-- deletes existing rows, and is safe to re-run (every statement is guarded). It is
-- also folded into secure_db/sql/complete-setup.sql and
-- money_tracker/database/setup/fresh-install-complete.sql for fresh installs.
--
-- RLS is UNCHANGED: attachments_select_participant already scopes rows to the
-- conversation's participants; this migration does not touch any policy or grant.
--
-- DEPLOY ORDER: run this BEFORE (or together with) shipping the client that stops
-- writing the plaintext columns. The new client inserts NULL file_name/size/type, so
-- the old NOT NULL constraints must already be relaxed or the INSERT would be
-- rejected. Old clients keep working (they still write the legacy columns, which
-- remain present).
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- NEW COLUMNS — private metadata blob + coarse size bucket. ADD IF NOT EXISTS so
-- re-running is a no-op and an already-migrated DB is untouched.
-- ----------------------------------------------------------------------------
ALTER TABLE message_attachments ADD COLUMN IF NOT EXISTS file_size_bucket   BIGINT;
ALTER TABLE message_attachments ADD COLUMN IF NOT EXISTS encrypted_metadata TEXT;
ALTER TABLE message_attachments ADD COLUMN IF NOT EXISTS metadata_nonce     TEXT;

-- ----------------------------------------------------------------------------
-- RELAX legacy NOT NULL constraints so new clients can leave them NULL. DROP NOT
-- NULL is idempotent (a no-op when the column is already nullable) and does NOT
-- touch existing data.
-- ----------------------------------------------------------------------------
ALTER TABLE message_attachments ALTER COLUMN file_name DROP NOT NULL;
ALTER TABLE message_attachments ALTER COLUMN file_size DROP NOT NULL;
ALTER TABLE message_attachments ALTER COLUMN mime_type DROP NOT NULL;

-- ----------------------------------------------------------------------------
-- DOCUMENT the new contract on the columns.
-- ----------------------------------------------------------------------------
COMMENT ON TABLE  message_attachments              IS 'File attachments for messages. Files expire after 24 hours. H-6: name/type/exact-size are client-encrypted (encrypted_metadata); only a coarse size bucket is in plaintext.';
COMMENT ON COLUMN message_attachments.encrypted_metadata IS 'H-6: client-encrypted JSON {file_name, mime_type, file_size}, sealed under the conversation attachment KEK. Replaces the plaintext columns.';
COMMENT ON COLUMN message_attachments.metadata_nonce     IS 'H-6: secretbox nonce (base64) for encrypted_metadata.';
COMMENT ON COLUMN message_attachments.file_size_bucket   IS 'H-6: file size rounded UP to a coarse bucket so the exact byte count never leaks. Exact size is in encrypted_metadata.';
COMMENT ON COLUMN message_attachments.file_name          IS 'H-6 LEGACY: plaintext name (nullable). Not written by current clients; kept only to read pre-H-6 rows.';
COMMENT ON COLUMN message_attachments.mime_type          IS 'H-6 LEGACY: plaintext MIME (nullable). Not written by current clients; kept only to read pre-H-6 rows.';
COMMENT ON COLUMN message_attachments.file_size          IS 'H-6 LEGACY: plaintext exact size (nullable). Superseded by file_size_bucket + encrypted_metadata.';

COMMIT;

-- ============================================================================
-- OPTIONAL HARDENING — DROP the legacy plaintext columns entirely.
-- ============================================================================
-- The legacy file_name / file_size / mime_type columns are retained above ONLY so
-- attachments written BEFORE this migration stay readable. Because attachments
-- auto-expire after 24 hours (cleanup_expired_attachments), once >24h have passed
-- since this migration AND every old client has been retired, NO row will have
-- meaningful plaintext metadata and the columns can be dropped to remove the leak
-- surface completely. This step is DESTRUCTIVE of those columns, so it is left
-- COMMENTED OUT — uncomment and run it only after the 24h window:
--
--   BEGIN;
--   ALTER TABLE message_attachments DROP COLUMN IF EXISTS file_name;
--   ALTER TABLE message_attachments DROP COLUMN IF EXISTS file_size;
--   ALTER TABLE message_attachments DROP COLUMN IF EXISTS mime_type;
--   COMMIT;
--
-- After dropping, also remove file_name/file_size/mime_type from the client SELECT
-- in attachmentService.getMessageAttachments (the back-compat fallback path).
-- ============================================================================

-- ============================================================================
-- VERIFY (optional, run in the SQL Editor after applying):
--   -- new columns present?
--   SELECT column_name, is_nullable FROM information_schema.columns
--     WHERE table_name='message_attachments'
--       AND column_name IN ('encrypted_metadata','metadata_nonce','file_size_bucket',
--                           'file_name','file_size','mime_type')
--     ORDER BY column_name;
--   -- expect encrypted_metadata/metadata_nonce/file_size_bucket = YES (nullable)
--   --        and file_name/file_size/mime_type = YES (now nullable too).
-- ============================================================================
