-- ============================================================
-- SECURE MESSENGER - MESSAGING-ONLY SCHEMA
-- ============================================================
-- This is the messaging-only Supabase schema for the standalone
-- "Secure Messenger" app. It was extracted VERBATIM from the
-- money_tracker combined schema (fresh-install-complete.sql),
-- keeping ONLY the secure-messaging / E2E-encryption objects.
-- All budget, subscription, payment, data-sharing, field-lock, and
-- notification objects have been dropped/omitted. Identity is
-- auth.users directly (there is NO profiles table).
--
-- The script is idempotent: it drops and recreates all kept objects,
-- so it can be re-run on an existing database.
-- ------------------------------------------------------------
-- PREREQUISITES (do these BEFORE running this script):
--   (a) STORAGE BUCKET: In the Supabase Dashboard > Storage, create a
--       PRIVATE bucket named 'message-attachments' with a 1MB file-size
--       limit (Public bucket = unchecked). The storage.objects RLS
--       policies in this script reference that bucket; they do not
--       create it. Files auto-expire after 24h via
--       cleanup_expired_attachments().
--   (b) EDGE FUNCTION: Deploy the 'user-lookup' edge function. Because
--       there is no profiles table, this function (running with the
--       service role) is the ONLY way the app resolves
--       email <-> userId (actions: findByEmail, getEmailById). User
--       discovery and "start conversation by email" will not work
--       without it.
--   (c) AUTH CONFIG: In the Supabase Dashboard > Authentication > URL
--       Configuration, set the Site URL and the allowed Redirect URLs
--       for the Secure Messenger app (email confirm / magic-link /
--       password-reset redirects).
-- ============================================================

DO $$
BEGIN
    RAISE NOTICE '============================================================';
    RAISE NOTICE 'SECURE MESSENGER - Starting messaging schema setup...';
    RAISE NOTICE '============================================================';
END $$;

-- ============================================================
-- CLEANUP: DROP ALL EXISTING (KEPT) OBJECTS (in dependency order)
-- ============================================================
-- This ensures a true fresh install by removing all existing data
-- for the kept messaging objects.

DO $$ BEGIN RAISE NOTICE '[1/9] Dropping existing tables, functions, and policies...'; END $$;

-- Drop tables with foreign key dependencies first
DROP TABLE IF EXISTS message_attachments CASCADE;
DROP TABLE IF EXISTS messages CASCADE;
DROP TABLE IF EXISTS conversation_session_keys CASCADE;
-- SM-40: conversation_participants was dead/self-only RLS; dropped. Kept in the
-- idempotent cleanup so re-running this script removes it from existing databases.
DROP TABLE IF EXISTS conversation_participants CASCADE;
DROP TABLE IF EXISTS conversations CASCADE;
DROP TABLE IF EXISTS device_keys CASCADE;
DROP TABLE IF EXISTS paired_devices CASCADE;
DROP TABLE IF EXISTS key_rotation_locks CASCADE;
DROP TABLE IF EXISTS public_key_history CASCADE;
DROP TABLE IF EXISTS identity_key_backups CASCADE;
DROP TABLE IF EXISTS identity_keys CASCADE;
DROP TABLE IF EXISTS friends CASCADE;
DROP TABLE IF EXISTS blocked_users CASCADE;

-- Drop functions that may exist
DROP FUNCTION IF EXISTS update_identity_keys_updated_at() CASCADE;
DROP FUNCTION IF EXISTS update_conversations_updated_at() CASCADE;
DROP FUNCTION IF EXISTS update_messages_updated_at() CASCADE;
DROP FUNCTION IF EXISTS cleanup_expired_attachments() CASCADE;
DROP FUNCTION IF EXISTS update_session_keys_updated_at() CASCADE;
DROP FUNCTION IF EXISTS update_key_backups_updated_at() CASCADE;
-- SM-15: SECURITY DEFINER helper for server-side block enforcement
DROP FUNCTION IF EXISTS is_blocked(UUID, UUID) CASCADE;
-- SM-30: SECURITY DEFINER helper for download-count increment
DROP FUNCTION IF EXISTS increment_attachment_download_count(BIGINT) CASCADE;

-- Drop storage policies (SM-05: re-scoped below to conversation participants / uploader)
DROP POLICY IF EXISTS "Users can upload attachments" ON storage.objects;
DROP POLICY IF EXISTS "Users can read attachments" ON storage.objects;
DROP POLICY IF EXISTS "Users can delete attachments" ON storage.objects;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- pgcrypto provides gen_random_uuid() used by public_key_history (no-op on Supabase, already present)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

DO $$ BEGIN RAISE NOTICE '[2/9] Creating friends system...'; END $$;

-- ============================================================
-- FRIENDS SYSTEM
-- ============================================================

CREATE TABLE IF NOT EXISTS friends (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    friend_user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'blocked')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, friend_user_id),
    CHECK (user_id != friend_user_id)
);

ALTER TABLE friends ENABLE ROW LEVEL SECURITY;

CREATE POLICY friends_select_involved ON friends
    FOR SELECT USING (auth.uid() = user_id OR auth.uid() = friend_user_id);

CREATE POLICY friends_insert_own ON friends
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- SM-39: only the request recipient may act on a pending request, and the row may
-- only be transitioned to 'accepted' or 'blocked'. WITH CHECK validates the NEW row
-- so the recipient cannot flip the row to an unauthorized state (e.g. reassign
-- friend_user_id away from themselves or set a value outside this set).
CREATE POLICY friends_update_as_friend ON friends
    FOR UPDATE
    USING (auth.uid() = friend_user_id AND status = 'pending')
    WITH CHECK (auth.uid() = friend_user_id AND status IN ('accepted', 'blocked'));

CREATE POLICY friends_delete_involved ON friends
    FOR DELETE USING (auth.uid() = user_id OR auth.uid() = friend_user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON friends TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE friends_id_seq TO authenticated;

DO $$ BEGIN RAISE NOTICE '[3/9] Creating blocked users system...'; END $$;

-- ============================================================
-- BLOCKED USERS
-- ============================================================

CREATE TABLE IF NOT EXISTS blocked_users (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    blocked_user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, blocked_user_id)
);

DROP INDEX IF EXISTS idx_blocked_users_user;
DROP INDEX IF EXISTS idx_blocked_users_blocked;
CREATE INDEX idx_blocked_users_user ON blocked_users(user_id);
CREATE INDEX idx_blocked_users_blocked ON blocked_users(blocked_user_id);

ALTER TABLE blocked_users ENABLE ROW LEVEL SECURITY;

-- Users can see their own blocked list
CREATE POLICY blocked_users_select_own ON blocked_users
    FOR SELECT USING (auth.uid() = user_id);

-- Users can block others
CREATE POLICY blocked_users_insert_own ON blocked_users
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Users can unblock others
CREATE POLICY blocked_users_delete_own ON blocked_users
    FOR DELETE USING (auth.uid() = user_id);

GRANT SELECT, INSERT, DELETE ON blocked_users TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE blocked_users_id_seq TO authenticated;

-- SM-15: server-side block enforcement helper.
-- blocked_users_select_own deliberately hides a user's block rows from everyone
-- but the owner, so a plain subquery inside another user's INSERT policy cannot
-- read them. This SECURITY DEFINER function answers "has p_owner blocked p_blocked?"
-- regardless of the caller, without exposing the block list itself.
CREATE OR REPLACE FUNCTION is_blocked(p_owner UUID, p_blocked UUID)
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = public
AS $$
    SELECT EXISTS (
        SELECT 1 FROM blocked_users
        WHERE user_id = p_owner
          AND blocked_user_id = p_blocked
    );
$$;

GRANT EXECUTE ON FUNCTION is_blocked(UUID, UUID) TO authenticated;

DO $$ BEGIN RAISE NOTICE '[4/9] Creating E2E encryption system (identity_keys, public_key_history, devices)...'; END $$;

-- ============================================================
-- E2E ENCRYPTION SYSTEM
-- ============================================================

-- Identity keys (public keys for key exchange)
CREATE TABLE IF NOT EXISTS identity_keys (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    current_epoch INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON COLUMN identity_keys.current_epoch IS 'Current key epoch. Incremented on each key regeneration for key rotation support.';

CREATE OR REPLACE FUNCTION update_identity_keys_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_update_identity_keys_updated_at
    BEFORE UPDATE ON identity_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_identity_keys_updated_at();

DROP INDEX IF EXISTS idx_identity_keys_user_id;
CREATE INDEX idx_identity_keys_user_id ON identity_keys(user_id);

ALTER TABLE identity_keys ENABLE ROW LEVEL SECURITY;

-- SM-14: restrict SELECT to authenticated users only (no anon/world access).
-- Public keys must remain readable by every authenticated user for key exchange,
-- but never by the anon role. (Authenticity/TOFU pinning and routing discovery
-- through the rate-limited user-lookup edge function are tracked under SM-01/SM-20.)
CREATE POLICY identity_keys_select_all ON identity_keys
    FOR SELECT TO authenticated USING (true);

CREATE POLICY identity_keys_insert_own ON identity_keys
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY identity_keys_update_own ON identity_keys
    FOR UPDATE USING (auth.uid() = user_id)
    -- HARDENING: WITH CHECK stops a user reassigning their key row to another user_id.
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY identity_keys_delete_own ON identity_keys
    FOR DELETE USING (auth.uid() = user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_keys TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE identity_keys_id_seq TO authenticated;

-- Public key history (stores historical public keys for epoch-based decryption)
-- When a user regenerates keys, their old public key is archived here
CREATE TABLE IF NOT EXISTS public_key_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, epoch)
);

DROP INDEX IF EXISTS idx_public_key_history_user_epoch;
CREATE INDEX idx_public_key_history_user_epoch ON public_key_history(user_id, epoch);

ALTER TABLE public_key_history ENABLE ROW LEVEL SECURITY;

-- Public keys are readable by all authenticated users (needed for decryption)
CREATE POLICY public_key_history_select_all ON public_key_history
    FOR SELECT TO authenticated USING (true);

-- Users can only insert their own historical keys
CREATE POLICY public_key_history_insert_own ON public_key_history
    FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

GRANT SELECT, INSERT ON public_key_history TO authenticated;

COMMENT ON TABLE public_key_history IS 'Historical public keys for epoch-based decryption of old messages';
COMMENT ON COLUMN public_key_history.epoch IS 'Key epoch - increments each time user regenerates keys';

-- NOTE: user_key_backups table has been REMOVED and consolidated into identity_key_backups
-- The identity_key_backups table (defined later) stores:
-- - Password-encrypted identity secret key
-- - Recovery-key encrypted identity secret key
-- - Stable session backup key for multi-device support
-- Public keys are stored in the identity_keys table

-- Paired devices (for multi-device support)
CREATE TABLE IF NOT EXISTS paired_devices (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    device_fingerprint TEXT,
    is_primary BOOLEAN DEFAULT false,
    last_active TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON COLUMN paired_devices.device_fingerprint IS 'Browser fingerprint for device identification';

DROP INDEX IF EXISTS idx_paired_devices_user_id;
CREATE INDEX idx_paired_devices_user_id ON paired_devices(user_id);

ALTER TABLE paired_devices ENABLE ROW LEVEL SECURITY;

CREATE POLICY paired_devices_select_own ON paired_devices
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY paired_devices_insert_own ON paired_devices
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY paired_devices_update_own ON paired_devices
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY paired_devices_delete_own ON paired_devices
    FOR DELETE USING (auth.uid() = user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON paired_devices TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE paired_devices_id_seq TO authenticated;

-- Device keys (temporary storage for device pairing requests)
-- Pairing codes are short-lived (5 minutes) and contain encrypted identity keys
CREATE TABLE IF NOT EXISTS device_keys (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_secret_key TEXT,
    encryption_nonce TEXT,
    pairing_code TEXT,
    expires_at TIMESTAMPTZ,
    is_primary BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON COLUMN device_keys.encrypted_secret_key IS 'Secret key encrypted with pairing-code-derived key (XSalsa20-Poly1305)';
COMMENT ON COLUMN device_keys.encryption_nonce IS 'Nonce used for secret key encryption';
COMMENT ON COLUMN device_keys.pairing_code IS '6-digit code for device pairing (expires after 5 minutes)';

DROP INDEX IF EXISTS idx_device_keys_user_id;
DROP INDEX IF EXISTS idx_device_keys_pairing_code;
CREATE INDEX idx_device_keys_user_id ON device_keys(user_id);
CREATE INDEX idx_device_keys_pairing_code ON device_keys(pairing_code) WHERE pairing_code IS NOT NULL;

ALTER TABLE device_keys ENABLE ROW LEVEL SECURITY;

-- SM-21: device_keys is correctly owner-scoped on every operation below
-- (auth.uid() = user_id), so no row is ever exposed beyond its owner.
-- NOTE: the 5-minute `expires_at` is NOT enforced here. The pairing flow that
-- writes these rows is being disabled separately; if it is ever re-enabled the
-- SELECT policy MUST also require `expires_at > now()` and a scheduled
-- `DELETE FROM device_keys WHERE expires_at < now()` must reap stale rows, so an
-- expired row holding the (weakly wrapped) identity secret cannot linger.
CREATE POLICY device_keys_select_own ON device_keys
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY device_keys_insert_own ON device_keys
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY device_keys_update_own ON device_keys
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY device_keys_delete_own ON device_keys
    FOR DELETE USING (auth.uid() = user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON device_keys TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE device_keys_id_seq TO authenticated;

-- Key rotation locks (prevents concurrent key rotations across devices/tabs)
CREATE TABLE IF NOT EXISTS key_rotation_locks (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    lock_token TEXT NOT NULL,
    locked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

COMMENT ON COLUMN key_rotation_locks.lock_token IS 'Unique token to identify lock owner';
COMMENT ON COLUMN key_rotation_locks.expires_at IS 'Lock auto-expires to prevent deadlocks (default 60 seconds)';

ALTER TABLE key_rotation_locks ENABLE ROW LEVEL SECURITY;

CREATE POLICY rotation_locks_select_own ON key_rotation_locks
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY rotation_locks_insert_own ON key_rotation_locks
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY rotation_locks_update_own ON key_rotation_locks
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY rotation_locks_delete_own ON key_rotation_locks
    FOR DELETE USING (auth.uid() = user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON key_rotation_locks TO authenticated;

DO $$ BEGIN RAISE NOTICE '[5/9] Creating conversations and participants...'; END $$;

-- ============================================================
-- CONVERSATIONS
-- ============================================================

-- Conversations
CREATE TABLE IF NOT EXISTS conversations (
    id BIGSERIAL PRIMARY KEY,
    user1_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    user2_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    last_message_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT conversations_users_different CHECK (user1_id != user2_id),
    CONSTRAINT conversations_users_ordered CHECK (user1_id < user2_id)
);

DROP INDEX IF EXISTS idx_conversations_users;
DROP INDEX IF EXISTS idx_conversations_user1;
DROP INDEX IF EXISTS idx_conversations_user2;
DROP INDEX IF EXISTS idx_conversations_last_message;
DROP INDEX IF EXISTS idx_conversations_updated_at;
CREATE UNIQUE INDEX idx_conversations_users ON conversations(user1_id, user2_id);
CREATE INDEX idx_conversations_user1 ON conversations(user1_id);
CREATE INDEX idx_conversations_user2 ON conversations(user2_id);
CREATE INDEX idx_conversations_last_message ON conversations(last_message_at DESC);
CREATE INDEX idx_conversations_updated_at ON conversations(updated_at DESC);

ALTER TABLE conversations ENABLE ROW LEVEL SECURITY;

-- SM-40: the conversations RLS policies (below) reference user1_id/user2_id
-- directly. The 1:1 model is sufficient, so the dead conversation_participants
-- table (self-only RLS, never referenced by the app) has been removed.

CREATE OR REPLACE FUNCTION update_conversations_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_update_conversations_updated_at
    BEFORE UPDATE ON conversations
    FOR EACH ROW
    EXECUTE FUNCTION update_conversations_updated_at();

GRANT SELECT, INSERT ON conversations TO authenticated;
-- HARDENING: column-scoped UPDATE so clients can advance conversation ordering
-- (last_message_at) but cannot rewrite participants or other columns.
GRANT UPDATE (last_message_at, updated_at) ON conversations TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE conversations_id_seq TO authenticated;

-- SM-40: conversation_participants table + policies removed (dead, self-only RLS).
-- The table is dropped in the idempotent cleanup section above so re-running this
-- script removes it from existing databases.

-- Conversations RLS policies (use user1_id/user2_id directly)
CREATE POLICY conversations_select_participant ON conversations
    FOR SELECT USING (
        auth.uid() = user1_id OR auth.uid() = user2_id
    );

CREATE POLICY conversations_insert_participant ON conversations
    FOR INSERT WITH CHECK (
        auth.uid() = user1_id OR auth.uid() = user2_id
    );

CREATE POLICY conversations_update_participant ON conversations
    FOR UPDATE USING (
        auth.uid() = user1_id OR auth.uid() = user2_id
    )
    -- HARDENING: WITH CHECK prevents moving a conversation to other users.
    WITH CHECK (
        auth.uid() = user1_id OR auth.uid() = user2_id
    );

DO $$ BEGIN RAISE NOTICE '[6/9] Creating messages...'; END $$;

-- ============================================================
-- MESSAGES
-- ============================================================

-- Messages (encrypted)
-- key_epoch tracks which session key version was used to encrypt each message
CREATE TABLE IF NOT EXISTS messages (
    id BIGSERIAL PRIMARY KEY,
    conversation_id BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sender_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    recipient_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    encrypted_content TEXT NOT NULL,
    encryption_nonce TEXT NOT NULL,
    message_counter BIGINT NOT NULL,
    key_epoch INTEGER DEFAULT 0,
    is_encrypted BOOLEAN DEFAULT TRUE,
    read BOOLEAN DEFAULT FALSE,
    read_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON COLUMN messages.key_epoch IS 'Session key epoch used to encrypt this message. Enables decryption with correct key version after key rotations.';

DROP INDEX IF EXISTS idx_messages_conversation_id;
DROP INDEX IF EXISTS idx_messages_sender_id;
DROP INDEX IF EXISTS idx_messages_recipient_id;
DROP INDEX IF EXISTS idx_messages_recipient_unread;
DROP INDEX IF EXISTS idx_messages_created_at;
DROP INDEX IF EXISTS idx_messages_key_epoch;
CREATE INDEX idx_messages_conversation_id ON messages(conversation_id);
CREATE INDEX idx_messages_sender_id ON messages(sender_id);
CREATE INDEX idx_messages_recipient_id ON messages(recipient_id);
CREATE INDEX idx_messages_recipient_unread ON messages(recipient_id, read) WHERE read = FALSE;
CREATE INDEX idx_messages_created_at ON messages(created_at DESC);
CREATE INDEX idx_messages_key_epoch ON messages(key_epoch);

ALTER TABLE messages ENABLE ROW LEVEL SECURITY;

CREATE POLICY messages_select_participant ON messages
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM conversations
            WHERE conversations.id = messages.conversation_id
            AND (conversations.user1_id = auth.uid() OR conversations.user2_id = auth.uid())
        )
    );

-- SM-15: enforce blocking server-side. A sender the recipient has blocked must not
-- be able to INSERT, even if they bypass the client guard and call PostgREST
-- directly. is_blocked() is SECURITY DEFINER because blocked_users_select_own hides
-- the recipient's block rows from the sender's own context.
CREATE POLICY messages_insert_participant ON messages
    FOR INSERT WITH CHECK (
        auth.uid() = sender_id AND
        EXISTS (
            SELECT 1 FROM conversations
            WHERE conversations.id = messages.conversation_id
            AND (conversations.user1_id = auth.uid() OR conversations.user2_id = auth.uid())
        ) AND
        NOT public.is_blocked(messages.recipient_id, auth.uid())
    );

CREATE POLICY messages_update_participant ON messages
    FOR UPDATE USING (
        EXISTS (
            SELECT 1 FROM conversations
            WHERE conversations.id = messages.conversation_id
            AND (conversations.user1_id = auth.uid() OR conversations.user2_id = auth.uid())
        )
    )
    -- HARDENING: WITH CHECK confines updates to the user's own conversations;
    -- paired with the column-scoped GRANT below (read/read_at only), message
    -- content and sender stay tamper-proof.
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM conversations
            WHERE conversations.id = messages.conversation_id
            AND (conversations.user1_id = auth.uid() OR conversations.user2_id = auth.uid())
        )
    );

CREATE OR REPLACE FUNCTION update_messages_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_update_messages_updated_at
    BEFORE UPDATE ON messages
    FOR EACH ROW
    EXECUTE FUNCTION update_messages_updated_at();

GRANT SELECT, INSERT ON messages TO authenticated;
-- HARDENING: column-scoped UPDATE so a participant can mark messages read (clears
-- unread counts) WITHOUT being able to alter encrypted_content / sender_id.
GRANT UPDATE (read, read_at) ON messages TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE messages_id_seq TO authenticated;

-- ============================================================
-- DEVICE PAIRING: pairing_requests (code-wrapped key handoff for multi-device)
-- The bundle (identity secret + session backup key) is PBKDF2+AES-GCM encrypted
-- under a one-time high-entropy code BEFORE storage; rows are RLS-owner-scoped,
-- single-use, and expiring. UPDATE is column-scoped to the attempt counter.
-- ============================================================
CREATE TABLE IF NOT EXISTS pairing_requests (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    encrypted_data TEXT NOT NULL,
    salt TEXT NOT NULL,
    iv TEXT NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pairing_requests_user_id ON pairing_requests(user_id);
ALTER TABLE pairing_requests ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pairing_requests_select_own ON pairing_requests;
CREATE POLICY pairing_requests_select_own ON pairing_requests
    FOR SELECT USING (auth.uid() = user_id);
DROP POLICY IF EXISTS pairing_requests_insert_own ON pairing_requests;
CREATE POLICY pairing_requests_insert_own ON pairing_requests
    FOR INSERT WITH CHECK (auth.uid() = user_id);
DROP POLICY IF EXISTS pairing_requests_update_own ON pairing_requests;
CREATE POLICY pairing_requests_update_own ON pairing_requests
    FOR UPDATE USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
DROP POLICY IF EXISTS pairing_requests_delete_own ON pairing_requests;
CREATE POLICY pairing_requests_delete_own ON pairing_requests
    FOR DELETE USING (auth.uid() = user_id);
GRANT SELECT, INSERT, DELETE ON pairing_requests TO authenticated;
GRANT UPDATE (attempts) ON pairing_requests TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE pairing_requests_id_seq TO authenticated;

DO $$ BEGIN RAISE NOTICE '[7/9] Creating message attachments system...'; END $$;

-- ============================================================
-- MESSAGE ATTACHMENTS
-- ============================================================
-- Files are stored in Supabase Storage with encrypted metadata
-- Files auto-expire after 24 hours via scheduled cleanup

CREATE TABLE IF NOT EXISTS message_attachments (
    id BIGSERIAL PRIMARY KEY,
    message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    conversation_id BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    uploader_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,

    -- File metadata (stored unencrypted for querying)
    file_name TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type TEXT NOT NULL,
    storage_path TEXT NOT NULL,  -- Path in Supabase Storage bucket

    -- Encrypted file key (file is encrypted client-side before upload)
    -- This key is encrypted with the conversation's session key
    encrypted_file_key TEXT,
    file_key_nonce TEXT,

    -- Lifecycle
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '24 hours'),
    downloaded_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE message_attachments IS 'File attachments for messages. Files expire after 24 hours.';
COMMENT ON COLUMN message_attachments.storage_path IS 'Path to encrypted file in Supabase Storage bucket';
COMMENT ON COLUMN message_attachments.encrypted_file_key IS 'File encryption key, encrypted with conversation session key';
COMMENT ON COLUMN message_attachments.expires_at IS 'Files auto-delete after this time (default 24 hours)';

DROP INDEX IF EXISTS idx_attachments_message_id;
DROP INDEX IF EXISTS idx_attachments_conversation_id;
DROP INDEX IF EXISTS idx_attachments_uploader_id;
DROP INDEX IF EXISTS idx_attachments_expires_at;
CREATE INDEX idx_attachments_message_id ON message_attachments(message_id);
CREATE INDEX idx_attachments_conversation_id ON message_attachments(conversation_id);
CREATE INDEX idx_attachments_uploader_id ON message_attachments(uploader_id);
CREATE INDEX idx_attachments_expires_at ON message_attachments(expires_at);

ALTER TABLE message_attachments ENABLE ROW LEVEL SECURITY;

-- Only conversation participants can view attachments
CREATE POLICY attachments_select_participant ON message_attachments
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM conversations
            WHERE conversations.id = message_attachments.conversation_id
            AND (conversations.user1_id = auth.uid() OR conversations.user2_id = auth.uid())
        )
    );

-- Only the uploader can insert
CREATE POLICY attachments_insert_uploader ON message_attachments
    FOR INSERT WITH CHECK (
        auth.uid() = uploader_id AND
        EXISTS (
            SELECT 1 FROM conversations
            WHERE conversations.id = message_attachments.conversation_id
            AND (conversations.user1_id = auth.uid() OR conversations.user2_id = auth.uid())
        )
    );

-- SM-30: the previous UPDATE policy let ANY conversation participant rewrite ANY
-- column on ANY attachment row (no WITH CHECK, no column scope) — enabling
-- cross-user metadata tampering (plant an XSS file_name on the counterparty's row),
-- object substitution (storage_path/encrypted_file_key), and expiry bypass
-- (push expires_at far into the future). Attachment metadata is immutable once
-- created, so there is NO table-level UPDATE policy and the table GRANT below
-- omits UPDATE. The only legitimate mutation — bumping downloaded_count — is
-- done through the SECURITY DEFINER function below, which any conversation
-- participant may call but which can touch no other column.

-- Only uploader can delete
CREATE POLICY attachments_delete_uploader ON message_attachments
    FOR DELETE USING (auth.uid() = uploader_id);

-- Deliberately NO UPDATE in this grant (SM-30): rows are immutable post-insert.
GRANT SELECT, INSERT, DELETE ON message_attachments TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE message_attachments_id_seq TO authenticated;

-- SM-30: controlled, column-scoped download-count increment. Runs as owner so it
-- can UPDATE despite no UPDATE GRANT/policy, but it only touches downloaded_count
-- and only for attachments in a conversation the caller participates in. All other
-- columns (file_name, storage_path, encrypted_file_key, expires_at, ...) stay
-- immutable after insert.
CREATE OR REPLACE FUNCTION increment_attachment_download_count(p_attachment_id BIGINT)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    new_count INTEGER;
BEGIN
    UPDATE message_attachments AS ma
    SET downloaded_count = ma.downloaded_count + 1
    WHERE ma.id = p_attachment_id
      AND EXISTS (
          SELECT 1 FROM conversations c
          WHERE c.id = ma.conversation_id
            AND (c.user1_id = auth.uid() OR c.user2_id = auth.uid())
      )
    RETURNING ma.downloaded_count INTO new_count;

    RETURN new_count; -- NULL if not found / caller not a participant
END;
$$;

GRANT EXECUTE ON FUNCTION increment_attachment_download_count(BIGINT) TO authenticated;

DO $$ BEGIN RAISE NOTICE '[8/9] Creating storage bucket policies and realtime...'; END $$;

-- ============================================================
-- STORAGE BUCKET POLICIES FOR MESSAGE ATTACHMENTS
-- ============================================================
-- These policies control access to the 'message-attachments' storage bucket.
-- The bucket must be created manually in Supabase Dashboard > Storage.
--
-- SM-05: the previous policies gated ONLY on bucket_id, so any authenticated user
-- could download (SELECT) or delete (DELETE) EVERY object in the bucket, and the
-- object keys (<conversationId>/<timestamp>-<rand>, conversationId being a
-- guessable BIGSERIAL) are fully enumerable. The policies below scope access to
-- the conversation in the object path:
--   - the upload path is built as `<conversationId>/...` (attachmentService.js),
--     so the first path segment is the conversation id;
--   - (storage.foldername(name))[1] extracts that first segment;
--   - the `~ '^[0-9]+$'` guard ensures a malformed/non-numeric key simply fails
--     the policy instead of raising a cast error;
--   - participation is verified against conversations.user1_id/user2_id.
-- SELECT is limited to conversation participants; INSERT and DELETE are further
-- limited to the object owner (auth.uid()), i.e. the uploader. Never expose
-- bucket-root .list() — keep the bucket PRIVATE.

-- INSERT: uploader must own the object AND participate in the path's conversation.
DROP POLICY IF EXISTS "Users can upload attachments" ON storage.objects;
CREATE POLICY "Users can upload attachments"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (
    bucket_id = 'message-attachments'
    AND owner = auth.uid()
    AND (storage.foldername(name))[1] ~ '^[0-9]+$'
    AND EXISTS (
        SELECT 1 FROM public.conversations c
        WHERE c.id = ((storage.foldername(name))[1])::bigint
          AND (c.user1_id = auth.uid() OR c.user2_id = auth.uid())
    )
);

-- SELECT: any participant of the path's conversation may read its objects.
DROP POLICY IF EXISTS "Users can read attachments" ON storage.objects;
CREATE POLICY "Users can read attachments"
ON storage.objects FOR SELECT
TO authenticated
USING (
    bucket_id = 'message-attachments'
    AND (storage.foldername(name))[1] ~ '^[0-9]+$'
    AND EXISTS (
        SELECT 1 FROM public.conversations c
        WHERE c.id = ((storage.foldername(name))[1])::bigint
          AND (c.user1_id = auth.uid() OR c.user2_id = auth.uid())
    )
);

-- DELETE: only the uploader (object owner) who is a participant may delete.
DROP POLICY IF EXISTS "Users can delete attachments" ON storage.objects;
CREATE POLICY "Users can delete attachments"
ON storage.objects FOR DELETE
TO authenticated
USING (
    bucket_id = 'message-attachments'
    AND owner = auth.uid()
    AND (storage.foldername(name))[1] ~ '^[0-9]+$'
    AND EXISTS (
        SELECT 1 FROM public.conversations c
        WHERE c.id = ((storage.foldername(name))[1])::bigint
          AND (c.user1_id = auth.uid() OR c.user2_id = auth.uid())
    )
);

-- Function to clean up expired attachments (run via scheduled job)
CREATE OR REPLACE FUNCTION cleanup_expired_attachments()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Delete expired attachment records
    -- Note: Actual file deletion from storage must be handled separately
    DELETE FROM message_attachments
    WHERE expires_at < NOW();

    GET DIAGNOSTICS deleted_count = ROW_COUNT;

    RETURN deleted_count;
END;
$$;

-- ============================================================
-- REALTIME CONFIGURATION FOR MESSAGES
-- ============================================================
-- Enable Supabase Realtime on the messages table
-- REPLICA IDENTITY FULL is required for filters to work with Realtime
ALTER TABLE messages REPLICA IDENTITY FULL;

-- Add the messages table to the supabase_realtime publication
-- This enables real-time subscriptions for the messages table
-- Note: Run this command. If the publication doesn't exist, create it first.
DO $$
BEGIN
    -- Check if the publication exists
    IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
        -- Add the table to existing publication (ignore if already added)
        BEGIN
            ALTER PUBLICATION supabase_realtime ADD TABLE messages;
        EXCEPTION WHEN duplicate_object THEN
            -- Table already in publication, that's fine
            NULL;
        END;
    ELSE
        -- Create the publication with the messages table
        CREATE PUBLICATION supabase_realtime FOR TABLE messages;
    END IF;
END $$;

-- Also enable for conversations table (for unread counts, etc.)
ALTER TABLE conversations REPLICA IDENTITY FULL;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
        BEGIN
            ALTER PUBLICATION supabase_realtime ADD TABLE conversations;
        EXCEPTION WHEN duplicate_object THEN
            NULL;
        END;
    END IF;
END $$;

DO $$ BEGIN RAISE NOTICE '[9/9] Creating multi-device encryption support (session keys, backups)...'; END $$;

-- ============================================================
-- MULTI-DEVICE ENCRYPTION SUPPORT
-- ============================================================

-- Session key backup for multi-device message decryption
-- Supports multiple session keys per conversation (one per epoch) for key rotation
CREATE TABLE IF NOT EXISTS conversation_session_keys (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    conversation_id BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    encrypted_session_key TEXT NOT NULL,
    encryption_nonce TEXT NOT NULL,
    message_counter BIGINT NOT NULL DEFAULT 0,
    key_epoch INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, conversation_id, key_epoch)
);

COMMENT ON COLUMN conversation_session_keys.key_epoch IS 'Key epoch this session belongs to. Higher epochs = more recent keys after regeneration.';

DROP INDEX IF EXISTS idx_session_keys_user_conversation;
DROP INDEX IF EXISTS idx_session_keys_epoch;
CREATE INDEX idx_session_keys_user_conversation ON conversation_session_keys(user_id, conversation_id);
CREATE INDEX idx_session_keys_epoch ON conversation_session_keys(key_epoch);

ALTER TABLE conversation_session_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY session_keys_select_own ON conversation_session_keys
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY session_keys_insert_own ON conversation_session_keys
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY session_keys_update_own ON conversation_session_keys
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY session_keys_delete_own ON conversation_session_keys
    FOR DELETE USING (auth.uid() = user_id);

CREATE OR REPLACE FUNCTION update_session_keys_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_update_session_keys_updated_at
    BEFORE UPDATE ON conversation_session_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_session_keys_updated_at();

GRANT SELECT, INSERT, UPDATE, DELETE ON conversation_session_keys TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE conversation_session_keys_id_seq TO authenticated;

-- Password and recovery key encrypted identity key backups
-- Also stores the stable session backup key for multi-device support
CREATE TABLE IF NOT EXISTS identity_key_backups (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    -- Password-encrypted identity secret key
    password_encrypted_data TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_iv TEXT NOT NULL,
    -- Recovery-key encrypted identity secret key
    recovery_encrypted_data TEXT NOT NULL,
    recovery_salt TEXT NOT NULL,
    recovery_iv TEXT NOT NULL,
    -- Stable session backup key (encrypted with password)
    -- This key survives identity key rotation for reliable multi-device sync
    session_backup_key_encrypted TEXT,
    session_backup_key_salt TEXT,
    session_backup_key_iv TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id)
);

DROP INDEX IF EXISTS idx_key_backups_user_id;
CREATE INDEX idx_key_backups_user_id ON identity_key_backups(user_id);

ALTER TABLE identity_key_backups ENABLE ROW LEVEL SECURITY;

CREATE POLICY key_backups_select_own ON identity_key_backups
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY key_backups_insert_own ON identity_key_backups
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY key_backups_update_own ON identity_key_backups
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY key_backups_delete_own ON identity_key_backups
    FOR DELETE USING (auth.uid() = user_id);

CREATE OR REPLACE FUNCTION update_key_backups_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_update_key_backups_updated_at
    BEFORE UPDATE ON identity_key_backups
    FOR EACH ROW
    EXECUTE FUNCTION update_key_backups_updated_at();

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_key_backups TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE identity_key_backups_id_seq TO authenticated;

-- ============================================================
-- ADDITIONAL INDEXES FOR PERFORMANCE
-- ============================================================

-- Improve query performance for common access patterns
CREATE INDEX IF NOT EXISTS idx_identity_keys_updated ON identity_keys(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_conversation_epoch ON messages(conversation_id, key_epoch);
CREATE INDEX IF NOT EXISTS idx_session_keys_user_updated ON conversation_session_keys(user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_public_key_history_user_epoch ON public_key_history(user_id, epoch);

-- ============================================================
-- MESSAGING SCHEMA COMPLETE
-- ============================================================

DO $$
DECLARE
    table_count INTEGER;
    function_count INTEGER;
    policy_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO table_count FROM information_schema.tables
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE';

    SELECT COUNT(*) INTO function_count FROM information_schema.routines
    WHERE routine_schema = 'public' AND routine_type = 'FUNCTION';

    SELECT COUNT(*) INTO policy_count FROM pg_policies
    WHERE schemaname = 'public';

    RAISE NOTICE '============================================================';
    RAISE NOTICE 'SECURE MESSENGER MESSAGING SCHEMA COMPLETE';
    RAISE NOTICE '============================================================';
    RAISE NOTICE 'Created % tables in public schema', table_count;
    RAISE NOTICE 'Created % functions in public schema', function_count;
    RAISE NOTICE 'Created % RLS policies', policy_count;
    RAISE NOTICE '------------------------------------------------------------';
    RAISE NOTICE 'Database is now ready with:';
    RAISE NOTICE '  - Friends and blocked users systems';
    RAISE NOTICE '  - E2E encryption (identity keys, conversations, messages)';
    RAISE NOTICE '  - Multi-device support (paired devices, session key backups)';
    RAISE NOTICE '  - Message attachments with storage policies';
    RAISE NOTICE '  - Realtime on messages and conversations';
    RAISE NOTICE '------------------------------------------------------------';
    RAISE NOTICE 'REMINDER: create the private message-attachments bucket,';
    RAISE NOTICE 'deploy the user-lookup edge function, and configure Auth URLs.';
    RAISE NOTICE '============================================================';
END $$;
