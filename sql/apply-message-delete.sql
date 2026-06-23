-- ============================================================================
-- DELETE FOR EVERYONE ("unsend") — MESSAGES HARD-DELETE (run ONCE in SQL Editor)
-- ============================================================================
-- MESSAGING-SIDE migration enabling a user to HARD-DELETE a message they SENT,
-- removing the row from the database for BOTH parties. Privacy-first hard delete:
-- there is NO tombstone / soft-delete column — the row is physically removed and
-- the message is gone for sender and recipient alike.
--
-- ADDITIVE ONLY. This migration:
--   * adds a DELETE RLS policy (sender-only),
--   * grants DELETE on messages to authenticated,
--   * ensures REPLICA IDENTITY FULL (so the realtime DELETE event carries the old
--     row's conversation_id — see the long note below),
--   * ensures messages is in the supabase_realtime publication.
-- It NEVER drops a table, never rewrites or deletes existing rows, and is safe to
-- re-run (every statement is idempotent / guarded).
--
-- DEPLOY ORDER: run this BEFORE shipping the client that calls deleteMessage(); the
-- DELETE request would otherwise be rejected (no DELETE grant/policy). It is also
-- already folded into secure_db/sql/complete-setup.sql for fresh installs.
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- DELETE RLS POLICY: only the SENDER may delete; the row vanishes for BOTH parties.
-- ----------------------------------------------------------------------------
-- DELETE policies are evaluated via USING only (there is no NEW row, so no
-- WITH CHECK). auth.uid() = sender_id means the recipient simply has no row to
-- target. The FK message_attachments.message_id ON DELETE CASCADE cleans up any
-- attachment metadata rows for the deleted message automatically.
DROP POLICY IF EXISTS messages_delete_own ON messages;
CREATE POLICY messages_delete_own ON messages
    FOR DELETE TO authenticated
    USING (auth.uid() = sender_id);

-- ----------------------------------------------------------------------------
-- GRANT: table-level DELETE privilege (RLS policy above scopes it to the sender).
-- Idempotent — re-GRANTing an existing privilege is a no-op.
-- ----------------------------------------------------------------------------
GRANT DELETE ON messages TO authenticated;

-- ----------------------------------------------------------------------------
-- REPLICA IDENTITY FULL — REQUIRED for the recipient to receive the DELETE event.
-- ----------------------------------------------------------------------------
-- On a DELETE, Postgres writes only the OLD row's *replica-identity* columns to the
-- WAL that logical replication / Supabase Realtime reads. With the default identity
-- (PRIMARY KEY) the realtime DELETE payload's `old` record would contain ONLY the
-- primary key (id) — NOT conversation_id. The recipient subscribes with a
-- conversation filter (`conversation_id=eq.N`), so without conversation_id in the
-- OLD row the broker cannot match the DELETE to the recipient's channel and the
-- recipient would never drop the unsent message.
--
-- REPLICA IDENTITY FULL makes the WAL carry the ENTIRE old row on DELETE (and
-- UPDATE), so old.conversation_id (and old.sender_id) are present and the
-- conversation-filtered subscription matches. This is idempotent (setting it when
-- already FULL is a no-op). complete-setup.sql already sets this; restated here so
-- this migration is self-sufficient on a database provisioned before that change.
ALTER TABLE messages REPLICA IDENTITY FULL;

-- ----------------------------------------------------------------------------
-- PUBLICATION: ensure messages streams realtime changes.
-- ----------------------------------------------------------------------------
-- A publication created without a FOR-operation clause streams INSERT, UPDATE AND
-- DELETE by default, so once messages is a member of supabase_realtime the DELETE
-- event flows automatically — no per-operation publication change is needed. This
-- block is a no-op when messages is already published (the typical case, since the
-- INSERT realtime path is already in production).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
        BEGIN
            ALTER PUBLICATION supabase_realtime ADD TABLE messages;
        EXCEPTION WHEN duplicate_object THEN
            -- Already a member of the publication; nothing to do.
            NULL;
        END;
    ELSE
        CREATE PUBLICATION supabase_realtime FOR TABLE messages;
    END IF;
END $$;

COMMIT;

-- ============================================================================
-- VERIFY (optional, run in the SQL Editor after applying):
--   -- sender-only DELETE policy present?
--   SELECT polname, cmd FROM pg_policies
--     WHERE schemaname='public' AND tablename='messages' AND cmd='DELETE';
--   -- REPLICA IDENTITY FULL ('f') on messages?
--   SELECT relreplident FROM pg_class WHERE relname='messages';  -- expect 'f'
--   -- messages in the realtime publication?
--   SELECT 1 FROM pg_publication_tables
--     WHERE pubname='supabase_realtime' AND tablename='messages';
-- ============================================================================
