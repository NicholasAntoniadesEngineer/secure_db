-- ============================================================================
-- FORWARD SECRECY — MESSAGES RATCHET/X3DH COLUMNS (run ONCE in the SQL Editor)
-- ============================================================================
-- MESSAGING-SIDE migration for FORWARD_SECRECY_DESIGN.md (step S3). Adds the
-- Double Ratchet header columns + X3DH first-message bootstrap columns to the
-- EXISTING messages table. ADDITIVE ONLY: every column is NULLABLE and added with
-- ADD COLUMN IF NOT EXISTS, so it NEVER drops, rewrites, or breaks existing rows or
-- data, and it is safe to re-run (idempotent).
--
-- These columns carry NON-SECRET header material (sender ratchet public key, chain
-- counters, and the initiator's public X3DH preamble). No RLS or GRANT change is
-- needed: the existing GRANT SELECT, INSERT ON messages is whole-row (not column-
-- scoped) and the messages_insert_participant policy constrains sender_id + the
-- conversation membership, not these columns. Pre-cutover rows simply leave the new
-- columns NULL (the client renders them as "previous encryption version — unavailable").
--
-- Companion migration (run separately on the IDENTITY database):
--   auth_db/backend/sql/apply-forward-secrecy-schema.sql  (prekeys + claim RPC)
--
-- DEPLOY ORDER: run BOTH migrations BEFORE shipping the forward-secrecy client (S4-S6),
-- otherwise the new client's inserts referencing these columns would fail.
-- ============================================================================

BEGIN;

-- Double Ratchet header (FORWARD_SECRECY_DESIGN.md §3): per-message routing fields.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS ratchet_pub    TEXT;     -- header.dh : sender ratchet pubkey (base64)
ALTER TABLE messages ADD COLUMN IF NOT EXISTS prev_chain_len INTEGER;  -- header.pn : # msgs in previous sending chain
ALTER TABLE messages ADD COLUMN IF NOT EXISTS msg_num        INTEGER;  -- header.n  : message number in current chain

-- X3DH first-message bootstrap preamble (FORWARD_SECRECY_DESIGN.md §2.4): set only on
-- the FIRST message of a conversation; NULL on every subsequent message.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS x3dh_ik        TEXT;     -- initiator X25519 identity public
ALTER TABLE messages ADD COLUMN IF NOT EXISTS x3dh_ik_sign   TEXT;     -- initiator Ed25519 identity-signing public (TOFU pin)
ALTER TABLE messages ADD COLUMN IF NOT EXISTS x3dh_ek        TEXT;     -- initiator ephemeral public EK_a
ALTER TABLE messages ADD COLUMN IF NOT EXISTS x3dh_spk_id    INTEGER;  -- recipient signed-prekey id used
ALTER TABLE messages ADD COLUMN IF NOT EXISTS x3dh_opk_id    INTEGER;  -- recipient one-time-prekey id used (NULL = SPK-only)

COMMENT ON COLUMN messages.ratchet_pub IS 'Double Ratchet header: sender ratchet public key (base64). NULL on pre-forward-secrecy rows.';
COMMENT ON COLUMN messages.prev_chain_len IS 'Double Ratchet header.pn: number of messages in the previous sending chain.';
COMMENT ON COLUMN messages.msg_num IS 'Double Ratchet header.n: message number within the current sending chain.';
COMMENT ON COLUMN messages.x3dh_ik IS 'X3DH first-message preamble: initiator X25519 identity public key. NULL except on the bootstrap message.';
COMMENT ON COLUMN messages.x3dh_ik_sign IS 'X3DH first-message preamble: initiator Ed25519 identity-signing public key (TOFU pin).';
COMMENT ON COLUMN messages.x3dh_ek IS 'X3DH first-message preamble: initiator ephemeral public key EK_a.';
COMMENT ON COLUMN messages.x3dh_spk_id IS 'X3DH first-message preamble: recipient signed-prekey id used.';
COMMENT ON COLUMN messages.x3dh_opk_id IS 'X3DH first-message preamble: recipient one-time prekey id consumed (NULL = SPK-only X3DH fallback).';

COMMIT;
