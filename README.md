# secure_db — secured shared database (messaging backend + master setup runbook)

The single source of truth for **setting up the secured shared Supabase project**
used by both `money_tracker` and `messaging_app`. This repo owns the
messaging/encryption backend **and** the ordered first-time-init runbook that
stitches every domain's scripts together.

> One Supabase project is shared by both apps (same auth, same data). These
> scripts are idempotent; on the current test project a clean re-run also applies
> the security hardening.

## This repo's backend (messaging / encryption)
- `sql/messaging-schema.sql` — messages, conversations, conversation_session_keys,
  message_attachments, identity_keys, public_key_history, paired_devices,
  device_keys, identity_key_backups, key_rotation_locks, blocked_users, friends —
  with **hardened RLS** (participant-scoped attachment storage, blocked-sender
  insert prevention, immutable attachments, authenticated-only key reads),
  realtime publication, and the `message-attachments` storage policies.
- `setup/supabase-storage-setup.md` — manual storage bucket step (must precede the SQL).

## First-time initialisation runbook (run in THIS order)

1. **Project + auth foundation — `auth_db`**
   - Run `auth_db/backend/sql/00_init_extensions.sql` (uuid-ossp, pgcrypto).
   - Deploy the `user-lookup` edge function.
2. **Messaging/encryption — `secure_db` (this repo)**
   - In the Dashboard, create a **private** Storage bucket `message-attachments`
     (1 MB limit) — see `setup/supabase-storage-setup.md`. (Must exist before the SQL.)
   - Run `sql/messaging-schema.sql`.
3. **Payments — `payments_app`**
   - Run `payments_app/backend/sql/subscription-schema.sql`.
   - Deploy edge functions `checkout-session`, `create-portal-session`, `stripe-webhook`.
4. **Budget — `money_tracker`**
   - Run the budget tables (user_months, pots, settings, data_shares, field_locks).

### Auth configuration (Dashboard → Authentication → URL Configuration)
- Set the **Site URL** and add each app's deployed URL + `…/auth/views/auth.html`
  to the redirect allow-list (sign-up confirmation + password-reset links).

### Edge-function secrets (Dashboard → Edge Functions → Secrets)
- `STRIPE_SECRET_KEY` — checkout + portal + webhook
- `STRIPE_WEBHOOK_SECRET` — webhook signature verification
- (`SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` are injected automatically)
- An account-deletion (`delete-account`) function, when deployed, also needs the
  service role (auto-injected) to cascade-delete a user.

## Account deletion (nuke)
Every messaging table FKs `auth.users(... ) ON DELETE CASCADE`, so deleting the
auth user removes all DB rows. Storage attachment objects are **not** cascaded and
must be removed explicitly by the `delete-account` edge function (see messaging_app).
