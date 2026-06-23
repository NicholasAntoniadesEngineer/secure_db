-- ============================================================================
-- PREMIUM ENTITLEMENT PREDICATE — MESSAGING-SCHEMA BOOTSTRAP (run ONCE in SQL Editor)
-- Idempotent, non-destructive.
-- ============================================================================
-- PRODUCT DECISION: MESSAGING IS FREE. The Premium feature is cross-user SHARING, gated
-- on the money_tracker data_shares owner-INSERT. This MESSAGING-SIDE migration therefore
-- does NOT touch any messages policy any more (it previously gated messages_insert_
-- participant on Premium — that gate has been REMOVED; messaging is free).
--
-- All this file still does is ship a fail-CLOSED bootstrap is_premium_active(uid) so the
-- predicate EXISTS in this database regardless of file-load order. In the shared all-in-
-- one DB the data_shares sharing gate (money_tracker/database/setup/
-- apply-premium-sharing-gate.sql) and the payments-side migration (payments_app/backend/
-- sql/apply-premium-entitlement.sql) CREATE-OR-REPLACE this with the full subscriptions-
-- backed body. Any run order is safe:
--   * if subscriptions is NOT present yet -> install the fail-closed bootstrap (denies);
--   * if subscriptions IS present but the function is missing -> install the full body;
--   * otherwise -> leave the existing (full) body untouched.
--
-- Predicate truth (whichever body is live):
--   premium == (status='active' AND plan=Premium)
--           OR (status='trial'  AND trial_end > NOW())   -- expired trial => NOT premium
--
-- ADDITIVE / re-runnable. Never drops the messages table; never rewrites rows; never
-- changes a messages policy. Already folded into secure_db/sql/complete-setup.sql for
-- fresh installs.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- BOOTSTRAP is_premium_active(uid) — fail-closed if subscriptions isn't installed yet.
-- Guards on whether subscriptions already exists and only (re)installs the bootstrap when
-- it does NOT, leaving an already-installed full body untouched.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.subscriptions') IS NULL
       OR to_regclass('public.subscription_plans') IS NULL THEN
        -- Payments schema not present yet: install the fail-closed bootstrap.
        EXECUTE $fn$
            CREATE OR REPLACE FUNCTION is_premium_active(p_uid UUID)
            RETURNS BOOLEAN
            LANGUAGE plpgsql
            STABLE
            SECURITY DEFINER
            SET search_path = public
            AS $body$
            BEGIN
                -- Fail closed if the subscriptions schema is not installed (deny, never allow).
                IF to_regclass('public.subscriptions') IS NULL
                   OR to_regclass('public.subscription_plans') IS NULL THEN
                    RETURN FALSE;
                END IF;

                RETURN EXISTS (
                    SELECT 1
                    FROM subscriptions s
                    JOIN subscription_plans p ON p.id = s.plan_id
                    WHERE s.user_id = p_uid
                      AND (
                            (s.status = 'active' AND p.name = 'Premium')
                         OR (s.status = 'trial'  AND s.trial_end IS NOT NULL AND s.trial_end > NOW())
                      )
                );
            END;
            $body$;
        $fn$;
        EXECUTE 'GRANT EXECUTE ON FUNCTION is_premium_active(UUID) TO authenticated';
        RAISE NOTICE 'is_premium_active: installed fail-closed bootstrap (subscriptions not present yet).';
    ELSIF to_regprocedure('public.is_premium_active(uuid)') IS NULL THEN
        -- Subscriptions present but the function was never created: install the full body.
        EXECUTE $fn$
            CREATE OR REPLACE FUNCTION is_premium_active(p_uid UUID)
            RETURNS BOOLEAN
            LANGUAGE sql
            STABLE
            SECURITY DEFINER
            SET search_path = public
            AS $body$
                SELECT EXISTS (
                    SELECT 1
                    FROM subscriptions s
                    JOIN subscription_plans p ON p.id = s.plan_id
                    WHERE s.user_id = p_uid
                      AND (
                            (s.status = 'active' AND p.name = 'Premium')
                         OR (s.status = 'trial'  AND s.trial_end IS NOT NULL AND s.trial_end > NOW())
                      )
                );
            $body$;
        $fn$;
        EXECUTE 'GRANT EXECUTE ON FUNCTION is_premium_active(UUID) TO authenticated';
        RAISE NOTICE 'is_premium_active: installed full subscriptions-backed body.';
    ELSE
        RAISE NOTICE 'is_premium_active: already present; leaving its body unchanged.';
    END IF;
END $$;

COMMIT;

-- ----------------------------------------------------------------------------
-- RUNBOOK
--   * MESSAGING IS FREE: this file no longer changes any messages policy. It only
--     guarantees is_premium_active() exists for the SHARING gate.
--   * Shared project (money_tracker + messaging): run the payments-side migration
--     (payments_app/backend/sql/apply-premium-entitlement.sql) and the money_tracker
--     sharing-gate migration (database/setup/apply-premium-sharing-gate.sql) to install
--     the full predicate + trial-expiry sweep + the data_shares Premium INSERT gate.
--     (On a fresh install all of this is already in the complete-setup.sql files.)
-- ----------------------------------------------------------------------------
