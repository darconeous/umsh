-- v21, as the Swift store applied it.
--
-- Whether a direct conversation may notify. Defaults on,
-- which is what direct messages did before there was a
-- switch. Channels have carried the same setting since they
-- arrived, defaulting off—the asymmetry is deliberate: a
-- message addressed to you is worth interrupting for, and a
-- channel's traffic is not until its owner says so.

ALTER TABLE direct_conversation
    ADD COLUMN notifications_enabled INTEGER NOT NULL DEFAULT 1;
