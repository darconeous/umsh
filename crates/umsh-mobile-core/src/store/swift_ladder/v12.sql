-- v12, as the Swift store applied it.
--
-- Whether the MAC authenticated the frame that delivered the
-- stored advertisement. A bundle's own signature is recoverable
-- from the payload at any time; how it *arrived* is not, and an
-- Identity Request reply is a MIC-authenticated unicast that
-- deliberately carries no signature. Without this, such a reply
-- is indistinguishable on reload from an unsigned broadcast
-- anyone could have sent. Existing rows default to 0: we have
-- no record either way, which is what the old display assumed.

ALTER TABLE node
    ADD COLUMN advertisement_authenticated INTEGER NOT NULL DEFAULT 0;
