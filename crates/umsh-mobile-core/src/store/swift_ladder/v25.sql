-- v25, as the Swift store applied it.
--
-- When the stored advertisement was heard. Bundles stored
-- before this have no arrival on record, the same as an
-- imported one.

ALTER TABLE node ADD COLUMN advertisement_received_at REAL;
