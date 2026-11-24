-- v19, as the Swift store applied it.
--
-- A one-shot watch: tell me the next time this node is heard
-- from. Armed by hand, disarmed by the hearing itself, so it
-- is state rather than a preference and belongs on the row it
-- is about—a watch that did not survive relaunch would be
-- useless for the thing it is for, which is a node that has
-- gone quiet and may come back at any hour.

ALTER TABLE node ADD COLUMN notify_when_heard INTEGER NOT NULL DEFAULT 0;
