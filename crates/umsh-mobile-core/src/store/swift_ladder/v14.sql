-- v14, as the Swift store applied it.
--
-- `is_contact` distinguished two kinds of saved node and did
-- nothing else: same storage, same messaging, same retention,
-- one section header apart. Favorites says "peers I care
-- about" and can be changed at any time, which is what the
-- flag was reaching for. Contacts stay saved nodes; the flag
-- is not promoted to a favorite, because it defaulted on at
-- import and would star nearly everything.

ALTER TABLE node DROP COLUMN is_contact;
