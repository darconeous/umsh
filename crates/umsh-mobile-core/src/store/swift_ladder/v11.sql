-- v11, as the Swift store applied it.
--
-- An edited outbound message keeps its pre-edit text here so
-- the sender can still review what the original said. Only the
-- first edit captures it; the wire archive holds edited
-- content only and can never serve the original again.

ALTER TABLE chat_message ADD COLUMN original_body TEXT;
