-- v33: records the earliest builds kept under the identity slot 'primary'
-- move to that identity's public address, which is its ID everywhere else.
-- The address is the row's own, so the records stay with the key they were
-- made under whichever identity the phone holds now. `public_address` is
-- unique, so no other row can already hold it as its ID.

-- The parent key and its children change together; checking at the commit
-- sees only the end state. The pragma ends with the transaction.
PRAGMA defer_foreign_keys = ON;

UPDATE channel SET owner_identity_id = (SELECT public_address FROM local_identity WHERE id = 'primary')
    WHERE owner_identity_id = 'primary' AND EXISTS (SELECT 1 FROM local_identity WHERE id = 'primary');
UPDATE channel_conversation SET owner_identity_id = (SELECT public_address FROM local_identity WHERE id = 'primary')
    WHERE owner_identity_id = 'primary' AND EXISTS (SELECT 1 FROM local_identity WHERE id = 'primary');
UPDATE chat_applied_mutation SET owner_identity_id = (SELECT public_address FROM local_identity WHERE id = 'primary')
    WHERE owner_identity_id = 'primary' AND EXISTS (SELECT 1 FROM local_identity WHERE id = 'primary');
UPDATE chat_delivery_fragment SET owner_identity_id = (SELECT public_address FROM local_identity WHERE id = 'primary')
    WHERE owner_identity_id = 'primary' AND EXISTS (SELECT 1 FROM local_identity WHERE id = 'primary');
UPDATE chat_message SET owner_identity_id = (SELECT public_address FROM local_identity WHERE id = 'primary')
    WHERE owner_identity_id = 'primary' AND EXISTS (SELECT 1 FROM local_identity WHERE id = 'primary');
UPDATE chat_outbound_archive SET owner_identity_id = (SELECT public_address FROM local_identity WHERE id = 'primary')
    WHERE owner_identity_id = 'primary' AND EXISTS (SELECT 1 FROM local_identity WHERE id = 'primary');
UPDATE chat_stream_checkpoint SET owner_identity_id = (SELECT public_address FROM local_identity WHERE id = 'primary')
    WHERE owner_identity_id = 'primary' AND EXISTS (SELECT 1 FROM local_identity WHERE id = 'primary');
UPDATE claimed_radio SET owner_identity_id = (SELECT public_address FROM local_identity WHERE id = 'primary')
    WHERE owner_identity_id = 'primary' AND EXISTS (SELECT 1 FROM local_identity WHERE id = 'primary');
UPDATE direct_conversation SET owner_identity_id = (SELECT public_address FROM local_identity WHERE id = 'primary')
    WHERE owner_identity_id = 'primary' AND EXISTS (SELECT 1 FROM local_identity WHERE id = 'primary');
UPDATE node SET owner_identity_id = (SELECT public_address FROM local_identity WHERE id = 'primary')
    WHERE owner_identity_id = 'primary' AND EXISTS (SELECT 1 FROM local_identity WHERE id = 'primary');
UPDATE local_identity SET id = public_address WHERE id = 'primary';
