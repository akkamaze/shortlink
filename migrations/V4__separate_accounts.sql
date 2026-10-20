-- Each sign-in provider is its own account for now, so accounts are no
-- longer found by email. V3's lookup and verified flag have no reader left.

ALTER TABLE users DROP COLUMN email_lookup;
ALTER TABLE users DROP COLUMN email_verified;
