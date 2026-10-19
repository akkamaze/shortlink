-- One account per email address. The address stays sealed; a keyed hash of
-- its lowercase form finds the account. email_verified records whether the
-- provider vouched for the address, so a verified sign-in can take an email
-- back from an account that only claimed it.

ALTER TABLE users ADD COLUMN email_lookup bytea UNIQUE CHECK (octet_length(email_lookup) = 32);
ALTER TABLE users ADD COLUMN email_verified boolean NOT NULL DEFAULT false;
