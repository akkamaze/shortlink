-- LINE vouches for no email, so an account may have none. Profile pictures
-- are sealed like the other personal fields.

ALTER TABLE users ALTER COLUMN email_sealed DROP NOT NULL;
ALTER TABLE users ADD COLUMN picture_sealed bytea;
