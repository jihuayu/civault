ALTER TABLE settings ADD COLUMN agentmail_key BLOB;
ALTER TABLE settings ADD COLUMN agentmail_key_revision INTEGER NOT NULL DEFAULT 0;
INSERT INTO schema_migrations(version) VALUES(2);
