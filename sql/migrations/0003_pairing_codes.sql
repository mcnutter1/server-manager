-- =====================================================================
-- Migration 0003 — pairing unlock codes.
-- Short-lived codes issued by the manager that an operator presents to a
-- downstream app's helper page to unlock it and reveal its enrollment key.
-- Idempotent.
-- =====================================================================

CREATE TABLE IF NOT EXISTS pairing_codes (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    code_hash     CHAR(64)        NOT NULL,          -- sha256 of the code; plaintext never stored
    label         VARCHAR(190)    NULL,              -- optional note, e.g. target app/domain
    created_by    VARCHAR(190)    NULL,
    used          INT UNSIGNED    NOT NULL DEFAULT 0,
    last_used_at  DATETIME        NULL,
    expires_at    DATETIME        NOT NULL,
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_code_hash (code_hash),
    KEY idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO settings (skey, svalue) VALUES
    ('schema_version', '"1.2.0"')
ON DUPLICATE KEY UPDATE svalue = VALUES(svalue);
