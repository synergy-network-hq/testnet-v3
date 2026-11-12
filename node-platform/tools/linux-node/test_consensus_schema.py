"""Native SQLite schema compatibility, without starting a node or migrating data."""
from pathlib import Path
import sqlite3
import unittest
from synergy_linux import consensus_archive_version


def native_schema(connection, version=2):
    # Actual native CREATE statements are independently checked against the
    # installer's ABI descriptor, detecting native/packaging drift.
    source = (Path(__file__).resolve().parents[2] /
              'crates/synergy-posy/src/persistence/evidence_store.rs').read_text()
    sql = source.split('connection.execute_batch("BEGIN IMMEDIATE;', 1)[1]
    sql = sql.split('PRAGMA user_version=2; COMMIT;', 1)[0]
    if version == 1:
        sql = sql.split('CREATE TABLE IF NOT EXISTS archive_objects', 1)[0]
    connection.executescript(sql)
    connection.execute('PRAGMA user_version=' + str(version))
    connection.commit()


class SchemaTests(unittest.TestCase):
    def test_native_versions_are_accepted_without_changes(self):
        for version in (1, 2):
            with self.subTest(version=version), sqlite3.connect(':memory:') as db:
                native_schema(db, version)
                before = tuple(db.iterdump())
                self.assertEqual(consensus_archive_version(db), version)
                self.assertEqual(tuple(db.iterdump()), before)

    def test_known_names_with_wrong_columns_are_rejected(self):
        with sqlite3.connect(':memory:') as db:
            native_schema(db)
            db.execute('ALTER TABLE archive_objects ADD COLUMN obsolete INTEGER')
            with self.assertRaisesRegex(ValueError, 'column schema: archive_objects'):
                consensus_archive_version(db)

    def test_type_primary_key_nullable_and_generated_drift_are_rejected(self):
        changes = [
            ('bytes BLOB NOT NULL', 'bytes TEXT NOT NULL'),
            ('bytes BLOB NOT NULL', 'bytes BLOB'),
            ('PRIMARY KEY(key,digest)', 'PRIMARY KEY(digest,key)'),
            ('bytes BLOB NOT NULL', 'bytes BLOB GENERATED ALWAYS AS (digest) VIRTUAL'),
        ]
        for old, new in changes:
            with self.subTest(change=new), sqlite3.connect(':memory:') as db:
                native_schema(db)
                sql = db.execute("SELECT sql FROM sqlite_master WHERE name='revisions'").fetchone()[0]
                self.assertIn(old, sql)
                db.execute('DROP TABLE revisions')
                db.execute(sql.replace(old, new))
                with self.assertRaisesRegex(ValueError, 'column schema: revisions'):
                    consensus_archive_version(db)

    def test_executable_schema_rejected(self):
        with sqlite3.connect(':memory:') as db:
            native_schema(db)
            db.execute('CREATE VIEW hidden AS SELECT * FROM evidence')
            with self.assertRaisesRegex(ValueError, 'executable schema'):
                consensus_archive_version(db)


if __name__ == '__main__':
    unittest.main()
