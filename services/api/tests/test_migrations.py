import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from app.settings import settings


class MigrationTests(unittest.TestCase):
    def test_fresh_database_upgrades_through_head(self):
        api_root = Path(__file__).resolve().parents[1]
        previous_url = settings.database_url
        try:
            with tempfile.TemporaryDirectory(dir=api_root) as directory:
                database_path = (Path(directory) / "migration-check.db").as_posix()
                settings.database_url = f"sqlite:///{database_path}"
                config = Config(str(api_root / "alembic.ini"))
                command.upgrade(config, "head")
                engine = create_engine(settings.database_url)
                try:
                    inspector = inspect(engine)
                    tables = set(inspector.get_table_names())
                    expected_tables = {
                        "targets", "scans", "scan_stages", "endpoints", "findings",
                        "evidence", "audit_events", "inventory_snapshots", "change_events",
                        "safety_controls", "test_credentials", "test_executions",
                        "endpoint_parameters", "endpoint_role_observations", "traffic_log_entries",
                        "vulnerability_scans", "discovered_vulnerabilities",
                    }
                    self.assertTrue(expected_tables.issubset(tables))
                    inventory_type = str(next(column["type"] for column in inspector.get_columns("inventory_snapshots") if column["name"] == "inventory_json")).upper()
                    self.assertIn("TEXT", inventory_type)
                    with engine.connect() as connection:
                        self.assertEqual(connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one(), "0007_vulnerability_engine")
                finally:
                    engine.dispose()
        finally:
            settings.database_url = previous_url


if __name__ == "__main__":
    unittest.main()
