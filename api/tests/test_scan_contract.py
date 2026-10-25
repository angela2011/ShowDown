import os
import sys
import unittest
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "api"), str(ROOT / "shared"), str(ROOT / "worker")]
os.environ["DATABASE_URL"] = "postgresql+asyncpg://test:test@127.0.0.1:5432/test"
from app.schemas import ScanOut
from shared.time_utils import database_utc
from shared.models import Scan, ScanStatus

class ContractTests(unittest.TestCase):
    def payload(self, **changes):
        data = dict(id=uuid.uuid4(),domain_id=uuid.uuid4(),status="completed",created_at=datetime(2026,1,1),completed_at=datetime(2026,1,1,1),subdomains=["owned.example"],tls_findings=[{"port":443,"flags":[]}],socket_findings={},open_ports={},diff={})
        data.update(changes)
        return data

    def test_worker_lists_serialize_and_timestamps_have_utc(self):
        result=ScanOut(**self.payload()).model_dump(mode="json")
        self.assertEqual(result["subdomains"],["owned.example"])
        self.assertEqual(result["tls_findings"],[{"port":443,"flags":[]}])
        self.assertTrue(result["created_at"].endswith("Z"))
        self.assertTrue(result["completed_at"].endswith("Z"))

    def test_legacy_dicts_and_nulls_are_preserved(self):
        for sub,tls in [({"owned.example":[]},{"owned.example":[{"port":443}]}),(None,None)]:
            result=ScanOut(**self.payload(subdomains=sub,tls_findings=tls,completed_at=None))
            self.assertEqual(result.subdomains,sub)
            self.assertEqual(result.tls_findings,tls)
            self.assertIsNone(result.completed_at)

    def test_timezone_conversion_and_unchanged_column(self):
        aware=datetime(2026,1,1,5,30,tzinfo=timezone(timedelta(hours=5,minutes=30)))
        self.assertEqual(database_utc(aware),datetime(2026,1,1))
        self.assertIsNone(database_utc().tzinfo)
        naive=datetime(2020,1,1)
        self.assertEqual(database_utc(naive),naive)
        self.assertFalse(Scan.__table__.c.completed_at.type.timezone)
        self.assertEqual(ScanOut(**self.payload(completed_at=aware)).completed_at,datetime(2026,1,1,tzinfo=timezone.utc))

# Worker transitions are tested against an isolated real ORM database in
# test_pipeline.py rather than mocking commits and row-lock queries.
if __name__ == '__main__': unittest.main()
