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

class WorkerTests(unittest.IsolatedAsyncioTestCase):
    async def test_pipeline_commit_uses_naive_utc_without_network_scan(self):
        with patch("sqlalchemy.ext.asyncio.create_async_engine", return_value=MagicMock()):
            from worker import main
        record=Scan(id=uuid.uuid4(),domain_id=uuid.uuid4(),status=ScanStatus.queued,created_at=datetime(2026,1,1))
        db=AsyncMock();db.get.return_value=record
        result=MagicMock();result.scalars.return_value.first.return_value=None
        db.execute.return_value=result
        context=MagicMock();context.__aenter__=AsyncMock(return_value=db);context.__aexit__=AsyncMock(return_value=None)
        output={"subdomains":["owned.example"],"open_ports":{},"socket_findings":{},"tls_findings":[]}
        with patch.object(main,"SessionLocal",return_value=context),patch.object(main,"run_pipeline",AsyncMock(return_value=output)),patch.object(main,"send_alert",AsyncMock()):
            await main.process_job({"scan_id":str(record.id),"domain":"owned.example"})
        self.assertEqual(record.status,ScanStatus.completed)
        self.assertIsNone(record.completed_at.tzinfo)
        self.assertEqual(record.subdomains,["owned.example"])
        self.assertEqual(db.commit.await_count,2)
        serialized=ScanOut.model_validate(record)
        self.assertEqual(serialized.completed_at.tzinfo,timezone.utc)

    async def test_failed_pipeline_rolls_back_and_records_failure(self):
        with patch("sqlalchemy.ext.asyncio.create_async_engine", return_value=MagicMock()):
            from worker import main
        record=Scan(id=uuid.uuid4(),domain_id=uuid.uuid4(),status=ScanStatus.queued,created_at=datetime(2026,1,1))
        db=AsyncMock();db.get.return_value=record
        context=MagicMock();context.__aenter__=AsyncMock(return_value=db);context.__aexit__=AsyncMock(return_value=None)
        with patch.object(main,"SessionLocal",return_value=context),patch.object(main,"run_pipeline",AsyncMock(side_effect=RuntimeError("test failure"))):
            await main.process_job({"scan_id":str(record.id),"domain":"owned.example"})
        db.rollback.assert_awaited_once()
        self.assertEqual(record.status,ScanStatus.failed)
        self.assertEqual(record.diff,{"error":"test failure"})

if __name__=="__main__":unittest.main()
