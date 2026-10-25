import sys
import unittest
from copy import deepcopy
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'worker'),str(ROOT/'shared')]
from worker.tasks.risk_engine import score_snapshot
from worker.tasks.diff_engine import diff_scans


def snapshot(ports=None, services=None, tls=None):
    return dict(domain='owned.example',subdomains=['owned.example'],open_ports={'owned.example':ports or []},
                socket_findings={'owned.example':services or []},tls_findings={'owned.example':tls or []},
                observed_at='2026-10-25T00:00:00Z')

class RiskChangesTests(unittest.TestCase):
    def test_database_evidence_and_new_exposure_critical(self):
        current=snapshot([5432],[{'port':5432,'fingerprint':'postgresql','flags':[]}])
        baseline=diff_scans(None,current)
        self.assertEqual(baseline['risk']['severity'],'high')
        self.assertNotIn('new_exposed_port',[f['rule_id'] for f in baseline['risk']['findings']])
        delta=diff_scans(snapshot(),current)
        self.assertEqual(delta['risk']['score'],90)
        self.assertEqual(delta['risk']['severity'],'critical')
        guessed=score_snapshot(snapshot([5432]))['findings'][0]
        self.assertEqual(guessed['severity'],'medium')
        self.assertIn('unconfirmed',guessed['reason'])
    def test_http_requires_observation_not_port_guess(self):
        self.assertEqual(score_snapshot(snapshot([80]))['findings'],[])
        result=score_snapshot(snapshot([80],[{'port':80,'fingerprint':'http','banner':'HTTP/1.1 200 OK'}]))
        self.assertEqual(result['findings'][0]['rule_id'],'insecure_http')
        self.assertEqual(result['score'],40)
    def test_low_high_and_deduplication(self):
        row={'port':443,'flags':['plaintext_response_on_expected_tls_port','possible_version_disclosure'],'banner':'test 1'}
        risk=score_snapshot(snapshot([443],[row,row]))
        self.assertEqual(risk['counts'],{'low':1,'medium':0,'high':1,'critical':0})
        self.assertEqual(risk['score'],70)
        self.assertEqual(len({f['id'] for f in risk['findings']}),2)
    def test_expiry_boundaries_and_utc_offsets(self):
        for expiry, expected in [('2026-10-24T23:59:59Z',80),('2026-10-25T00:00:00Z',70),('2026-11-01T00:00:00Z',70),('2026-11-01T00:00:01Z',40),('2026-11-24T00:00:00Z',40),('2026-11-24T00:00:01Z',0)]:
            current=snapshot([443],tls=[{'port':443,'reachable':True,'expires':expiry}])
            self.assertEqual(score_snapshot(current)['score'],expected)
        current=snapshot([443],tls=[{'port':443,'expires':'2026-11-01T05:30:00+05:30'}])
        self.assertEqual(score_snapshot(current)['score'],70)
    def test_tls_failure_not_treated_as_expired(self):
        current=snapshot([443],tls=[{'port':443,'reachable':False,'error':'TimeoutError','days_until_expiry':-1}])
        self.assertEqual(score_snapshot(current)['findings'],[])
    def test_legacy_tls_list_and_nulls(self):
        current=snapshot();current['tls_findings']=[{'port':443,'days_until_expiry':4}]
        self.assertEqual(score_snapshot(current)['findings'][0]['host'],'owned.example')
        result=diff_scans({'subdomains':None,'open_ports':None,'socket_findings':None,'tls_findings':None},current)
        self.assertEqual(result['risk']['severity'],'high')
    def test_asset_ip_port_service_and_certificate_changes(self):
        before=snapshot([80,443],[{'port':80,'fingerprint':'http','banner':'HTTP/1.0 old'}],[{'port':443,'serial_number':'1','expires':'2027-01-01T00:00:00Z'}])
        before['resolved_addresses']={'owned.example':['8.8.8.8']}
        after=snapshot([80,443,22],[{'port':80,'fingerprint':'http','banner':'HTTP/1.1 new'}],[{'port':443,'serial_number':'2','expires':'2028-01-01T00:00:00Z'}])
        after['resolved_addresses']={'owned.example':['1.1.1.1']}
        result=diff_scans(before,after)
        self.assertEqual(len(result['changes']['assets']['changed']),1)
        self.assertEqual(len(result['changes']['services']['changed']),1)
        self.assertEqual(len(result['changes']['certificates']['changed']),1)
        self.assertEqual(len(result['changes']['ports']['changed']),2)
        self.assertEqual(result['new_open_ports'],{'owned.example':[22]})
    def test_removed_host_includes_all_endpoint_observations(self):
        before=snapshot([443],[{'port':443,'fingerprint':'http'}],[{'port':443,'expires':'2027-01-01T00:00:00Z'}])
        result=diff_scans(before,{'subdomains':[],'open_ports':{}})
        for kind in ['assets','ports','services','certificates']:
            self.assertEqual(len(result['changes'][kind]['no_longer_detected']),1)
        self.assertEqual(result['closed_ports'],{'owned.example':[443]})
        self.assertIn('does not establish',result['comparison_notes'][0])
    def test_same_cert_age_change_is_not_rotation(self):
        before=snapshot([443],tls=[{'port':443,'expires':'2027-01-01T00:00:00Z','days_until_expiry':20}])
        after=deepcopy(before);after['tls_findings']['owned.example'][0]['days_until_expiry']=19
        result=diff_scans(before,after)
        self.assertEqual(result['changes']['certificates']['changed'],[])
    def test_certificate_fingerprint_detects_same_metadata_replacement(self):
        before=snapshot([443],tls=[{'port':443,'sha256':'a'}]);after=deepcopy(before);after['tls_findings']['owned.example'][0]['sha256']='b'
        self.assertEqual(len(diff_scans(before,after)['changes']['certificates']['changed']),1)
    def test_partial_scan_and_handshake_gaps_not_remediation(self):
        before=snapshot([443],tls=[{'port':443,'expires':'2026-10-26T00:00:00Z'}])
        after=snapshot([443],tls=[{'port':443,'reachable':False,'error':'timeout'}]);after['warnings']=[{'stage':'dns'}]
        result=diff_scans(before,after)
        self.assertEqual(len(result['changes']['certificates']['no_longer_detected']),1)
        self.assertEqual(len(result['changes']['findings']['no_longer_detected']),1)
        self.assertTrue(any('incomplete coverage' in n for n in result['comparison_notes']))
    def test_stable_ids_and_input_order_independence(self):
        a=snapshot([22,80],[{'port':80,'fingerprint':'http'},{'port':22,'flags':['possible_version_disclosure']}])
        b=deepcopy(a);b['open_ports']['owned.example'].reverse();b['socket_findings']['owned.example'].reverse()
        self.assertEqual(score_snapshot(a),score_snapshot(b))
        self.assertFalse(diff_scans(a,b)['changes']['assets']['changed'])
    def test_findings_severity_change_uses_same_id(self):
        a=snapshot([443],tls=[{'port':443,'expires':'2026-11-10T00:00:00Z'}]);a['diff']={'risk':score_snapshot(a)}
        b=deepcopy(a);b['observed_at']='2026-11-05T00:00:00Z'
        result=diff_scans(a,b)['changes']['findings']
        self.assertEqual(len(result['changed']),1)
        self.assertEqual(result['changed'][0]['before']['id'],result['changed'][0]['after']['id'])
        self.assertEqual(result['changed'][0]['after']['severity'],'high')
    def test_no_unsubstantiated_version_vulnerability_claim(self):
        result=score_snapshot(snapshot([22],[{'port':22,'fingerprint':'ssh','banner':'SSH-2.0-OldServer 1.0','flags':[]}]))
        self.assertEqual(result['findings'],[])


class LocalObservationTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_local_http_observation_becomes_risk(self):
        import asyncio
        from worker.tasks.socket_scan import _probe_port
        async def handler(reader, writer):
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server=await asyncio.start_server(handler,'127.0.0.1',0)
        async with server:
            port=server.sockets[0].getsockname()[1]
            observation=await _probe_port('127.0.0.1',port)
        self.assertEqual(observation['fingerprint'],'http')
        # Test-owned loopback fixture exercises observation -> scoring, not DNS ownership.
        result=score_snapshot(snapshot([port],[observation]))
        finding=next(f for f in result['findings'] if f['rule_id']=='insecure_http')
        self.assertEqual(finding['severity'],'medium')
        self.assertTrue(finding['evidence']['banner'].startswith('HTTP/1.1 200 OK'))
