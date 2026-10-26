import unittest

from cffc.normalizers import NORMALIZERS, NormalizationError
from cffc.normalizers.aws_cloudtrail import normalize_record
from cffc.schema import CANONICAL_FIELDS, REQUIRED_FIELDS, populated_field_count, validate_event
from cffc.timeutil import TimeParseError, format_utc, parse_utc
from .helpers import HASH, cloudtrail_record, ev


def norm(rec, idx=3):
    return normalize_record(rec, source_log_file="a/b.json.gz", record_index=idx, evidence_hash=HASH)


class TimeTests(unittest.TestCase):
    def test_parse_variants_to_utc(self):
        self.assertEqual(format_utc(parse_utc("2026-01-15T14:30:00+05:30")), "2026-01-15T09:00:00Z")
        self.assertEqual(format_utc(parse_utc("2026-01-15T09:00:00Z")), "2026-01-15T09:00:00Z")
        self.assertEqual(format_utc(parse_utc("2026-01-15T09:00:00.123456789Z")), "2026-01-15T09:00:00.123456Z")

    def test_naive_and_garbage_rejected(self):
        for bad in ("2026-01-15T09:00:00", "not-a-time", "", 12345):
            with self.assertRaises(TimeParseError):
                parse_utc(bad)


class SchemaTests(unittest.TestCase):
    def test_sixteen_fields_and_required_split(self):
        self.assertEqual(len(CANONICAL_FIELDS), 16)
        self.assertEqual(set(CANONICAL_FIELDS) - set(REQUIRED_FIELDS), {"source_ip", "resource_id", "region"})

    def test_valid_event_has_no_errors(self):
        self.assertEqual(validate_event(ev("e1", 0, ip="198.51.100.1")), [])

    def test_each_rule_rejects(self):
        base = ev("e1", 0).to_dict()
        cases = {
            "event_time_utc": "2026-01-15 09:00:00", "cloud_provider": "oracle", "event_type": "weird",
            "result": "maybe", "evidence_hash": "XYZ", "raw_event_ref": "nohash", "schema_version": "9.9",
            "provider_specific": "str", "principal_id": "  ", "source_ip": "",
        }
        for key, bad in cases.items():
            d = dict(base); d[key] = bad
            self.assertTrue(validate_event(d), f"{key}={bad!r} should be rejected")

    def test_missing_required_and_unexpected_field(self):
        d = ev("e1", 0).to_dict(); del d["action"]; d["extra"] = 1
        errs = " | ".join(validate_event(d))
        self.assertIn("missing required field: action", errs)
        self.assertIn("unexpected field: extra", errs)

    def test_uppercase_hash_rejected(self):
        d = ev("e1", 0).to_dict(); d["evidence_hash"] = "A" * 64
        self.assertTrue(validate_event(d))

    def test_populated_count_ignores_empty(self):
        e = ev("e1", 0, ip=None, resource=None)
        e.region = None; e.provider_specific = {}
        self.assertEqual(populated_field_count(e), 16 - 4)
        e2 = ev("e1", 0, ip="1.2.3.4", resource="r")
        self.assertEqual(populated_field_count(e2), 16)


class CloudTrailNormalizationTests(unittest.TestCase):
    def test_core_mapping(self):
        e = norm(cloudtrail_record("GetObject", requestParameters={"bucketName": "bkt"}))
        self.assertEqual((e.cloud_provider, e.cloud_service, e.action, e.region),
                         ("aws", "s3.amazonaws.com", "GetObject", "us-east-1"))
        self.assertEqual(e.principal_id, "arn:aws:iam::000000000000:user/u1")
        self.assertEqual(e.source_ip, "198.51.100.1")
        self.assertEqual(e.resource_id, "arn:aws:s3:::bkt")
        self.assertEqual(e.raw_event_ref, "a/b.json.gz#3")
        self.assertEqual(e.evidence_hash, HASH)
        self.assertEqual(e.result, "success")
        self.assertEqual(validate_event(e), [])

    def test_error_code_means_failure(self):
        self.assertEqual(norm(cloudtrail_record(errorCode="AccessDenied")).result, "failure")

    def test_console_login_results(self):
        mk = lambda s: cloudtrail_record("ConsoleLogin", eventType="AwsConsoleSignIn", responseElements={"ConsoleLogin": s})
        self.assertEqual(norm(mk("Success")).result, "success")
        self.assertEqual(norm(mk("Failure")).result, "failure")
        self.assertEqual(norm(mk("Weird")).result, "unknown")
        self.assertEqual(norm(mk("Success")).event_type, "console_login")
        self.assertEqual(norm(cloudtrail_record("ConsoleLogin")).result, "unknown")

    def test_principal_fallbacks_and_sentinels(self):
        r = cloudtrail_record(userIdentity={"type": "IAMUser", "principalId": "Unknown", "userName": "HIDDEN_DUE_TO_SECURITY_REASONS"})
        self.assertEqual(norm(r).principal_id, "unknown")
        r = cloudtrail_record(userIdentity={"type": "AWSService", "invokedBy": "ec2.amazonaws.com"})
        self.assertEqual(norm(r).principal_id, "ec2.amazonaws.com")
        r = cloudtrail_record(userIdentity={"type": "IAMUser", "principalId": "AIDAX"})
        self.assertEqual(norm(r).principal_id, "AIDAX")
        r = cloudtrail_record(); del r["userIdentity"]
        self.assertEqual(norm(r).principal_id, "unknown")

    def test_resource_priority(self):
        r = cloudtrail_record(resources=[{"ARN": "arn:aws:s3:::b/k"}, {"ARN": "arn:aws:s3:::b"}], requestParameters={"roleArn": "R"})
        self.assertEqual(norm(r).resource_id, "arn:aws:s3:::b/k")
        self.assertEqual(norm(cloudtrail_record(requestParameters={"roleArn": "arn:role"})).resource_id, "arn:role")
        r = cloudtrail_record(responseElements={"instancesSet": {"items": [{"instanceId": "i-1"}]}})
        self.assertEqual(norm(r).resource_id, "i-1")
        self.assertIsNone(norm(cloudtrail_record()).resource_id)

    def test_timezone_offset_converted(self):
        self.assertEqual(norm(cloudtrail_record(t="2026-01-15T14:30:00+05:30")).event_time_utc, "2026-01-15T09:00:00Z")

    def test_generated_event_id_is_deterministic(self):
        r = cloudtrail_record(); del r["eventID"]
        self.assertEqual(norm(r).event_id, norm(r).event_id)
        self.assertNotEqual(norm(r, 1).event_id, norm(r, 2).event_id)

    def test_missing_required_fields_raise(self):
        for key in ("eventTime", "eventName", "eventSource"):
            r = cloudtrail_record(); del r[key]
            with self.assertRaises(NormalizationError):
                norm(r)
        with self.assertRaises(NormalizationError):
            norm(cloudtrail_record(t="garbage"))
        with self.assertRaises(NormalizationError):
            norm("not a dict")

    def test_provider_specific_preserved(self):
        e = norm(cloudtrail_record(requestParameters={"a": 1}, errorCode="X"))
        self.assertEqual(e.provider_specific["requestParameters"], {"a": 1})
        self.assertEqual(e.provider_specific["errorCode"], "X")
        self.assertEqual(e.provider_specific["userIdentity"]["accountId"], "000000000000")


class DesignLevelCrossProviderTests(unittest.TestCase):
    """RQ1 structural-portability check on hand-written SYNTHETIC samples (not live Azure/GCP data)."""

    def test_azure_sample(self):
        rec = {"eventTimestamp": "2026-01-15T09:00:00Z", "operationName": "Microsoft.Compute/virtualMachines/write",
               "caller": "alice@example.org", "callerIpAddress": "198.51.100.5", "resourceId": "/subscriptions/x/rg/vm1",
               "resultType": "Success", "eventDataId": "azure-evt-1", "category": "Administrative"}
        e = NORMALIZERS["azure"](rec, source_log_file="az.json", record_index=0, evidence_hash=HASH)
        self.assertEqual(validate_event(e), [])
        self.assertEqual((e.cloud_provider, e.cloud_service, e.principal_id, e.result, e.event_id),
                         ("azure", "Microsoft.Compute", "alice@example.org", "success", "azure-evt-1"))

    def test_gcp_sample(self):
        rec = {"insertId": "gcp-1", "timestamp": "2026-01-15T09:00:00.123456789Z",
               "protoPayload": {"serviceName": "storage.googleapis.com", "methodName": "storage.objects.get",
                                "authenticationInfo": {"principalEmail": "svc@proj.iam.gserviceaccount.com"},
                                "requestMetadata": {"callerIp": "203.0.113.7"}, "resourceName": "projects/_/buckets/b/objects/o",
                                "status": {"code": 7}}}
        e = NORMALIZERS["gcp"](rec, source_log_file="gcp.json", record_index=0, evidence_hash=HASH)
        self.assertEqual(validate_event(e), [])
        self.assertEqual((e.result, e.action, e.source_ip), ("failure", "storage.objects.get", "203.0.113.7"))

    def test_malformed_rejected(self):
        with self.assertRaises(NormalizationError):
            NORMALIZERS["gcp"]({"timestamp": "2026-01-15T09:00:00Z"}, source_log_file="f", record_index=0, evidence_hash=HASH)
        with self.assertRaises(NormalizationError):
            NORMALIZERS["azure"]({"operationName": "x"}, source_log_file="f", record_index=0, evidence_hash=HASH)


if __name__ == "__main__":
    unittest.main()
