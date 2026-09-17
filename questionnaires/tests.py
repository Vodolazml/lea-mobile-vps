import hashlib
import hmac
import json
import os
import time
import uuid
from unittest.mock import patch

from django.test import TestCase

from .models import BusinessRegion, ExchangePackage, MobileApiKey, MobileDevice


class MobileKeyAuthTests(TestCase):
    def setUp(self):
        self.token = "phone-raw-token"
        self.token_hash = hashlib.sha256(self.token.encode()).hexdigest()
        MobileApiKey.objects.create(token_hash=self.token_hash, label="test-phone", active=True)

    def test_health_requires_known_token(self):
        self.assertEqual(self.client.get("/api/mobile/v1/health/").status_code, 401)
        self.assertEqual(self.client.get("/api/mobile/v1/health/", HTTP_AUTHORIZATION="Bearer wrong").status_code, 401)
        result = self.client.get("/api/mobile/v1/health/", HTTP_AUTHORIZATION=f"Bearer {self.token}")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["service"], "lea-mobile-vps")

    def test_revoked_key_is_rejected(self):
        MobileApiKey.objects.filter(token_hash=self.token_hash).update(active=False)
        self.assertEqual(self.client.get("/api/mobile/v1/health/", HTTP_AUTHORIZATION=f"Bearer {self.token}").status_code, 401)

    def test_directories_lists_only_active_entries(self):
        region = BusinessRegion.objects.create(name="Крым", sort=1)
        region.zones.create(name="Симферополь", sort=1)
        BusinessRegion.objects.create(name="Скрытый", active=False)
        result = self.client.get("/api/mobile/v1/directories/", HTTP_AUTHORIZATION=f"Bearer {self.token}")
        names = [item["name"] for item in result.json()["regions"]]
        self.assertEqual(names, ["Крым"])


class AdminKeyManagementTests(TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"LEA_MOBILE_ADMIN_KEY": "admin-secret"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_register_requires_admin_key(self):
        body = {"token_hash": "a" * 64, "label": "phone-1"}
        self.assertEqual(self.client.post("/api/admin/v1/mobile-keys/register/", json.dumps(body), content_type="application/json").status_code, 401)
        result = self.client.post("/api/admin/v1/mobile-keys/register/", json.dumps(body), content_type="application/json", HTTP_X_LEA_ADMIN_KEY="admin-secret")
        self.assertEqual(result.status_code, 201)
        self.assertTrue(MobileApiKey.objects.filter(token_hash="a" * 64, active=True).exists())

    def test_revoke_deactivates_key(self):
        MobileApiKey.objects.create(token_hash="b" * 64, label="phone-2", active=True)
        result = self.client.post("/api/admin/v1/mobile-keys/revoke/", json.dumps({"token_hash": "b" * 64}), content_type="application/json", HTTP_X_LEA_ADMIN_KEY="admin-secret")
        self.assertEqual(result.status_code, 200)
        self.assertFalse(MobileApiKey.objects.get(token_hash="b" * 64).active)


class ExchangePackageRelayTests(TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"LEA_MOBILE_LOCAL_API_KEY": "local-secret"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.token = "phone-raw-token"
        MobileApiKey.objects.create(token_hash=hashlib.sha256(self.token.encode()).hexdigest(), label="test-phone", active=True)
        self.secret_hash = hashlib.sha256(b"device-secret").hexdigest()
        MobileDevice.objects.create(device_key="A7K3", user_id="test-phone", display_name="Test", secret_hash=self.secret_hash, active=True)
        self.package_uuid = "A7K3-T6FS9E-Z91P2Q-PKG"
        self.object_uuid = "A7K3-T6FS9D-X82K4M-Q"
        self.encrypted_payload = "v1:opaque-ciphertext-nobody-on-vps-can-read"
        self.payload_hash = hashlib.sha256(self.encrypted_payload.encode()).hexdigest()

    def signed_headers(self, path, body, idempotency=None):
        timestamp = str(int(time.time() * 1000))
        nonce = str(uuid.uuid4())
        raw = json.dumps(body)
        message = "\n".join(["POST", path, timestamp, nonce, raw]).encode("utf-8")
        signature = hmac.new(self.secret_hash.encode("utf-8"), message, hashlib.sha256).hexdigest()
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {self.token}",
            "HTTP_X_LEA_DEVICE_KEY": "A7K3",
            "HTTP_X_LEA_TIMESTAMP": timestamp,
            "HTTP_X_LEA_NONCE": nonce,
            "HTTP_X_LEA_SIGNATURE": signature,
        }
        if idempotency:
            headers["HTTP_IDEMPOTENCY_KEY"] = idempotency
        return raw, headers

    def upload(self):
        body = {
            "package_uuid": self.package_uuid,
            "object_uuid": self.object_uuid,
            "object_type": "questionnaire",
            "device_key": "A7K3",
            "user_id": "test-phone",
            "payload_hash": self.payload_hash,
            "payload_size": len(self.encrypted_payload),
            "encrypted_payload": self.encrypted_payload,
        }
        raw, headers = self.signed_headers("/api/mobile/v1/packages/", body, self.package_uuid)
        return self.client.post("/api/mobile/v1/packages/", raw, content_type="application/json", **headers)

    def test_package_lifecycle_deletes_payload_only_after_confirm(self):
        result = self.upload()
        self.assertEqual(result.status_code, 201, result.content)
        row = ExchangePackage.objects.get(package_uuid=self.package_uuid)
        self.assertTrue(row.encrypted_payload)
        self.assertEqual(row.status, "uploaded_to_vps")

        status_body = {"package_uuids": [self.package_uuid]}
        raw, headers = self.signed_headers("/api/mobile/v1/packages/status/", status_body)
        status = self.client.post("/api/mobile/v1/packages/status/", raw, content_type="application/json", **headers)
        self.assertEqual(status.json()["packages"][0]["status"], "uploaded_to_vps")

        inbox = self.client.post("/api/local/v1/packages/inbox/", json.dumps({}), content_type="application/json", HTTP_X_LEA_LOCAL_KEY="local-secret")
        self.assertEqual(inbox.status_code, 200)
        self.assertEqual(inbox.json()["packages"][0]["encrypted_payload"], self.encrypted_payload)
        row.refresh_from_db()
        self.assertEqual(row.status, "downloaded_by_local_server")

        confirm = self.client.post("/api/local/v1/packages/confirm/", json.dumps({"packages": [{"package_uuid": self.package_uuid, "status": "processed_by_local_server"}]}), content_type="application/json", HTTP_X_LEA_LOCAL_KEY="local-secret")
        self.assertEqual(confirm.status_code, 200)
        row.refresh_from_db()
        self.assertEqual(row.status, "processed_by_local_server")
        self.assertFalse(row.encrypted_payload, "payload must be wiped from VPS once the local server confirmed it")
        self.assertIsNotNone(row.payload_deleted_at)

    def test_local_endpoints_require_local_key(self):
        self.assertEqual(self.client.post("/api/local/v1/packages/inbox/", "{}", content_type="application/json").status_code, 401)
        self.assertEqual(self.client.get("/api/local/v1/logs/").status_code, 401)

    def test_technical_log_exposes_metadata_only(self):
        self.upload()
        result = self.client.get("/api/local/v1/logs/", HTTP_X_LEA_LOCAL_KEY="local-secret")
        payload = result.json()["packages"][0]
        self.assertNotIn("encrypted_payload", payload)
        self.assertEqual(payload["package_uuid"], self.package_uuid)

    def test_identity_handshake_local_pushes_answer_phone_pulls_and_acks(self):
        """The VPS relays a "who am I" question package from phone to local, and an
        identity answer package from local back to phone, without ever decrypting either."""
        result = self.upload()
        self.assertEqual(result.status_code, 201)

        answer_uuid = "A7K3-ANSWER1-Z91P2Q-PKG"
        answer_payload = "v1:opaque-identity-answer-nobody-on-vps-can-read"
        answer_hash = hashlib.sha256(answer_payload.encode()).hexdigest()
        outbox_body = {
            "package_uuid": answer_uuid,
            "object_uuid": self.object_uuid,
            "object_type": "identity_response",
            "target_token_hash": hashlib.sha256(self.token.encode()).hexdigest(),
            "payload_hash": answer_hash,
            "payload_size": len(answer_payload),
            "encrypted_payload": answer_payload,
        }
        outbox = self.client.post(
            "/api/local/v1/packages/outbox/", json.dumps(outbox_body), content_type="application/json",
            HTTP_X_LEA_LOCAL_KEY="local-secret", HTTP_IDEMPOTENCY_KEY=answer_uuid,
        )
        self.assertEqual(outbox.status_code, 201, outbox.content)

        inbox = self.client.get("/api/mobile/v1/packages/inbox/", HTTP_AUTHORIZATION=f"Bearer {self.token}")
        self.assertEqual(inbox.status_code, 200)
        packages = inbox.json()["packages"]
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0]["encrypted_payload"], answer_payload)
        row = ExchangePackage.objects.get(package_uuid=answer_uuid)
        self.assertEqual(row.status, "downloaded_by_phone")

        ack = self.client.post(
            "/api/mobile/v1/packages/ack/", json.dumps({"package_uuids": [answer_uuid]}),
            content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        self.assertEqual(ack.status_code, 200)
        self.assertEqual(ack.json()["confirmed"], 1)
        row.refresh_from_db()
        self.assertEqual(row.status, "confirmed_by_phone")
        self.assertFalse(row.encrypted_payload)

    def test_local_inbox_never_returns_local_to_phone_packages(self):
        """Regression: local_inbox used to return every uploaded_to_vps row regardless of
        direction, so the office would pull back its own identity_response pushes and choke
        trying to process them as an inbound questionnaire."""
        self.upload()  # a genuine phone_to_vps package
        outbox_body = {
            "package_uuid": "A7K3-ANSWER3-Z91P2Q-PKG",
            "object_uuid": self.object_uuid,
            "object_type": "identity_response",
            "target_token_hash": hashlib.sha256(self.token.encode()).hexdigest(),
            "payload_hash": hashlib.sha256(b"x").hexdigest(),
            "payload_size": 1,
            "encrypted_payload": "v1:answer-for-the-phone-not-the-office",
        }
        self.client.post(
            "/api/local/v1/packages/outbox/", json.dumps(outbox_body), content_type="application/json",
            HTTP_X_LEA_LOCAL_KEY="local-secret", HTTP_IDEMPOTENCY_KEY=outbox_body["package_uuid"],
        )
        inbox = self.client.post("/api/local/v1/packages/inbox/", json.dumps({}), content_type="application/json", HTTP_X_LEA_LOCAL_KEY="local-secret")
        uuids = [p["package_uuid"] for p in inbox.json()["packages"]]
        self.assertEqual(uuids, [self.package_uuid])
        self.assertNotIn("A7K3-ANSWER3-Z91P2Q-PKG", uuids)

    def test_local_outbox_rearms_on_repeat_push_unless_confirmed(self):
        """The local server retries pushing the same identity_response every sync run
        (deterministic package_uuid). Repeating it must revive a row a bug once knocked into
        manual_review_required, but never undo a delivery the phone already confirmed."""
        target_hash = hashlib.sha256(self.token.encode()).hexdigest()
        body = {
            "package_uuid": "grant-a7k3demo", "object_uuid": "grant-a7k3demo", "object_type": "identity_response",
            "target_token_hash": target_hash, "payload_hash": hashlib.sha256(b"x").hexdigest(),
            "payload_size": 1, "encrypted_payload": "v1:answer",
        }
        headers = {"HTTP_X_LEA_LOCAL_KEY": "local-secret", "HTTP_IDEMPOTENCY_KEY": body["package_uuid"]}
        self.client.post("/api/local/v1/packages/outbox/", json.dumps(body), content_type="application/json", **headers)
        row = ExchangePackage.objects.get(package_uuid=body["package_uuid"])
        row.status = "manual_review_required"
        row.encrypted_payload = ""
        row.save(update_fields=["status", "encrypted_payload"])

        self.client.post("/api/local/v1/packages/outbox/", json.dumps(body), content_type="application/json", **headers)
        row.refresh_from_db()
        self.assertEqual(row.status, "uploaded_to_vps")
        self.assertEqual(row.encrypted_payload, "v1:answer")

        row.status = "confirmed_by_phone"
        row.encrypted_payload = ""
        row.save(update_fields=["status", "encrypted_payload"])
        self.client.post("/api/local/v1/packages/outbox/", json.dumps(body), content_type="application/json", **headers)
        row.refresh_from_db()
        self.assertEqual(row.status, "confirmed_by_phone")
        self.assertFalse(row.encrypted_payload)

    def test_mobile_inbox_never_returns_another_phones_package(self):
        other_token = "someone-elses-token"
        MobileApiKey.objects.create(token_hash=hashlib.sha256(other_token.encode()).hexdigest(), label="other-phone", active=True)
        outbox_body = {
            "package_uuid": "A7K3-ANSWER2-Z91P2Q-PKG",
            "object_uuid": self.object_uuid,
            "object_type": "identity_response",
            "target_token_hash": hashlib.sha256(other_token.encode()).hexdigest(),
            "payload_hash": hashlib.sha256(b"x").hexdigest(),
            "payload_size": 1,
            "encrypted_payload": "v1:for-the-other-phone-only",
        }
        self.client.post(
            "/api/local/v1/packages/outbox/", json.dumps(outbox_body), content_type="application/json",
            HTTP_X_LEA_LOCAL_KEY="local-secret", HTTP_IDEMPOTENCY_KEY=outbox_body["package_uuid"],
        )
        inbox = self.client.get("/api/mobile/v1/packages/inbox/", HTTP_AUTHORIZATION=f"Bearer {self.token}")
        self.assertEqual(inbox.json()["packages"], [])

    def test_bad_signature_is_rejected(self):
        body = {
            "package_uuid": self.package_uuid, "object_uuid": self.object_uuid, "object_type": "questionnaire",
            "device_key": "A7K3", "user_id": "test-phone", "payload_hash": self.payload_hash,
            "payload_size": len(self.encrypted_payload), "encrypted_payload": self.encrypted_payload,
        }
        raw, headers = self.signed_headers("/api/mobile/v1/packages/", body, self.package_uuid)
        headers["HTTP_X_LEA_SIGNATURE"] = "0" * 64
        result = self.client.post("/api/mobile/v1/packages/", raw, content_type="application/json", **headers)
        self.assertEqual(result.status_code, 401)
        self.assertFalse(ExchangePackage.objects.exists())

    def test_local_directories_sync_replaces_regions_and_zones(self):
        BusinessRegion.objects.create(name="Устаревший регион", sort=1)
        body = {"regions": [{"name": "Крым", "sort": 1, "zones": [{"name": "Симферополь", "sort": 1}, {"name": "Ялта", "sort": 2}]}]}
        result = self.client.post("/api/local/v1/directories/sync/", json.dumps(body), content_type="application/json", HTTP_X_LEA_LOCAL_KEY="local-secret")
        self.assertEqual(result.status_code, 200, result.content)
        self.assertEqual(result.json()["regions"], 1)
        region = BusinessRegion.objects.get()
        self.assertEqual(region.name, "Крым")
        self.assertEqual(sorted(region.zones.values_list("name", flat=True)), ["Симферополь", "Ялта"])

        fetched = self.client.get("/api/mobile/v1/directories/", HTTP_AUTHORIZATION=f"Bearer {self.token}")
        self.assertEqual([r["name"] for r in fetched.json()["regions"]], ["Крым"])
