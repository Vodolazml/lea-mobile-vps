import hashlib
import hmac
import json
import os
import time
from datetime import timedelta
from functools import wraps

from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .models import ApiNonce, BusinessRegion, DeliveryZone, ExchangePackage, MobileApiKey, MobileDevice


def response(data=None, status=200):
    return JsonResponse({"service": "lea-mobile-vps", "schema_version": 1, **(data or {})}, status=status)


def valid_sync_id(value, limit=80, min_len=8):
    value = str(value or "").strip()
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz-_")
    if not min_len <= len(value) <= limit or any(ch not in allowed for ch in value):
        raise ValueError("bad_id")
    return value


def ms(dt):
    return int(dt.timestamp() * 1000) if dt else 0


# ---------------------------------------------------------------------------
# Mobile device authentication: Bearer token hash must be allow-listed on VPS.
# The VPS never sees a login/password and never issues its own tokens — the
# raw token is generated on the phone and its SHA-256 hash is registered here
# out of band by an office admin (see admin_register_key below).
# ---------------------------------------------------------------------------

def api_auth(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return response({"error": "unauthorized"}, 401)
        token = header[7:].strip()
        digest = hashlib.sha256(token.encode()).hexdigest()
        try:
            key = MobileApiKey.objects.get(token_hash=digest, active=True)
        except MobileApiKey.DoesNotExist:
            return response({"error": "unauthorized"}, 401)
        key.last_used_at = timezone.now()
        key.save(update_fields=["last_used_at"])
        request.mobile_user = {"id": key.label or key.token_hash[:12], "display_name": key.label, "role": "device"}
        request.mobile_device = str(request.mobile_user["id"])
        request.mobile_token_hash = digest
        return view(request, *args, **kwargs)
    return wrapped


def request_body_bytes(request):
    return request.body or b""


def verify_signed_device_request(request):
    device_key = str(request.headers.get("X-LEA-Device-Key") or "").strip()
    timestamp = str(request.headers.get("X-LEA-Timestamp") or "").strip()
    nonce = str(request.headers.get("X-LEA-Nonce") or "").strip()
    signature = str(request.headers.get("X-LEA-Signature") or "").strip()
    if not device_key or not timestamp or not nonce or not signature:
        return False, "missing_signature_headers"
    try:
        ts = int(timestamp)
    except ValueError:
        return False, "bad_timestamp"
    if abs(int(time.time() * 1000) - ts) > 10 * 60 * 1000:
        return False, "stale_timestamp"
    try:
        device = MobileDevice.objects.get(device_key=device_key, active=True)
    except MobileDevice.DoesNotExist:
        return False, "unknown_or_blocked_device"
    if device.user_id and str(device.user_id) != str(request.mobile_user.get("id") or ""):
        return False, "device_user_mismatch"
    message = "\n".join([request.method.upper(), request.path, timestamp, nonce, request_body_bytes(request).decode("utf-8", errors="replace")]).encode("utf-8")
    expected = hmac.new(device.secret_hash.encode("utf-8"), message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False, "bad_signature"
    try:
        ApiNonce.objects.create(device=device, nonce=nonce[:80])
    except Exception:
        return False, "nonce_reused"
    device.last_seen_at = timezone.now()
    device.save(update_fields=["last_seen_at"])
    request.mobile_device = device.device_key
    request.mobile_device_row = device
    return True, ""


def signed_api_auth(view):
    @wraps(view)
    @api_auth
    def wrapped(request, *args, **kwargs):
        ok, error = verify_signed_device_request(request)
        if not ok:
            return response({"error": error}, 401)
        return view(request, *args, **kwargs)
    return wrapped


@csrf_exempt
@require_POST
@api_auth
def register_device(request):
    if request.content_type != "application/json":
        return response({"error": "json_required"}, 415)
    try:
        body = json.loads(request.body or b"{}")
        device_key = valid_sync_id(body.get("device_key"), 16, 4)
        secret_hash = str(body.get("secret_hash") or "")
        if len(secret_hash) != 64 or any(ch not in "0123456789abcdef" for ch in secret_hash.lower()):
            raise ValueError()
        public_name = str(body.get("public_name") or "")[:200]
    except (ValueError, TypeError, json.JSONDecodeError):
        return response({"error": "invalid_device"}, 400)
    user_id = str(request.mobile_user.get("id") or "")
    device, created = MobileDevice.objects.get_or_create(device_key=device_key, defaults={"user_id": user_id, "display_name": str(request.mobile_user.get("display_name") or ""), "secret_hash": secret_hash.lower(), "public_name": public_name})
    if not created and device.secret_hash != secret_hash.lower():
        return response({"error": "device_key_conflict"}, 409)
    if not device.active:
        return response({"error": "device_blocked"}, 403)
    if device.user_id != user_id:
        return response({"error": "device_user_mismatch"}, 409)
    device.last_seen_at = timezone.now()
    device.public_name = public_name or device.public_name
    device.save(update_fields=["last_seen_at", "public_name"])
    return response({"accepted": True, "device_key": device.device_key, "created": created})


@require_GET
@api_auth
def health(request):
    ExchangePackage.objects.exists()
    return response({"ready": True, "user": request.mobile_user})


@require_GET
@api_auth
def directories(request):
    regions = []
    for region in BusinessRegion.objects.filter(active=True).prefetch_related("zones"):
        regions.append({
            "id": region.id,
            "name": region.name,
            "zones": [{"id": zone.id, "name": zone.name} for zone in region.zones.filter(active=True)],
        })
    return response({"regions": regions})


# ---------------------------------------------------------------------------
# Encrypted package relay. The VPS only stores/forwards the opaque
# encrypted_payload blob — it has no decryption key and never reads field
# content, so there is nothing readable in the open here except this log.
# ---------------------------------------------------------------------------

def package_json(row):
    return {
        "package_uuid": row.package_uuid,
        "object_uuid": row.object_uuid,
        "object_type": row.object_type,
        "device_key": row.device_key,
        "user_id": row.user_id,
        "target_token_hash": row.target_token_hash,
        "direction": row.direction,
        "channel": row.channel,
        "status": row.status,
        "force_upload": row.force_upload,
        "payload_hash": row.payload_hash,
        "payload_size": row.payload_size,
        "payload_present": row.payload_present,
        "created_at": ms(row.created_at),
        "uploaded_to_vps_at": ms(row.uploaded_to_vps_at),
        "downloaded_by_local_at": ms(row.downloaded_by_local_at),
        "confirmed_by_local_at": ms(row.confirmed_by_local_at),
        "delivered_to_phone_at": ms(row.delivered_to_phone_at),
        "confirmed_by_phone_at": ms(row.confirmed_by_phone_at),
        "payload_deleted_at": ms(row.payload_deleted_at),
        "error": row.error,
    }


def store_uploaded_package(request):
    if request.content_type != "application/json":
        return None, response({"error": "json_required"}, 415)
    try:
        if len(request.body) > 60 * 1024 * 1024:
            return None, response({"error": "too_large"}, 413)
        body = json.loads(request.body)
        package_uuid = valid_sync_id(body.get("package_uuid"))
        object_uuid = valid_sync_id(body.get("object_uuid"))
        object_type = str(body.get("object_type") or "")[:40]
        device_key = valid_sync_id(body.get("device_key"), 16, 4)
        encrypted_payload = str(body.get("encrypted_payload") or "")
        payload_hash = str(body.get("payload_hash") or "")
        payload_size = int(body.get("payload_size") or len(encrypted_payload))
        if object_type not in {"questionnaire", "order", "photo", "directory_ack", "identity_request"} or not encrypted_payload or len(payload_hash) != 64:
            raise ValueError()
        if request.headers.get("Idempotency-Key") != package_uuid:
            raise ValueError()
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None, response({"error": "invalid_package"}, 400)
    now = timezone.now()
    existing = ExchangePackage.objects.filter(package_uuid=package_uuid).first()
    if existing:
        if existing.object_uuid != object_uuid or existing.payload_hash != payload_hash:
            return None, response({"error": "conflict"}, 409)
        return existing, response({"accepted": True, "package": package_json(existing)})
    row = ExchangePackage.objects.create(
        package_uuid=package_uuid,
        object_uuid=object_uuid,
        object_type=object_type,
        device_key=device_key,
        device_id=request.mobile_device,
        user_id=str(body.get("user_id") or request.mobile_user.get("id") or ""),
        target_token_hash=request.mobile_token_hash,
        direction="phone_to_vps",
        channel="vps",
        status="uploaded_to_vps",
        force_upload=bool(body.get("force_upload")),
        payload_hash=payload_hash,
        payload_size=payload_size,
        encrypted_payload=encrypted_payload,
        uploaded_to_vps_at=now,
    )
    return row, response({"accepted": True, "package": package_json(row)}, 201)


@csrf_exempt
@require_POST
@signed_api_auth
def upload_package(request):
    _, result = store_uploaded_package(request)
    return result


@csrf_exempt
@require_POST
@signed_api_auth
def package_statuses(request):
    try:
        body = json.loads(request.body or b"{}")
        ids = body.get("package_uuids") or []
        ids = [valid_sync_id(item) for item in ids[:200]]
    except (ValueError, TypeError, json.JSONDecodeError):
        return response({"error": "invalid_status_request"}, 400)
    rows = ExchangePackage.objects.filter(package_uuid__in=ids, device_id=request.mobile_device)
    return response({"packages": [package_json(row) for row in rows]})


def local_api_auth(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        expected = os.environ.get("LEA_MOBILE_LOCAL_API_KEY", "")
        if expected and hmac.compare_digest(request.headers.get("X-LEA-Local-Key", ""), expected):
            return view(request, *args, **kwargs)
        return response({"error": "local_unauthorized"}, 401)
    return wrapped


@csrf_exempt
@require_POST
@local_api_auth
def local_inbox(request):
    """Only phone-uploaded packages — local_to_phone (identity answers the local server itself
    pushed via local_outbox) must never come back through here, or the office would try to
    process its own outgoing packages as if a phone had sent them."""
    now = timezone.now()
    rows = list(ExchangePackage.objects.filter(direction="phone_to_vps", status="uploaded_to_vps", encrypted_payload__gt="").order_by("created_at")[:100])
    for row in rows:
        row.status = "downloaded_by_local_server"
        row.downloaded_by_local_at = now
        row.save(update_fields=["status", "downloaded_by_local_at"])
    return response({"packages": [{**package_json(row), "encrypted_payload": row.encrypted_payload} for row in rows]})


@csrf_exempt
@require_POST
@local_api_auth
def local_confirm(request):
    try:
        body = json.loads(request.body or b"{}")
        confirmations = body.get("packages") or []
        if not isinstance(confirmations, list):
            raise ValueError()
    except (ValueError, TypeError, json.JSONDecodeError):
        return response({"error": "invalid_confirm"}, 400)
    results = []
    now = timezone.now()
    for item in confirmations[:200]:
        try:
            package_uuid = valid_sync_id(item.get("package_uuid"))
            status = str(item.get("status") or "processed_by_local_server")
            row = ExchangePackage.objects.get(package_uuid=package_uuid)
            if status in {"processed_by_local_server", "duplicate_on_local_server"}:
                # VPS is the log of record for the exchange — the local server only ever
                # displays a mirror of it (see sync_vps_exchange's mirror_vps_log). Wipe the
                # payload (the actual business data), but keep the row: uuid/type/device and
                # every lifecycle timestamp stay visible in "Лог обмена" until someone prunes
                # it on purpose via /api/local/v1/packages/prune/.
                row.status = status
                row.confirmed_by_local_at = now
                row.encrypted_payload = ""
                row.payload_deleted_at = now
                row.error = ""
                row.save(update_fields=["status", "confirmed_by_local_at", "encrypted_payload", "payload_deleted_at", "error"])
            elif status in {"conflict_on_local_server", "manual_review_required"}:
                row.status = status
                row.confirmed_by_local_at = now
                row.error = str(item.get("error") or status)[:1000]
                row.save(update_fields=["status", "confirmed_by_local_at", "error"])
            results.append(package_json(row))
        except Exception as exc:
            results.append({"package_uuid": str(item.get("package_uuid") if isinstance(item, dict) else ""), "status": "error", "error": str(exc)})
    return response({"packages": results})


@csrf_exempt
@require_POST
@local_api_auth
def local_outbox(request):
    """Local server pushes a package addressed to a specific phone (by its token hash),
    e.g. an identity answer to a phone's earlier "who am I" package. Opaque to the VPS."""
    if request.content_type != "application/json":
        return response({"error": "json_required"}, 415)
    try:
        if len(request.body) > 60 * 1024 * 1024:
            return response({"error": "too_large"}, 413)
        body = json.loads(request.body)
        package_uuid = valid_sync_id(body.get("package_uuid"))
        object_uuid = valid_sync_id(body.get("object_uuid"))
        object_type = str(body.get("object_type") or "")[:40]
        target_token_hash = str(body.get("target_token_hash") or "").lower().strip()
        if len(target_token_hash) != 64 or any(ch not in "0123456789abcdef" for ch in target_token_hash):
            raise ValueError()
        encrypted_payload = str(body.get("encrypted_payload") or "")
        payload_hash = str(body.get("payload_hash") or "")
        payload_size = int(body.get("payload_size") or len(encrypted_payload))
        if not object_type or not encrypted_payload or len(payload_hash) != 64:
            raise ValueError()
        if request.headers.get("Idempotency-Key") != package_uuid:
            raise ValueError()
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return response({"error": "invalid_package"}, 400)
    now = timezone.now()
    existing = ExchangePackage.objects.filter(package_uuid=package_uuid).first()
    if existing:
        # local_outbox is only ever called by the trusted local server (local_api_auth), which
        # retries the same logical answer every sync run — re-encrypting uses a random IV, so
        # payload_hash legitimately differs between pushes of identical content. Unlike the
        # phone-facing upload endpoint, there's no spoofing risk here worth rejecting a retry
        # over, so just refresh the content instead of treating that as a conflict. Never touch
        # a row the phone already confirmed, though — that delivery is done.
        if existing.status != "confirmed_by_phone":
            existing.object_uuid = object_uuid
            existing.status = "uploaded_to_vps"
            existing.payload_hash = payload_hash
            existing.payload_size = payload_size
            existing.encrypted_payload = encrypted_payload
            existing.uploaded_to_vps_at = now
            existing.error = ""
            existing.save(update_fields=["object_uuid", "status", "payload_hash", "payload_size", "encrypted_payload", "uploaded_to_vps_at", "error"])
        return response({"accepted": True, "package": package_json(existing)})
    row = ExchangePackage.objects.create(
        package_uuid=package_uuid,
        object_uuid=object_uuid,
        object_type=object_type,
        target_token_hash=target_token_hash,
        direction="local_to_phone",
        channel="vps",
        status="uploaded_to_vps",
        payload_hash=payload_hash,
        payload_size=payload_size,
        encrypted_payload=encrypted_payload,
        uploaded_to_vps_at=now,
    )
    return response({"accepted": True, "package": package_json(row)}, 201)


@require_GET
@api_auth
def mobile_inbox(request):
    """The phone polls for packages the local server addressed to its own token hash."""
    now = timezone.now()
    rows = list(ExchangePackage.objects.filter(
        direction="local_to_phone", target_token_hash=request.mobile_token_hash,
        status="uploaded_to_vps", encrypted_payload__gt="",
    ).order_by("created_at")[:50])
    for row in rows:
        row.status = "downloaded_by_phone"
        row.delivered_to_phone_at = now
        row.save(update_fields=["status", "delivered_to_phone_at"])
    return response({"packages": [{**package_json(row), "encrypted_payload": row.encrypted_payload} for row in rows]})


@csrf_exempt
@require_POST
@api_auth
def mobile_ack(request):
    """The phone confirms it received and decrypted a local_to_phone package. Wipes the
    payload but — unlike a confirmed questionnaire — keeps the row as a lightweight
    confirmed_by_phone marker for a while (cleaned up later by local_prune_packages): the
    office's sync retries the same deterministic grant-<hash> package every run for as long
    as someone still has access, and this marker is what stops that from resurrecting a
    fresh, unclaimed package for an employee who's already fully authorized."""
    try:
        body = json.loads(request.body or b"{}")
        ids = [valid_sync_id(item) for item in (body.get("package_uuids") or [])[:50]]
    except (ValueError, TypeError, json.JSONDecodeError):
        return response({"error": "invalid_ack"}, 400)
    now = timezone.now()
    updated = ExchangePackage.objects.filter(
        package_uuid__in=ids, target_token_hash=request.mobile_token_hash, direction="local_to_phone",
    ).update(status="confirmed_by_phone", confirmed_by_phone_at=now, encrypted_payload="", payload_deleted_at=now)
    return response({"accepted": True, "confirmed": updated})


@require_GET
@local_api_auth
def technical_logs(request):
    """The only thing visible about exchanged data on this VPS: metadata, never content."""
    rows = ExchangePackage.objects.all().order_by("-created_at")[:500]
    return response({"packages": [package_json(row) for row in rows]})


# Finished packages the phone/local server no longer need to see — never anything still
# waiting for someone, and never anything flagged for a human to look at.
TERMINAL_STATUSES = {"processed_by_local_server", "processed_direct_by_local", "duplicate_on_local_server", "confirmed_by_phone"}


@csrf_exempt
@require_POST
@local_api_auth
def local_prune_packages(request):
    """Deletes finished exchange packages older than the requested age — directories are a
    separate, always-current table (never a queued package), so nothing here ever touches
    what the phone downloads for business regions/zones."""
    try:
        body = json.loads(request.body or b"{}")
        older_than_days = int(body.get("older_than_days") or 7)
        if not 0 <= older_than_days <= 3650:
            raise ValueError()
    except (ValueError, TypeError, json.JSONDecodeError):
        return response({"error": "invalid_request"}, 400)
    cutoff = timezone.now() - timedelta(days=older_than_days)
    deleted, _ = ExchangePackage.objects.filter(status__in=TERMINAL_STATUSES, created_at__lt=cutoff).delete()
    return response({"accepted": True, "deleted": deleted})


@csrf_exempt
@require_POST
@local_api_auth
def local_directories_sync(request):
    """Full replace of the region/zone list the phone reads via /api/mobile/v1/directories/.
    The local server pushes this every sync run — business data, not a secret, so a plain
    reference list here doesn't conflict with "nothing readable except the log" on the VPS."""
    try:
        body = json.loads(request.body or b"{}")
        regions = body.get("regions")
        if not isinstance(regions, list):
            raise ValueError()
    except (ValueError, TypeError, json.JSONDecodeError):
        return response({"error": "invalid_directories"}, 400)
    with transaction.atomic():
        DeliveryZone.objects.all().delete()
        BusinessRegion.objects.all().delete()
        for index, item in enumerate(regions[:500]):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()[:120]
            if not name:
                continue
            region = BusinessRegion.objects.create(name=name, sort=int(item.get("sort") or index))
            zones = item.get("zones") or []
            if not isinstance(zones, list):
                continue
            for zi, zone in enumerate(zones[:500]):
                if not isinstance(zone, dict):
                    continue
                zname = str(zone.get("name") or "").strip()[:120]
                if not zname:
                    continue
                DeliveryZone.objects.create(region=region, name=zname, sort=int(zone.get("sort") or zi))
    return response({"accepted": True, "regions": BusinessRegion.objects.count()})


# ---------------------------------------------------------------------------
# Admin key management: an office admin registers/revokes a phone's Bearer
# token hash here. The raw token itself never passes through this API or is
# ever stored anywhere on the VPS — only its SHA-256 hash is.
# ---------------------------------------------------------------------------

def admin_api_auth(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        expected = os.environ.get("LEA_MOBILE_ADMIN_KEY", "")
        if expected and hmac.compare_digest(request.headers.get("X-LEA-Admin-Key", ""), expected):
            return view(request, *args, **kwargs)
        return response({"error": "admin_unauthorized"}, 401)
    return wrapped


@csrf_exempt
@require_POST
@admin_api_auth
def admin_register_key(request):
    try:
        body = json.loads(request.body or b"{}")
        token_hash = str(body.get("token_hash") or "").lower().strip()
        if len(token_hash) != 64 or any(ch not in "0123456789abcdef" for ch in token_hash):
            raise ValueError()
        label = str(body.get("label") or "")[:200]
    except (ValueError, TypeError, json.JSONDecodeError):
        return response({"error": "invalid_key"}, 400)
    with transaction.atomic():
        key, created = MobileApiKey.objects.get_or_create(token_hash=token_hash, defaults={"label": label, "active": True})
        if not created:
            key.label = label or key.label
            key.active = True
            key.save(update_fields=["label", "active"])
    return response({"accepted": True, "created": created, "label": key.label}, 201 if created else 200)


@csrf_exempt
@require_POST
@admin_api_auth
def admin_revoke_key(request):
    try:
        body = json.loads(request.body or b"{}")
        token_hash = str(body.get("token_hash") or "").lower().strip()
        if len(token_hash) != 64:
            raise ValueError()
    except (ValueError, TypeError, json.JSONDecodeError):
        return response({"error": "invalid_key"}, 400)
    updated = MobileApiKey.objects.filter(token_hash=token_hash).update(active=False)
    return response({"accepted": True, "revoked": bool(updated)})


@require_GET
@admin_api_auth
def admin_list_keys(request):
    rows = MobileApiKey.objects.all()
    return response({"keys": [{"token_hash_prefix": row.token_hash[:12], "label": row.label, "active": row.active, "created_at": ms(row.created_at), "last_used_at": ms(row.last_used_at)} for row in rows]})
