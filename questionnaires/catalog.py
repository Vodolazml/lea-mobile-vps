"""1С product catalog for phones. The office server pushes, whenever its catalog version changes,
the full catalog at that version and a package of the changes since the version it pushed
before (local_catalog_publish). Those change packages form a chain v1→v3→v4→…; a phone tells
its own version and gets (mobile_catalog):

  * nothing new        — it's already on the latest version;
  * the changes        — the chain from its version up to the latest, merged into one answer;
  * the full catalog   — first download, or its version fell out of the chain, or the changes
                         would weigh more than the whole catalog anyway.

Packages are stored gzipped as the office built them; VPS only opens them to merge a chain.
"""
import base64
import binascii
import gzip
import json

from django.db import transaction
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .models import CatalogPackage
from .views import api_auth, local_api_auth, response

# Change packages kept; a phone further behind than that gets the full catalog.
KEEP_DELTAS = 200
MAX_PACKAGE_BYTES = 100 * 1024 * 1024


def _gzip_response(data: bytes) -> HttpResponse:
    reply = HttpResponse(data, content_type="application/json; charset=utf-8")
    reply["Content-Encoding"] = "gzip"
    reply["Cache-Control"] = "no-store"
    return reply


def _decode(b64: str) -> bytes:
    data = base64.b64decode(b64.encode("ascii"), validate=True)
    if not data or len(data) > MAX_PACKAGE_BYTES:
        raise ValueError("bad size")
    json.loads(gzip.decompress(data))  # must be a whole, readable package
    return data


@csrf_exempt
@require_POST
@local_api_auth
def local_catalog_publish(request):
    try:
        body = json.loads(request.body or b"{}")
        version = int(body.get("version") or 0)
        full = _decode(str(body.get("full") or ""))
        delta = _decode(str(body["delta"])) if body.get("delta") else None
        from_version = int(body.get("from") or 0)
        if version <= 0 or (delta is not None and not 0 < from_version < version):
            raise ValueError()
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, binascii.Error, OSError, EOFError):
        return response({"error": "invalid_catalog"}, 400)
    stored = ["full"]
    with transaction.atomic():
        latest = CatalogPackage.objects.filter(kind="full").order_by("-to_version").first()
        # A change package only joins the chain if it starts where the chain ends — after a
        # VPS reset or a missed push, phones simply fall back to the full catalog.
        if delta is not None and latest is not None and latest.to_version == from_version:
            CatalogPackage.objects.update_or_create(kind="delta", from_version=from_version, to_version=version, defaults={"data": delta, "size": len(delta)})
            stored.append("delta")
        CatalogPackage.objects.filter(kind="full").delete()
        CatalogPackage.objects.create(kind="full", from_version=0, to_version=version, data=full, size=len(full))
        stale = CatalogPackage.objects.filter(kind="delta").order_by("-to_version").values_list("id", flat=True)[KEEP_DELTAS:]
        CatalogPackage.objects.filter(id__in=list(stale)).delete()
    return response({"accepted": True, "version": version, "stored": "+".join(stored)}, 201)


def _merge(packages) -> dict:
    """Later packages win: a product re-added after removal is back, one removed after an
    update is gone. Groups/warehouses come whole with every package — the last one is current."""
    products, removed, last = {}, set(), None
    for package in packages:
        last = json.loads(gzip.decompress(package.data))
        for item in last.get("products", []):
            products[item["i"]] = item
            removed.discard(item["i"])
        for pid in last.get("remove", []):
            products.pop(pid, None)
            removed.add(pid)
    merged = dict(last)
    merged.update({"from": packages[0].from_version, "products": list(products.values()), "remove": sorted(removed)})
    return merged


@require_GET
@api_auth
def mobile_catalog(request):
    try:
        since = max(int(request.GET.get("since") or 0), 0)
    except ValueError:
        since = 0
    full = CatalogPackage.objects.filter(kind="full").order_by("-to_version").first()
    if full is None:
        return response({"version": 0, "up_to_date": True, "empty": True})
    if since == full.to_version:
        return response({"version": since, "up_to_date": True})
    if 0 < since < full.to_version:
        chain, current = [], since
        deltas = {d.from_version: d for d in CatalogPackage.objects.filter(kind="delta", from_version__gte=since).only("id", "from_version", "to_version", "size")}
        while current in deltas and current < full.to_version:
            chain.append(deltas[current])
            current = deltas[current].to_version
        if current == full.to_version and chain and sum(d.size for d in chain) < full.size:
            loaded = list(CatalogPackage.objects.filter(id__in=[d.id for d in chain]).order_by("from_version"))
            return _gzip_response(gzip.compress(json.dumps(_merge(loaded), ensure_ascii=False, separators=(",", ":")).encode("utf-8"), compresslevel=6))
    return _gzip_response(bytes(full.data))


@require_GET
@local_api_auth
def local_catalog_status(request):
    full = CatalogPackage.objects.filter(kind="full").order_by("-to_version").first()
    deltas = CatalogPackage.objects.filter(kind="delta").count()
    return response({"version": full.to_version if full else 0, "full_size": full.size if full else 0, "deltas": deltas})


# ---------------------------------------------------------------------------------------------
# Product pictures: the office sends each picture once as a thumbnail and a card-sized JPEG
# (server_mobile catalog_images.py); phones fetch them by key only when they show them.
# ---------------------------------------------------------------------------------------------

def _image_dir():
    from django.conf import settings
    path = settings.CATALOG_IMAGES_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def _valid_key(key: str) -> bool:
    return 8 <= len(key) <= 40 and all(c in "0123456789abcdef" for c in key)


@csrf_exempt
@require_POST
@local_api_auth
def local_catalog_images(request):
    try:
        items = json.loads(request.body or b"{}").get("images")
        if not isinstance(items, list):
            raise ValueError()
    except (ValueError, TypeError, json.JSONDecodeError):
        return response({"error": "invalid_images"}, 400)
    stored = 0
    folder = _image_dir()
    for item in items:
        key = str(item.get("key") or "")
        if not _valid_key(key):
            continue
        try:
            thumb = base64.b64decode(str(item.get("thumb") or ""), validate=True)
            full = base64.b64decode(str(item.get("full") or ""), validate=True)
        except (binascii.Error, ValueError):
            continue
        if not thumb.startswith(b"\xff\xd8") or not full.startswith(b"\xff\xd8"):
            continue  # only JPEGs, as the office makes them
        for suffix, data in (("t", thumb), ("f", full)):
            tmp = folder / f"{key}_{suffix}.jpg.part"
            tmp.write_bytes(data)
            tmp.replace(folder / f"{key}_{suffix}.jpg")
        stored += 1
    return response({"accepted": True, "stored": stored}, 201)


@require_GET
@api_auth
def mobile_catalog_image(request, key, size):
    from django.http import FileResponse, Http404
    if not _valid_key(key) or size not in ("t", "f"):
        raise Http404("bad key")
    path = _image_dir() / f"{key}_{size}.jpg"
    if not path.is_file():
        raise Http404("no picture")
    reply = FileResponse(open(path, "rb"), content_type="image/jpeg")
    # The key changes whenever the picture does — phones may keep it forever.
    reply["Cache-Control"] = "private, max-age=31536000, immutable"
    return reply
