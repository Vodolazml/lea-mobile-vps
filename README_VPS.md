# LEA mobile VPS bridge

This is the full, self-contained deployment bundle for the public VPS bridge. It is
meant to live in its own `lea-mobile-vps` repository — push exactly this folder's
contents there, so the VPS only ever pulls the code it actually needs.

## What this is (and is not)

The VPS is a dumb relay between the phone and the office's local server:

- The phone encrypts a questionnaire on-device and uploads the opaque ciphertext.
- The VPS stores that ciphertext in `ExchangePackage.encrypted_payload` until the
  local server picks it up (`/api/local/v1/packages/inbox/`) and confirms it was
  processed (`/api/local/v1/packages/confirm/`), at which point the VPS deletes it.
- The VPS has **no decryption key** and never has one — do not set an exchange/payload
  key in `/etc/lea-mobile.env` on this machine, ever.
- The VPS has **no questionnaire admin UI, no photo storage, no payroll login**. Those
  only exist on the local office server. The only thing an admin can see here is the
  exchange log (`/api/local/v1/logs/`) — package metadata (status/timestamps), never
  field content.

## Mobile authentication (no login round-trip to the VPS)

The phone generates its own random API token locally and never sends the raw token
anywhere for storage — it authenticates every request with `Authorization: Bearer <token>`,
and the VPS only ever stores/compares the **SHA-256 hash** of that token
(`MobileApiKey.token_hash`).

### Adding a phone

1. On the phone (or with `python generate_key.py` for a one-off test token), get the
   raw token and its SHA-256 hash.
2. From the office, register the hash on the VPS:

   ```bash
   curl -X POST https://YOUR_DOMAIN/api/admin/v1/mobile-keys/register/ \
     -H "X-LEA-Admin-Key: $LEA_MOBILE_ADMIN_KEY" \
     -H "Content-Type: application/json" \
     -d '{"token_hash": "<sha256 hash>", "label": "Иванов И.И."}'
   ```

3. The phone can now call any `/api/mobile/v1/...` endpoint with that raw token.

### Revoking a phone

```bash
curl -X POST https://YOUR_DOMAIN/api/admin/v1/mobile-keys/revoke/ \
  -H "X-LEA-Admin-Key: $LEA_MOBILE_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"token_hash": "<sha256 hash>"}'
```

### Listing registered phones

```bash
curl https://YOUR_DOMAIN/api/admin/v1/mobile-keys/ -H "X-LEA-Admin-Key: $LEA_MOBILE_ADMIN_KEY"
```

Package uploads (`/api/mobile/v1/packages/` and `/status/`) additionally require a
per-request HMAC signature tied to a registered device (`/api/mobile/v1/device/register/`,
`X-LEA-Device-Key` / `X-LEA-Timestamp` / `X-LEA-Nonce` / `X-LEA-Signature` headers) — this
part was already working before this cleanup and is unchanged.

### Identity handshake ("who am I"), same relay, no VPS login

There's still no login endpoint on the VPS. Instead, the exchange-package queue works in
both directions, and the VPS only ever matches a token hash to route bytes — it never
reads either side:

1. Phone uploads an encrypted `identity_request` package the normal way
   (`POST /api/mobile/v1/packages/`, signed).
2. Local server pulls it via `/api/local/v1/packages/inbox/` like any other package,
   decrypts it, looks up the employee by the accompanying token hash in its own table,
   and pushes an encrypted `identity_response` package back with
   `POST /api/local/v1/packages/outbox/` (`local_api_auth`, body includes
   `target_token_hash`).
3. Phone polls `GET /api/mobile/v1/packages/inbox/` (Bearer auth only), gets the package
   addressed to its own token hash, decrypts it locally to learn its id/ФИО, then
   acknowledges with `POST /api/mobile/v1/packages/ack/` so the VPS wipes the payload.

Registering the token hash via the admin API (above) is still the one-time bootstrap step
that lets a phone in at all — the identity handshake only tells the phone *who it is*,
it isn't what lets it talk to the VPS in the first place.

## Directories (business regions / delivery zones)

The phone also fetches `GET /api/mobile/v1/directories/` from whichever server `settings.url`
points at, so a copy of `BusinessRegion`/`DeliveryZone` lives on the VPS too. There is no
admin UI for it here by design (keep the VPS surface minimal) — manage entries with the
Django shell:

```bash
cd /opt/lea-mobile
set -a; . /etc/lea-mobile.env; set +a
.venv/bin/python manage.py shell -c "
from questionnaires.models import BusinessRegion
r = BusinessRegion.objects.create(name='Крым', sort=1)
r.zones.create(name='Симферополь', sort=1)
"
```

## Install on VPS

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nginx

sudo mkdir -p /opt/lea-mobile /var/lib/lea-mobile-vps
sudo chown -R rus12:rus12 /opt/lea-mobile /var/lib/lea-mobile-vps
```

Copy this folder's contents to `/opt/lea-mobile`, then run:

```bash
cd /opt/lea-mobile
python3 -m venv .venv
.venv/bin/pip install -U pip
.venv/bin/pip install -r requirements.txt
```

Create `/etc/lea-mobile.env` from `deploy/vps.env.example`.

Generate the Django secret:

```bash
cd /opt/lea-mobile
.venv/bin/python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

Generate the local-server API key and the admin key (run twice, once per key):

```bash
openssl rand -hex 32
```

Apply migrations:

```bash
cd /opt/lea-mobile
set -a
. /etc/lea-mobile.env
set +a
.venv/bin/python manage.py migrate
```

Install the service:

```bash
sudo cp /opt/lea-mobile/deploy/lea-mobile-vps.service /etc/systemd/system/lea-mobile.service
sudo systemctl daemon-reload
sudo systemctl enable --now lea-mobile
sudo systemctl status lea-mobile --no-pager
```

Install the nginx config:

```bash
sudo cp /opt/lea-mobile/deploy/nginx-vps.conf /etc/nginx/sites-available/lea-mobile
sudo ln -s /etc/nginx/sites-available/lea-mobile /etc/nginx/sites-enabled/lea-mobile
sudo nginx -t
sudo systemctl reload nginx
```

Check:

```bash
curl -H "Authorization: Bearer test" http://YOUR_DOMAIN_OR_IP/api/mobile/v1/health/
# expect: {"service": "lea-mobile-vps", ..., "error": "unauthorized"} until a real key is registered
```
