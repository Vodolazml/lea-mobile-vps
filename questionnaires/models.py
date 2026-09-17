from django.db import models


class BusinessRegion(models.Model):
    name = models.CharField(max_length=120, unique=True)
    active = models.BooleanField(default=True)
    sort = models.PositiveIntegerField(default=100)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["sort", "name"]

    def __str__(self):
        return self.name


class DeliveryZone(models.Model):
    region = models.ForeignKey(BusinessRegion, on_delete=models.CASCADE, related_name="zones")
    name = models.CharField(max_length=120)
    active = models.BooleanField(default=True)
    sort = models.PositiveIntegerField(default=100)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["sort", "name"]
        constraints = [models.UniqueConstraint(fields=["region", "name"], name="unique_delivery_zone_per_region")]

    def __str__(self):
        return f"{self.region.name} · {self.name}"


class MobileApiKey(models.Model):
    """Allow-listed mobile Bearer tokens. Only the SHA-256 hash is stored, never the raw token."""
    token_hash = models.CharField(max_length=64, primary_key=True)
    label = models.CharField(max_length=200, blank=True)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.label or self.token_hash[:12]


class MobileDevice(models.Model):
    device_key = models.CharField(max_length=16, primary_key=True)
    user_id = models.CharField(max_length=100, blank=True, db_index=True)
    display_name = models.CharField(max_length=200, blank=True)
    secret_hash = models.CharField(max_length=64)
    public_name = models.CharField(max_length=200, blank=True)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["device_key"]


class ApiNonce(models.Model):
    device = models.ForeignKey(MobileDevice, on_delete=models.CASCADE, related_name="nonces")
    nonce = models.CharField(max_length=80)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["device", "nonce"], name="unique_nonce_per_device")]
        ordering = ["-created_at"]


class ExchangePackage(models.Model):
    """Opaque encrypted relay queue. The VPS never decrypts encrypted_payload.

    Two directions share this one queue:
      - phone_to_vps: uploaded by a phone, picked up by the local server (device_key set).
      - local_to_phone: pushed by the local server, addressed to a phone by the SHA-256
        hash of its Bearer token (target_token_hash set) — used e.g. for the local server
        to answer a phone's "who am I" identity package with the matching id/ФИО.
    The VPS only ever matches hashes and moves bytes; it cannot read either direction.
    """
    package_uuid = models.CharField(max_length=80, primary_key=True)
    object_uuid = models.CharField(max_length=80, db_index=True)
    object_type = models.CharField(max_length=40)
    device_key = models.CharField(max_length=16, blank=True, db_index=True)
    device_id = models.CharField(max_length=100, blank=True, db_index=True)
    user_id = models.CharField(max_length=100, blank=True, db_index=True)
    target_token_hash = models.CharField(max_length=64, blank=True, db_index=True)
    direction = models.CharField(max_length=40, default="phone_to_vps")
    status = models.CharField(max_length=50, default="uploaded_to_vps", db_index=True)
    channel = models.CharField(max_length=40, default="vps")
    force_upload = models.BooleanField(default=False)
    payload_hash = models.CharField(max_length=64)
    payload_size = models.PositiveIntegerField(default=0)
    encrypted_payload = models.TextField(blank=True)
    error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    uploaded_to_vps_at = models.DateTimeField(null=True, blank=True)
    downloaded_by_local_at = models.DateTimeField(null=True, blank=True)
    confirmed_by_local_at = models.DateTimeField(null=True, blank=True)
    delivered_to_phone_at = models.DateTimeField(null=True, blank=True)
    confirmed_by_phone_at = models.DateTimeField(null=True, blank=True)
    payload_deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    @property
    def payload_present(self):
        return bool(self.encrypted_payload)
