from django.urls import path
from questionnaires import views

urlpatterns = [
    path("api/mobile/v1/health/", views.health),
    path("api/mobile/v1/device/register/", views.register_device),
    path("api/mobile/v1/directories/", views.directories),
    path("api/mobile/v1/version/", views.app_version),
    path("api/mobile/v1/download/", views.app_download),
    path("api/mobile/v1/packages/", views.upload_package),
    path("api/mobile/v1/packages/status/", views.package_statuses),
    path("api/mobile/v1/packages/inbox/", views.mobile_inbox),
    path("api/mobile/v1/packages/ack/", views.mobile_ack),
    path("api/local/v1/packages/inbox/", views.local_inbox),
    path("api/local/v1/packages/confirm/", views.local_confirm),
    path("api/local/v1/packages/confirm-direct/", views.local_confirm_direct),
    path("api/local/v1/packages/outbox/", views.local_outbox),
    path("api/local/v1/logs/", views.technical_logs),
    path("api/local/v1/directories/sync/", views.local_directories_sync),
    path("api/local/v1/release/publish/", views.local_publish_release),
    path("api/local/v1/release/status/", views.local_release_status),
    path("api/local/v1/packages/prune/", views.local_prune_packages),
    path("api/admin/v1/mobile-keys/register/", views.admin_register_key),
    path("api/admin/v1/mobile-keys/revoke/", views.admin_revoke_key),
    path("api/admin/v1/mobile-keys/", views.admin_list_keys),
]
