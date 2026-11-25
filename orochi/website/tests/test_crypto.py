import pytest
from django.core.management import call_command

from orochi.website.crypto import decrypt_secret, encrypt_secret
from orochi.website.defaults import SERVICE_MISP
from orochi.website.models import Service

OLD_KEY = "old-secret-key-used-before-rotation"
NEW_KEY = "new-secret-key-after-rotation"


def test_decrypt_secret_uses_fallback_keys(settings):
    settings.SECRET_KEY = OLD_KEY
    encrypted = encrypt_secret("api-token")

    settings.SECRET_KEY = NEW_KEY
    settings.SECRET_KEY_FALLBACKS = [OLD_KEY]
    assert decrypt_secret(encrypted) == "api-token"

    settings.SECRET_KEY_FALLBACKS = []
    with pytest.raises(ValueError):
        decrypt_secret(encrypted)


@pytest.mark.django_db
def test_decrypted_key_never_returns_ciphertext(settings):
    settings.SECRET_KEY = OLD_KEY
    service = Service.objects.create(name=SERVICE_MISP, url="https://misp.local", key="api-token")
    assert service.key.startswith("enc:")

    settings.SECRET_KEY = NEW_KEY
    settings.SECRET_KEY_FALLBACKS = []
    service.refresh_from_db()
    assert service.decrypted_key == ""


@pytest.mark.django_db
def test_reencrypt_service_keys_command(settings):
    settings.SECRET_KEY = OLD_KEY
    Service.objects.create(name=SERVICE_MISP, url="https://misp.local", key="api-token")

    settings.SECRET_KEY = NEW_KEY
    settings.SECRET_KEY_FALLBACKS = [OLD_KEY]
    call_command("reencrypt_service_keys")

    settings.SECRET_KEY_FALLBACKS = []
    service = Service.objects.get(name=SERVICE_MISP)
    assert service.decrypted_key == "api-token"
