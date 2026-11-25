from django.core.management.base import BaseCommand

from orochi.website.crypto import decrypt_secret
from orochi.website.models import Service


class Command(BaseCommand):
    """Re-encrypt every Service key with the current ``SECRET_KEY`` after a key rotation."""

    help = (
        "Re-encrypt every Service key with the current SECRET_KEY. "
        "Run after rotating DJANGO_SECRET_KEY, with the old key in DJANGO_SECRET_KEY_FALLBACKS."
    )

    def handle(self, *args, **options):
        """Decrypt each key (current or fallback secret) and save it encrypted with the current one; report failures."""
        failed = 0
        for service in Service.objects.all():
            if not service.key:
                continue
            raw = service.key
            if raw.startswith("enc:"):
                try:
                    raw = decrypt_secret(raw[4:])
                except ValueError:
                    failed += 1
                    self.stderr.write(f"{service}: cannot decrypt, re-enter its key from the admin")
                    continue
            service.set_encrypted_key(raw)
            service.save(update_fields=["key"])
            self.stdout.write(f"{service}: re-encrypted")
        if failed:
            self.stderr.write(self.style.WARNING(f"{failed} service key(s) could not be decrypted"))
        else:
            self.stdout.write(self.style.SUCCESS("All service keys use the current SECRET_KEY"))
