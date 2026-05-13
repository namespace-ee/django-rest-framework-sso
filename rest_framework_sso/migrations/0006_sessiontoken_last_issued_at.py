from django.db import migrations, models


def backfill_last_issued_at(apps, schema_editor):
    SessionToken = apps.get_model("rest_framework_sso", "SessionToken")
    SessionToken.objects.filter(last_issued_at__isnull=True).update(last_issued_at=models.F("created_at"))


class Migration(migrations.Migration):
    dependencies = [
        ("rest_framework_sso", "0005_sessiontoken_version"),
    ]

    operations = [
        migrations.AddField(
            model_name="sessiontoken",
            name="last_issued_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.RunPython(backfill_last_issued_at, migrations.RunPython.noop),
    ]
