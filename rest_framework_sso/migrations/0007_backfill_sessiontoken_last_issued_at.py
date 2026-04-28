from django.db import migrations


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("rest_framework_sso", "0006_sessiontoken_last_issued_at"),
    ]

    operations = [
        migrations.RunSQL(
            sql="UPDATE rest_framework_sso_sessiontoken SET last_issued_at = created_at WHERE last_issued_at IS NULL",
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
