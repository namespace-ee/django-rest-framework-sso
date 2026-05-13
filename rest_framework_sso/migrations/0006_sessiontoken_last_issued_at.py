from django.db import migrations, models


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
        migrations.RunSQL(
            sql="UPDATE rest_framework_sso_sessiontoken SET last_issued_at = created_at WHERE last_issued_at IS NULL",
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
