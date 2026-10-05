from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("rest_framework_sso", "0006_sessiontoken_last_issued_at"),
    ]

    operations = [
        migrations.AlterField(
            model_name="sessiontoken",
            name="last_issued_at",
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
    ]
