# Generated by Django 4.2.10 on 2024-02-21 09:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("rest_framework_sso", "0004_sessiontoken_created_by"),
    ]

    operations = [
        migrations.AddField(
            model_name="sessiontoken",
            name="version",
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
