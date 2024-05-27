# Generated by Django 5.0.4 on 2024-05-25 06:57

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0005_oldapplicationmodel_user'),
    ]

    operations = [
        migrations.AlterField(
            model_name='oldapplicationmodel',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='Old_Application', to=settings.AUTH_USER_MODEL),
        ),
    ]
