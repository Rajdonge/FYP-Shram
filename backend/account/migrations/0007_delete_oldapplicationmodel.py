# Generated by Django 5.0.4 on 2024-05-25 17:36

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0006_alter_oldapplicationmodel_user'),
    ]

    operations = [
        migrations.DeleteModel(
            name='OldApplicationModel',
        ),
    ]
