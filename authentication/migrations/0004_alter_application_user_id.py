# Generated by Django 3.2.15 on 2022-12-03 17:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0003_alter_application_user_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='application_user',
            name='id',
            field=models.BigIntegerField(primary_key=True, serialize=False),
        ),
    ]
