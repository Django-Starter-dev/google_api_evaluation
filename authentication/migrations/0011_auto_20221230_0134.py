# Generated by Django 3.2.15 on 2022-12-29 20:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0010_message_history'),
    ]

    operations = [
        migrations.AlterField(
            model_name='application_user_messages',
            name='from_address',
            field=models.CharField(max_length=1000),
        ),
        migrations.AlterField(
            model_name='application_user_messages',
            name='message_subject',
            field=models.CharField(max_length=1000),
        ),
        migrations.AlterField(
            model_name='application_user_messages',
            name='to_address',
            field=models.CharField(max_length=1000),
        ),
    ]
