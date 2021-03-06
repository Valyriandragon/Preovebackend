# -*- coding: utf-8 -*-
# Generated by Django 1.9.7 on 2016-07-01 11:14
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('quickstart', '0004_remove_appuser_owner'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='appuser',
            options={'ordering': ('updated',)},
        ),
        migrations.RemoveField(
            model_name='appuser',
            name='created',
        ),
        migrations.AddField(
            model_name='appuser',
            name='owner',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, related_name='quickstart', to=settings.AUTH_USER_MODEL),
            preserve_default=False,
        ),
    ]
