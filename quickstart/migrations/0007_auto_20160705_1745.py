# -*- coding: utf-8 -*-
# Generated by Django 1.9.6 on 2016-07-05 12:15
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('quickstart', '0006_auto_20160701_1645'),
    ]

    operations = [
        migrations.AlterField(
            model_name='appuser',
            name='owner',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='app_user', to=settings.AUTH_USER_MODEL),
        ),
    ]
