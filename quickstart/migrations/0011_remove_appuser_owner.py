# -*- coding: utf-8 -*-
# Generated by Django 1.9.6 on 2016-07-07 16:14
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('quickstart', '0010_userinfo'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='appuser',
            name='owner',
        ),
    ]
