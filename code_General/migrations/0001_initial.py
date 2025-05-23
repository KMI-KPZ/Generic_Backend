# Generated by Django 4.2.7 on 2023-11-29 09:59

import django.contrib.postgres.fields
from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Organization',
            fields=[
                ('subID', models.CharField(max_length=100, primary_key=True, serialize=False)),
                ('hashedID', models.CharField(max_length=513)),
                ('name', models.CharField(max_length=100)),
                ('details', models.JSONField()),
                ('supportedServices', django.contrib.postgres.fields.ArrayField(base_field=models.IntegerField(), size=None)),
                ('uri', models.CharField(max_length=200)),
                ('createdWhen', models.DateTimeField(auto_now_add=True)),
                ('updatedWhen', models.DateTimeField()),
                ('accessedWhen', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('subID', models.CharField(max_length=100, primary_key=True, serialize=False)),
                ('hashedID', models.CharField(max_length=513)),
                ('name', models.CharField(max_length=100)),
                ('details', models.JSONField()),
                ('createdWhen', models.DateTimeField(auto_now_add=True)),
                ('updatedWhen', models.DateTimeField(default=django.utils.timezone.now)),
                ('accessedWhen', models.DateTimeField(auto_now=True)),
                ('lastSeen', models.DateTimeField(default=django.utils.timezone.now)),
                ('organizations', models.ManyToManyField(to='code_General.organization')),
            ],
        ),
        migrations.AddField(
            model_name='organization',
            name='users',
            field=models.ManyToManyField(to='code_General.user'),
        ),
        migrations.AddIndex(
            model_name='user',
            index=models.Index(fields=['hashedID'], name='user_idx'),
        ),
        migrations.AddIndex(
            model_name='organization',
            index=models.Index(fields=['hashedID'], name='organization_idx'),
        ),
    ]
