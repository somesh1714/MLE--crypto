# Generated by Django 3.1.2 on 2021-03-21 12:19

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('users', '0003_delete_userinfo'),
    ]

    operations = [
        migrations.CreateModel(
            name='Member',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('f_name', models.CharField(max_length=30, verbose_name='First Name')),
                ('l_name', models.CharField(blank=True, max_length=30, verbose_name='Last Name')),
                ('userName', models.CharField(max_length=100, verbose_name='username')),
                ('email', models.EmailField(max_length=100, verbose_name='Email')),
                ('password', models.CharField(max_length=100, verbose_name='Password')),
            ],
        ),
        migrations.CreateModel(
            name='serverMessages',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('cipherText', models.BinaryField(verbose_name='Cipher Text')),
                ('tag', models.BinaryField(verbose_name='Tag')),
            ],
        ),
        migrations.CreateModel(
            name='Messages',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key', models.BinaryField(verbose_name='Key')),
                ('messageId', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='users.servermessages')),
                ('users', models.ManyToManyField(to='users.Member')),
            ],
        ),
    ]
