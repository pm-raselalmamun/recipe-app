# <img width="30" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/apple.svg" />&nbsp; Recipe App Api

<a href="https://github.com/"><img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" /></a>
<a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-14354C?style=for-the-badge&logo=python&logoColor=white" /></a>
<a href="https://www.djangoproject.com/"><img src="https://img.shields.io/badge/Django-092E20?style=for-the-badge&logo=django&logoColor=white" /></a>
<a href="https://www.postgresql.org/"><img src="https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white" /></a>



To Create Recipe App API with Django & Test Project

> - <a href="#docker">1. Docker Environment Setup </a>

> - <a href="#user">2. Create Custom User Model with Test </a>

> - <a href="#travis">3. Travis CI & Flake8 Setup </a>

> - <a href="#postgres">4. Setup PostgreSQL Database </a>
## 1. Docker Environment Setup <a href="" name="docker"> - </a>

1. Create Files - `Dockerfile` & `requirements.txt` & `docker-compose.yml`

2. Create Folder - `app`

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/docker.svg" /> &nbsp;&nbsp;Dockerfile -

```docker
FROM python:3.9-alpine

ENV PYTHONUNBUFFERED 1

COPY ./requirements.txt /requirements.txt
RUN pip install -r requirements.txt

RUN mkdir /app
WORKDIR /app
COPY ./app /app

RUN adduser -D user
USER user
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/keycdn.svg" /> &nbsp;&nbsp; requirements.txt -

```py
Django>=3.1.4,<3.2.0
djangorestframework>=3.12.2,<3.13.0
flake8>=3.8.4,<3.9.0
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/docker.svg" /> &nbsp;&nbsp;docker-compose.yml -

```yml
version: '3'

services:
  app:
    build:
      context: .
    ports:
      - '8000:8000'
    volumes:
      - ./app:/app
    command: >
      sh -c 'python manage.py runserver 0.0.0.0:8000'
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp;Commands - `docker build .` & `docker-compose build`

## 2. Create Custom User Model with Test <a href="" name="user"> - </a>

1. Create a Django Project - `docker-compose run app sh -c 'django-admin startproject app .'`

2. Create a Django App - `docker-compose run app sh -c 'django-admin startapp core'`


<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > core > models.py -

```py
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_("Users must have an email address"))
        if not password:
            raise ValueError(_("Users must have a password"))

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(_('email address'), unique=True)
    name = models.CharField(_('name'), max_length=200)
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    last_login = models.DateTimeField(_('last login'), auto_now=True)
    is_active = models.BooleanField(_('active'), default=True)
    is_staff = models.BooleanField(_('staff status'), default=False)
    is_superuser = models.BooleanField(_('superuser status'), default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'

    def __str__(self):
        return self.email

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > core > tests > test_models.py

```py
from django.test import TestCase
from django.contrib.auth import get_user_model


def sample_user(email='test@gmail.com', password='testpass'):
    """Create a sample user"""
    return get_user_model().objects.create_user(email, password)


class UserAccountTests(TestCase):
    def test_new_superuser(self):
        db = get_user_model()
        super_user = db.objects.create_superuser('testuser@super.com', 'password')
        self.assertEqual(super_user.email, 'testuser@super.com')
        self.assertTrue(super_user.is_superuser)
        self.assertTrue(super_user.is_staff)
        self.assertTrue(super_user.is_active)

        with self.assertRaises(ValueError):
            db.objects.create_superuser(email='testuser@super.com', password='password', is_superuser=False)

        with self.assertRaises(ValueError):
            db.objects.create_superuser(email='testuser@super.com', password='password', is_staff=False)

        with self.assertRaises(ValueError):
            db.objects.create_superuser(email='', password='password', is_superuser=True)

    def test_new_user(self):
        db = get_user_model()
        user = db.objects.create_user('testuser@user.com', 'password')
        self.assertEqual(user.email, 'testuser@user.com')
        self.assertFalse(user.is_superuser)
        self.assertFalse(user.is_staff)
        self.assertTrue(user.is_active)

        with self.assertRaises(ValueError):
            db.objects.create_user(email='', password='password')

        with self.assertRaises(ValueError):
            db.objects.create_user(email='testuser@super.com', password='')

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > app > settings.py - `AUTH_USER_MODEL = 'core.User'`


<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > core > admin.py -

```py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    ordering = ('-date_joined',)
    list_display = ('email', 'name', 'is_active', 'is_staff')
    list_filter = ('email', 'name', 'is_staff', 'is_superuser', 'is_active')
    search_fields = ('email', 'name')
    fieldsets = (
        (None, {'fields': ('email', 'password',)}),
        (_('Personal info'), {'fields': ('name',)}),
        (_('Permissions'), {
         'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
         }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'name', 'password1', 'password2')}
         ),
    )
    readonly_fields = ('id', 'date_joined', 'last_login')
    filter_horizontal = ('groups', 'user_permissions',)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > core > tests > test_admin.py -

```py
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse


class AdminSiteTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin_user = get_user_model().objects.create_superuser(
            email='admin@test.com',
            password='password'
        )
        self.client.force_login(self.admin_user)
        self.user = get_user_model().objects.create_user(
            email='user@test.com',
            password='password',
            name='user name'
        )

    def test_user_listed(self):
        """Test that users are listed on user page"""
        url = reverse('admin:core_user_changelist')
        response = self.client.get(url)

        self.assertContains(response, self.user.name)
        self.assertContains(response, self.user.email)

    def test_user_change_page(self):
        """Test that user edit page works"""
        url = reverse('admin:core_user_change', args=[self.user.id])
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)

    def test_create_user_page(self):
        """Test that the create user page works"""
        url = reverse('admin:core_user_add')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp;Command - \
`docker-compose run app sh -c "python manage.py makemigrations"`\
`docker-compose run app sh -c "python manage.py migrate"`\
`docker-compose run app sh -c "python manage.py test && flake8"`

## 3. Travis CI & Flake8 Setup <a href="" name="travis"> - </a>

1. Enable github Repositorie at `https://travis-ci.org/` 
2. Create Files - `.travis.yml` & app > `.flake8`

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/travisci.svg" /> &nbsp;&nbsp; .travis.yml -

```yml
language: python
python:
  - '3.6'

services:
  - docker

before_script: pip install docker-compose

script:
  - docker-compose run app sh -c "python manage.py test && flake8"
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/snowflake.svg" /> &nbsp;&nbsp; app > .flake8 -

```yml
[flake8]
max-line-length = 119
exclude =
    migrations,
    __pycache__,
    manage.py,
    settings.py
```

## 4. Setup PostgreSQL Database <a href="" name="postgres"> - </a>

> - <a href="#configure">I. Configure PostgreSQL </a>

> - <a href="#custom">II. Create Custom Command for Database</a>

### I. Configure PostgreSQL <a href="" name="configure"> - </a>

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/docker.svg" /> &nbsp;&nbsp; Dockerfile -

```py
COPY ./requirements.txt /requirements.txt
RUN apk add --update --no-cache postgresql-client
RUN apk add --update --no-cache --virtual .tmp-build-deps gcc libc-dev linux-headers postgresql-dev
RUN pip install -r /requirements.txt

RUN rm -rf /var/cache/apk/* && \
 rm -rf /tmp/*

RUN apk update
RUN apk del .tmp-build-deps
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/postgresql.svg" /> &nbsp;&nbsp; docker-compose.yml -

```yml
    command: >
      sh -c "python manage.py wait_for_db && 
             python manage.py migrate && 
             python manage.py runserver 0.0.0.0:8000"
    environment:
      - DB_HOST=db
      - DB_NAME=app
      - DB_USER=postgres
      - DB_PASS=supersecretpassword
    depends_on:
      - db

  db:
    image: postgres:11-alpine
    environment:
      - POSTGRES_DB=app
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=supersecretpassword
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" /> &nbsp;&nbsp; app > app > settings.py -

```py
import os

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'HOST': os.environ.get('DB_HOST'),
        'NAME': os.environ.get('DB_NAME'),
        'USER': os.environ.get('DB_USER'),
        'PASSWORD': os.environ.get('DB_PASS'),
    }
}
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/keycdn.svg" /> &nbsp;&nbsp; requirements.txt - `psycopg2>=2.8.6,<2.9.0`

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp; Commands - `docker-compose build`
### II. Create Custom Command for Database with Test <a href="" name="custom"> - </a>

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" /> &nbsp;&nbsp; app > core > management > commands > wait_for_db.py -

```py
import time
from django.db import connections
from django.db.utils import OperationalError
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    """Django command to pause execution until database is available"""

    def handle(self, *args, **options):
        self.stdout.write('Waiting for database...')
        db_conn = None
        while not db_conn:
            try:
                db_conn = connections['default']
            except OperationalError:
                self.stdout.write('Database unavailable, waiting 1 second...')
                time.sleep(1)

        self.stdout.write(self.style.SUCCESS('Database available!'))

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" /> &nbsp;&nbsp; app > core > tests > test_commands.py - 

```py
from unittest.mock import patch
from django.core.management import call_command
from django.db.utils import OperationalError
from django.test import TestCase


class CommandTests(TestCase):

    def test_wait_for_db_ready(self):
        """Test waiting for db when db is available"""
        with patch('django.db.utils.ConnectionHandler.__getitem__') as gi:
            gi.return_value = True
            call_command('wait_for_db')
            self.assertEqual(gi.call_count, 1)

    @patch('time.sleep', return_value=True)
    def test_wait_for_db(self, ts):
        """Test waiting for db"""
        with patch('django.db.utils.ConnectionHandler.__getitem__') as gi:
            gi.side_effect = [OperationalError] * 5 + [True]
            call_command('wait_for_db')
            self.assertEqual(gi.call_count, 6)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp;  Command - \
`docker-compose run app sh -c "python manage.py makemigrations"`\
`docker-compose run app sh -c "python manage.py migrate"`\
`docker-compose run app sh -c "python manage.py test && flake8"`