# <img width="30" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/apple.svg" />&nbsp; Recipe App Api

[![Build Status](https://www.travis-ci.com/pm-raselalmamun/recipe-app.svg?branch=main)](https://www.travis-ci.com/pm-raselalmamun/recipe-app)

<a href="https://github.com/"><img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" /></a>
<a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-14354C?style=for-the-badge&logo=python&logoColor=white" /></a>
<a href="https://www.djangoproject.com/"><img src="https://img.shields.io/badge/Django-092E20?style=for-the-badge&logo=django&logoColor=white" /></a>
<a href="https://www.postgresql.org/"><img src="https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white" /></a>

To Create Recipe App API with Django & Test Project

> - <a href="#docker">1. Docker Environment Setup </a>

> - <a href="#user">2. Create Custom User Model with Test </a>

> - <a href="#travis">3. Travis CI & Flake8 Setup </a>

> - <a href="#postgres">4. Setup PostgreSQL Database </a>

> - <a href="#management">5. Create User Management Endpoints </a>

> - <a href="#tags">6. Create Tags Endpoints </a>

> - <a href="#ingredients">7. Create Ingredients Endpoints </a>

> - <a href="#recipe">8. Create Recipe Endpoints </a>

> - <a href="#image">9. Upload Image Endpoints </a>

> - <a href="#filter">10. Filter the Endpoints </a>

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

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp; Command - \
`docker-compose run app sh -c "python manage.py makemigrations"`\
`docker-compose run app sh -c "python manage.py migrate"`\
`docker-compose run app sh -c "python manage.py test && flake8"`

## 5. Create User Management Endpoints <a href="" name="management"> - </a>

> - <a href="#endpoints">I. Create User Endpoints </a>

> - <a href="#token">II. Create a New Token</a>

> - <a href="#user_management">III. User Management Endpoints</a>

### I. Create User Endpoints <a href="" name="endpoints"> - </a>

1. Create a User App - `docker-compose run app sh -c 'django-admin startapp user'`

2. Define App into settings.py - `INSTALLED_APPS = ['user.apps.UserConfig']`

3. Add URL into urls.py - `urlpatterns = [path('api/user/', include('user.urls'))]`

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > user > serializers.py -

```py
from django.contrib.auth import get_user_model
from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    """Serializer for the users object"""

    class Meta:
        model = get_user_model()
        fields = ('email', 'password', 'name')
        extra_kwargs = {'password': {'write_only': True, 'min_length': 5}}

    def create(self, validated_data):
        """Create a new user with encrypted password and return it"""
        return get_user_model().objects.create_user(**validated_data)
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > user > views.py -

```py
from .serializers import UserSerializer
from rest_framework import generics


class CreateUserView(generics.CreateAPIView):
    """Create a new user in the system"""
    serializer_class = UserSerializer

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > user > urls.py -

```py
from django.urls import path
from .views import CreateUserView

app_name = 'user'

urlpatterns = [
    path('create/', CreateUserView.as_view(), name='create'),
]

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > user > tests > test_user_api.py -

```py
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status

CREATE_USER_URL = reverse('user:create')


def create_user(**params):
    return get_user_model().objects.create_user(**params)


class PublicUserApiTests(TestCase):
    """Test the users API (public)"""

    def setUp(self):
        self.client = APIClient()

    def test_create_valid_user_success(self):
        """Test creating user with valid payload is successful"""
        payload = {
            'email': 'test@gmail.com',
            'password': 'testpass',
            'name': 'Test name'
        }
        response = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(**response.data)
        self.assertTrue(user.check_password(payload['password']))
        self.assertNotIn('password', response.data)

    def test_user_exists(self):
        """Test creatinga  user that already exists fails"""
        payload = {
            'email': 'test@gmail.com',
            'password': 'testpass',
            'name': 'Test',
        }
        create_user(**payload)
        response = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_too_short(self):
        """Test that the password must be more than 5 characters"""
        payload = {
            'email': 'test@gmail.com',
            'password': 'pw',
            'name': 'Test',
        }
        response = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        user_exists = get_user_model().objects.filter(
            email=payload['email']
        ).exists()
        self.assertFalse(user_exists)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp; Command - \
`docker-compose run app sh -c "python manage.py test && flake8"`

### II. Create a New Token <a href="" name="token"> - </a>

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > user > serializers.py -

```py
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import authenticate

class AuthTokenSerializer(serializers.Serializer):
    """Serializer for the user authentication object"""
    email = serializers.CharField()
    password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        """Validate and authenticate the user"""
        email = attrs.get('email')
        password = attrs.get('password')

        user = authenticate(
            request=self.context.get('request'),
            username=email,
            password=password
        )
        if not user:
            massage = _('Unable to authenticate with provided credentials')
            raise serializers.ValidationError(massage, code='authentication')

        attrs['user'] = user
        return attrs
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > user > views.py -

```py
from rest_framework.settings import api_settings
from rest_framework.authtoken.views import ObtainAuthToken
from .serializers import AuthTokenSerializer

class CreateTokenView(ObtainAuthToken):
    """Create a new auth token for user"""
    serializer_class = AuthTokenSerializer
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > user > urls.py -

```py
from .views import CreateTokenView

urlpatterns = [
    path('token/', CreateTokenView.as_view(), name='token'),
]
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > user > tests > test_user_api.py -

```py
TOKEN_URL = reverse('user:token')

class PublicUserApiTests(TestCase):
    def test_create_token_for_user(self):
        """Test that a token is created for the user"""
        payload = {
            'email': 'test@gmail.com',
            'password': 'testpass',
            'name': 'Test',
        }
        create_user(**payload)
        response = self.client.post(TOKEN_URL, payload)

        self.assertIn('token', response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_create_token_invalid_credentials(self):
        """Test that token is not created if invalid credentials are given"""
        create_user(email='test@gmil.com', password="testpass")
        payload = {
            'email': 'test@gmail.com',
            'password': 'wrong',
            'name': 'Test',
        }
        response = self.client.post(TOKEN_URL, payload)

        self.assertNotIn('token', response.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_token_no_user(self):
        """Test that token is not created if user doesn't exist"""
        payload = {
            'email': 'test@gmail.com',
            'password': 'testpass',
            'name': 'Test'
        }
        response = self.client.post(TOKEN_URL, payload)

        self.assertNotIn('token', response.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_token_missing_field(self):
        """Test that email and password are required"""
        response = self.client.post(TOKEN_URL, {'email': 'one', 'password': ''})
        self.assertNotIn('token', response.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp; Command - \
`docker-compose run app sh -c "python manage.py test && flake8"`

### III. User Management Endpoints <a href="" name="user_management"> - </a>

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > user > serializers.py -

```py
class UserSerializer(serializers.ModelSerializer):
    def update(self, instance, validated_data):
        """Update a user, setting the password correctly and return it"""
        password = validated_data.pop('password', None)
        user = super().update(instance, validated_data)

        if password:
            user.set_password(password)
            user.save()

        return user
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > user > views.py -

```py
from rest_framework import authentication, generics, permissions

class ManageUserView(generics.RetrieveUpdateAPIView):
    """Manage the authenticated user"""
    serializer_class = UserSerializer
    authentication_classes = (authentication.TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self):
        """Retrieve and return authentication user"""
        return self.request.user
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > user > urls.py -

```py
from .views import ManageUserView

urlpatterns = [
    path('me/', ManageUserView.as_view(), name='me'),
]
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > user > tests > test_user_api.py -

```py
ME_URL = reverse('user:me')

class PublicUserApiTests(TestCase):
    def test_retrieve_user_unauthorized(self):
        """Test that authentication is required for users"""
        response = self.client.get(ME_URL)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class PrivateUserApiTests(TestCase):
    """Test API requests that require authentication"""

    def setUp(self):
        self.user = create_user(
            email='test@gmail.com',
            password='testpass',
            name='name'
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_retrieve_profile_success(self):
        """Test retrieving profile for logged in user"""
        response = self.client.get(ME_URL)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {
            'name': self.user.name,
            'email': self.user.email
        })

    def test_post_me_not_allowed(self):
        """Test that POST is not allowed on the me url"""
        response = self.client.post(ME_URL, {})

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_update_user_profile(self):
        """Test updating the user profile for authenticated user"""
        payload = {'name': 'new name', 'password': 'newpassword'}

        response = self.client.patch(ME_URL, payload)

        self.user.refresh_from_db()
        self.assertEqual(self.user.name, payload['name'])
        self.assertTrue(self.user.check_password(payload['password']))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp; Command - \
`docker-compose run app sh -c "python manage.py test && flake8"`

## 6. Create Tags Endpoints <a href="" name="tags"> - </a>

> - <a href="#tag_model">I. Create Tag Model </a>

> - <a href="#tag_endpoints">II. Create Tag Endpoints </a>

### I. Create Tag Model <a href="" name="tag_model"> - </a>

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > core > models.py -

```py
from django.conf import settings

class Tag(models.Model):
    """Tag to be used for a recipe"""
    name = models.CharField(max_length=255)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    def __str__(self):
        return self.name
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > core > admin.py -

```py
from .models import Tag

class TagAdmin(admin.ModelAdmin):
    list_display = ['__str__', 'user']

    class Meta:
        model = Tag

admin.site.register(Tag, TagAdmin)
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > core > tests > test_models.py

```py
from core.models import Tag

def sample_user(email='test@gmail.com', password='testpass'):
    """Create a sample user"""
    return get_user_model().objects.create_user(email, password)


class UserAccountTests(TestCase):
    def test_tag_str(self):
        """Test the tag string representation"""
        tag = Tag.objects.create(
            user=sample_user(),
            name='Vegan'
        )

        self.assertEqual(str(tag), tag.name)
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp;Command - \
`docker-compose run app sh -c "python manage.py makemigrations"`\
`docker-compose run app sh -c "python manage.py migrate"`\
`docker-compose run app sh -c "python manage.py test && flake8"`

### II. Create Tag Endpoints <a href="" name="tag_endpoints"> - </a>

1. Create a User App - `docker-compose run app sh -c 'django-admin startapp recipe'`

2. Define App into settings.py - `INSTALLED_APPS = ['recipe.apps.RecipeConfig']`

3. Add URL into urls.py - `urlpatterns = [path('api/recipe/', include('recipe.urls'))]`

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > serializers.py -

```py
from core.models import Tag
from rest_framework import serializers


class TagSerializer(serializers.ModelSerializer):
    """Serializer for tag objects"""

    class Meta:
        model = Tag
        fields = ('id', 'name')
        read_only_fields = ('id',)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > views.py -

```py
from core.models import Tag
from .serializers import TagSerializer
from rest_framework import viewsets, mixins
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication


class TagViewSet(viewsets.GenericViewSet, mixins.ListModelMixin, mixins.CreateModelMixin):
    """Manage tags in the database"""
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    queryset = Tag.objects.all()
    serializer_class = TagSerializer

    def get_queryset(self):
        """Return objects for the current authenticated user only"""
        queryset = self.queryset
        return queryset.filter(user=self.request.user).order_by('-name')

    def perform_create(self, serializer):
        """Create a new object"""
        serializer.save(user=self.request.user)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > urls.py -

```py
from .views import TagViewSet
from django.urls import path, include
from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register('tags', TagViewSet)


app_name = 'recipe'

urlpatterns = [
    path('', include(router.urls))
]

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > tests > test_tags.py -

```py
from core.models import Tag
from django.urls import reverse
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient
from recipe.serializers import TagSerializer
from django.contrib.auth import get_user_model


TAGS_URL = reverse('recipe:tag-list')


class PublicTagsApiTests(TestCase):
    """Test thje publicly available tags API"""

    def setUp(self):
        self.client = APIClient()

    def test_login_required(self):
        """Test that login is required for retrieving tags"""
        response = self.client.get(TAGS_URL)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class PrivateTagsApiTests(TestCase):
    """Test the authorized user tags API"""

    def setUp(self):
        self.user = get_user_model().objects.create_user(
            'test@gmail.com',
            'password'
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_retrieve_tags(self):
        """Test retrieving tags"""
        Tag.objects.create(user=self.user, name='Vegan')
        Tag.objects.create(user=self.user, name='Dessert')

        response = self.client.get(TAGS_URL)

        tags = Tag.objects.all().order_by('-name')
        serializer = TagSerializer(tags, many=True)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, serializer.data)

    def test_tags_limited_to_user(self):
        """Test that tags returned are for the authenticated user"""
        user2 = get_user_model().objects.create_user(
            'other@gmail.com',
            'testpass'
        )
        Tag.objects.create(user=user2, name='Fruity')
        tag = Tag.objects.create(user=self.user, name='Comfort Food')

        response = self.client.get(TAGS_URL)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], tag.name)

    def test_create_tag_successful(self):
        """Test creating a new tag"""
        payload = {'name': 'Test tag'}
        self.client.post(TAGS_URL, payload)

        exists = Tag.objects.filter(
            user=self.user,
            name=payload['name']
        ).exists()
        self.assertTrue(exists)

    def test_create_tag_invalid(self):
        """Test creating a new tag with invalid payload"""
        payload = {'name': ''}
        res = self.client.post(TAGS_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp;Command - \
`docker-compose run app sh -c "python manage.py test && flake8"`

## 7. Create Ingredients Endpoints <a href="" name="ingredients"> - </a>

> - <a href="#ingredients_model">I. Create Ingredients Model </a>

> - <a href="#ingredients_endpoints">II. Create Ingredients Endpoints </a>

### I. Create Ingredients Model <a href="" name="ingredients_model"> - </a>

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > core > models.py -

```py
from django.conf import settings

class Ingredient(models.Model):
    """Ingredient to be used in a recipe"""
    name = models.CharField(max_length=255)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    def __str__(self):
        return self.name
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > core > admin.py -

```py
from .models import Ingredient

class IngredientAdmin(admin.ModelAdmin):
    list_display = ['__str__', 'user']

    class Meta:
        model = Ingredient


admin.site.register(Ingredient, IngredientAdmin)
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > core > tests > test_models.py

```py
from core.models import Ingredient

def sample_user(email='test@gmail.com', password='testpass'):
    """Create a sample user"""
    return get_user_model().objects.create_user(email, password)


class UserAccountTests(TestCase):
    def test_ingredient_str(self):
        """Test the ingredient string respresentation"""
        ingredient = Ingredient.objects.create(
            user=sample_user(),
            name='Cucumber'
        )

        self.assertEqual(str(ingredient), ingredient.name)
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp;Command - \
`docker-compose run app sh -c "python manage.py makemigrations"`\
`docker-compose run app sh -c "python manage.py migrate"`\
`docker-compose run app sh -c "python manage.py test && flake8"`

### II. Create Ingredients Endpoints <a href="" name="ingredients_endpoints"> - </a>

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > serializers.py -

```py
from core.models import Ingredient


class IngredientSerializer(serializers.ModelSerializer):
    """Serializer for ingredient objects"""

    class Meta:
        model = Ingredient
        fields = ('id', 'name')
        read_only_fields = ('id',)

```

#### Create Custom ViewSet Class -

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > views.py -

```py
from core.models import Tag, Ingredient
from rest_framework import viewsets, mixins
from rest_framework.permissions import IsAuthenticated
from .serializers import TagSerializer, IngredientSerializer
from rest_framework.authentication import TokenAuthentication


class BaseRecipeAttrViewSet(viewsets.GenericViewSet, mixins.ListModelMixin, mixins.CreateModelMixin):
    """Base viewset for user owned recipe attributes"""
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        """Return objects for the current authenticated user only"""
        queryset = self.queryset
        return queryset.filter(user=self.request.user).order_by('-name')

    def perform_create(self, serializer):
        """Create a new object"""
        serializer.save(user=self.request.user)


class TagViewSet(BaseRecipeAttrViewSet):
    """Manage tags in the database"""
    queryset = Tag.objects.all()
    serializer_class = TagSerializer


class IngredientViewSet(BaseRecipeAttrViewSet):
    """Manage ingredients in the database"""
    queryset = Ingredient.objects.all()
    serializer_class = IngredientSerializer


```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > urls.py -

```py
from .views import IngredientViewSet

router.register('ingredients', IngredientViewSet)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > tests > test_ingredients.py -

```py
from django.urls import reverse
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient
from core.models import Ingredient
from django.contrib.auth import get_user_model
from recipe.serializers import IngredientSerializer


INGREDIENTS_URL = reverse('recipe:ingredient-list')


class PublicIngredientsApiTests(TestCase):
    """Test the publicly available ingredients API"""

    def setUp(self):
        self.client = APIClient()

    def test_login_required(self):
        """Test that login is required to access the endpoint"""
        res = self.client.get(INGREDIENTS_URL)

        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)


class PrivateIngredientsApiTests(TestCase):
    """Test the private ingredients API"""

    def setUp(self):
        self.client = APIClient()
        self.user = get_user_model().objects.create_user(
            'test@user.com',
            'testpass'
        )
        self.client.force_authenticate(self.user)

    def test_retrieve_ingredient_list(self):
        """Test retrieving a list of ingredients"""
        Ingredient.objects.create(user=self.user, name='Kale')
        Ingredient.objects.create(user=self.user, name='Salt')

        res = self.client.get(INGREDIENTS_URL)

        ingredients = Ingredient.objects.all().order_by('-name')
        serializer = IngredientSerializer(ingredients, many=True)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data, serializer.data)

    def test_ingredients_limited_to_user(self):
        """Test that ingredients for the authenticated user are returend"""
        user2 = get_user_model().objects.create_user(
            'other@user.com',
            'testpass'
        )
        Ingredient.objects.create(user=user2, name='Vinegar')
        ingredient = Ingredient.objects.create(user=self.user, name='Tumeric')

        res = self.client.get(INGREDIENTS_URL)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(len(res.data), 1)
        self.assertEqual(res.data[0]['name'], ingredient.name)

    def test_create_ingredient_successful(self):
        """Test create a new ingredient"""
        payload = {'name': 'Cabbage'}
        self.client.post(INGREDIENTS_URL, payload)

        exists = Ingredient.objects.filter(
            user=self.user,
            name=payload['name'],
        ).exists()
        self.assertTrue(exists)

    def test_create_ingredient_invalid(self):
        """Test creating invalid ingredient fails"""
        payload = {'name': ''}
        res = self.client.post(INGREDIENTS_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp;Command - \
`docker-compose run app sh -c "python manage.py test && flake8"`



## 8. Create Recipe Endpoints <a href="" name="recipe"> - </a>

> - <a href="#recipe_model">I. Create Recipe Model </a>

> - <a href="#recipe_endpoints">II. Create Recipe Endpoints </a>

> - <a href="#details_endpoints">III. Create Recipe Details Endpoints </a>

> - <a href="#create_recipe">IV. Send Post Request for Create Recipe </a>

> - <a href="#update_recipe">V. Send Post Request for Update Recipe </a>

### I. Create Recipe Model <a href="" name="recipe_model"> - </a>

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > core > models.py -

```py
class Recipe(models.Model):
    """Recipe object"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    time_minutes = models.IntegerField()
    price = models.DecimalField(max_digits=5, decimal_places=2)
    link = models.CharField(max_length=255, blank=True)
    ingredients = models.ManyToManyField('Ingredient')
    tags = models.ManyToManyField('Tag')

    def __str__(self):
        return self.title

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > core > admin.py -

```py
from .models import Recipe

class RecipeAdmin(admin.ModelAdmin):
    list_display = ['__str__', 'price', 'time_minutes']

    class Meta:
        model = Recipe


admin.site.register(Recipe, RecipeAdmin)
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > core > tests > test_models.py

```py
from core.models import Recipe


class UserAccountTests(TestCase):
    def test_recipe_str(self):
        """Test the recipe string representation"""
        recipe = Recipe.objects.create(
            user=sample_user(),
            title='Steak and mushroom sauce',
            time_minutes=5,
            price=5.00
        )

        self.assertEqual(str(recipe), recipe.title)
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp;Command - \
`docker-compose run app sh -c "python manage.py makemigrations"`\
`docker-compose run app sh -c "python manage.py migrate"`\
`docker-compose run app sh -c "python manage.py test && flake8"`


### II. Create Recipe Endpoints <a href="" name="recipe_endpoints"> - </a>

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > serializers.py -

```py
from core.models import Ingredient, Tag, Recipe

class RecipeSerializer(serializers.ModelSerializer):
    """Serialize a recipe"""
    ingredients = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Ingredient.objects.all()
    )
    tags = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Tag.objects.all()
    )

    class Meta:
        model = Recipe
        fields = (
            'id', 'title', 'ingredients', 'tags', 'time_minutes',
            'price', 'link'
        )
        read_only_fields = ('id',)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > views.py -

```py
from core.models import Recipe
from .serializers import RecipeSerializer


class RecipeViewSet(viewsets.ModelViewSet):
    """Manage recipes in the database"""
    serializer_class = RecipeSerializer
    queryset = Recipe.objects.all()
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        """Retrieve the recipes for the authenticated user"""
        queryset = self.queryset
        return queryset.filter(user=self.request.user)


```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > urls.py -

```py
from .views import RecipeViewSet

router.register('recipes', RecipeViewSet)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > tests > test_recipe.py -

```py
from django.urls import reverse
from django.test import TestCase
from rest_framework import status
from core.models import Recipe
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from recipe.serializers import RecipeSerializer


RECIPES_URL = reverse('recipe:recipe-list')


def sample_recipe(user, **params):
    """Create and return a sample recipe"""
    defaults = {
        'title': 'Sample recipe',
        'time_minutes': 10,
        'price': 5.00
    }
    defaults.update(params)

    return Recipe.objects.create(user=user, **defaults)


class PublicRecipeApiTests(TestCase):
    """Test unauthenticated recipe API access"""

    def setUp(self):
        self.client = APIClient()

    def test_auth_required(self):
        """Test that authentication is required"""
        response = self.client.get(RECIPES_URL)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class PrivateRecipeApiTests(TestCase):
    """Test unauthenticated recipe API access"""

    def setUp(self):
        self.client = APIClient()
        self.user = get_user_model().objects.create_user(
            'test@user.com',
            'testpass'
        )
        self.client.force_authenticate(self.user)

    def test_retrieve_recipes(self):
        """Test retrieving a list of recipes"""
        sample_recipe(user=self.user)
        sample_recipe(user=self.user)

        response = self.client.get(RECIPES_URL)

        recipes = Recipe.objects.all().order_by('-id')
        serializer = RecipeSerializer(recipes, many=True)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, serializer.data)

    def test_recipes_limited_to_user(self):
        """Test retrieving recipes for user"""
        user2 = get_user_model().objects.create_user(
            'other@user.com',
            'password123'
        )
        sample_recipe(user=user2)
        sample_recipe(user=self.user)

        response = self.client.get(RECIPES_URL)

        recipes = Recipe.objects.filter(user=self.user)
        serializer = RecipeSerializer(recipes, many=True)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data, serializer.data)


```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp;Command - \
`docker-compose run app sh -c "python manage.py test && flake8"`


### III. Create Recipe Details Endpoints <a href="" name="details_endpoints"> - </a>

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > serializers.py -

```py
class RecipeDetailSerializer(RecipeSerializer):
    """Serialize a recipe detail"""
    ingredients = IngredientSerializer(many=True, read_only=True)
    tags = TagSerializer(many=True, read_only=True)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > views.py -

```py
from .serializers import RecipeDetailSerializer

class RecipeViewSet(viewsets.ModelViewSet):

    def get_serializer_class(self):
        """Return appropriate serializer class"""
        if self.action == 'retrieve':
            return RecipeDetailSerializer

        return self.serializer_class

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > tests > test_recipe.py -

```py
from recipe.serializers import RecipeDetailSerializer

def detail_url(recipe_id):
    """Return recipe detail URL"""
    return reverse('recipe:recipe-detail', args=[recipe_id])


def sample_tag(user, name='Main course'):
    """Create and return a sample tag"""
    return Tag.objects.create(user=user, name=name)


def sample_ingredient(user, name='Cinnamon'):
    """Create and return a sample ingredient"""
    return Ingredient.objects.create(user=user, name=name)


class PrivateRecipeApiTests(TestCase):

    def test_view_recipe_detail(self):
        """Test viewing a recipe detail"""
        recipe = sample_recipe(user=self.user)
        recipe.tags.add(sample_tag(user=self.user))
        recipe.ingredients.add(sample_ingredient(user=self.user))

        url = detail_url(recipe.id)
        response = self.client.get(url)

        serializer = RecipeDetailSerializer(recipe)
        self.assertEqual(response.data, serializer.data)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp;Command - \
`docker-compose run app sh -c "python manage.py test && flake8"`

### IV. Send Post Request for Create Recipe <a href="" name="create_recipe"> - </a>

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > views.py -

```py
class RecipeViewSet(viewsets.ModelViewSet):
    def perform_create(self, serializer):
        """Create a new recipe"""
        serializer.save(user=self.request.user)
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > tests > test_recipe.py -

```py
class PrivateRecipeApiTests(TestCase):
    def test_create_basic_recipe(self):
        """Test creating recipe"""
        payload = {
            'title': 'Chocolate cheesecake',
            'time_minutes': 30,
            'price': 5.00
        }
        response = self.client.post(RECIPES_URL, payload)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        recipe = Recipe.objects.get(id=response.data['id'])
        for key in payload.keys():
            self.assertEqual(payload[key], getattr(recipe, key))

    def test_create_recipe_with_tags(self):
        """Test creating a recipe with tags"""
        tag1 = sample_tag(user=self.user, name='Vegan')
        tag2 = sample_tag(user=self.user, name='Dessert')
        payload = {
            'title': 'Avocado lime cheesecake',
            'tags': [tag1.id, tag2.id],
            'time_minutes': 60,
            'price': 20.00
        }
        response = self.client.post(RECIPES_URL, payload)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        recipe = Recipe.objects.get(id=response.data['id'])
        tags = recipe.tags.all()
        self.assertEqual(tags.count(), 2)
        self.assertIn(tag1, tags)
        self.assertIn(tag2, tags)

    def test_create_recipe_with_ingredients(self):
        """Test creating recipe with ingredients"""
        ingredient1 = sample_ingredient(user=self.user, name='Prawns')
        ingredient2 = sample_ingredient(user=self.user, name='Ginger')
        payload = {
            'title': 'Thai prawn red curry',
            'ingredients': [ingredient1.id, ingredient2.id],
            'time_minutes': 20,
            'price': 7.00
        }
        response = self.client.post(RECIPES_URL, payload)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        recipe = Recipe.objects.get(id=response.data['id'])
        ingredients = recipe.ingredients.all()
        self.assertEqual(ingredients.count(), 2)
        self.assertIn(ingredient1, ingredients)
        self.assertIn(ingredient2, ingredients)

```
<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp;Command - \
`docker-compose run app sh -c "python manage.py test && flake8"`


### V. Send Post Request for Update Recipe <a href="" name="update_recipe"> - </a>

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > tests > test_recipe.py -

```py
class PrivateRecipeApiTests(TestCase):
    def test_partial_update_recipe(self):
        """Test updating a recipe with patch"""
        recipe = sample_recipe(user=self.user)
        recipe.tags.add(sample_tag(user=self.user))
        new_tag = sample_tag(user=self.user, name='Curry')

        payload = {'title': 'Chicken tikka', 'tags': [new_tag.id]}
        url = detail_url(recipe.id)
        self.client.patch(url, payload)

        recipe.refresh_from_db()
        self.assertEqual(recipe.title, payload['title'])
        tags = recipe.tags.all()
        self.assertEqual(len(tags), 1)
        self.assertIn(new_tag, tags)

    def test_full_update_recipe(self):
        """Test updating a recipe with put"""
        recipe = sample_recipe(user=self.user)
        recipe.tags.add(sample_tag(user=self.user))
        payload = {
            'title': 'Spaghetti carbonara',
            'time_minutes': 25,
            'price': 5.00
        }
        url = detail_url(recipe.id)
        self.client.put(url, payload)

        recipe.refresh_from_db()
        self.assertEqual(recipe.title, payload['title'])
        self.assertEqual(recipe.time_minutes, payload['time_minutes'])
        self.assertEqual(recipe.price, payload['price'])
        tags = recipe.tags.all()
        self.assertEqual(len(tags), 0)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp;Command - \
`docker-compose run app sh -c "python manage.py test && flake8"`


## 9. Upload Image Endpoints <a href="" name="image"> - </a>

> - <a href="#image_docker">I. Setup Docker & Settings File </a>

> - <a href="#image_models">II. Modify the Models </a>

> - <a href="#image_endpoints">III. Create Image Endpoints </a>


### I. Setup Docker File <a href="" name="image_docker"> - </a>

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/docker.svg" /> &nbsp;&nbsp;Dockerfile -

```yml
RUN apk add --update --no-cache postgresql-client jpeg-dev
RUN apk add --update --no-cache --virtual .tmp-build-deps gcc libc-dev linux-headers postgresql-dev musl-dev zlib zlib-dev

RUN mkdir -p /vol/web/media
RUN mkdir -p /vol/web/static
RUN adduser -D user
RUN chown -R user:user /vol/
RUN chmod -R 755 /vol/web
USER user
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/keycdn.svg" /> &nbsp;&nbsp; requirements.txt -

```py
Pillow>=8.0.1,<8.1.0
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" /> &nbsp;&nbsp; app > app > settings.py -

```py
MEDIA_URL = '/media/'

MEDIA_ROOT = '/vol/web/media'

STATIC_ROOT = '/vol/web/static'
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" /> &nbsp;&nbsp; app > app > urls.py -

```py
from django.conf.urls.static import static
from django.conf import settings

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

```

### II. Modify the Models <a href="" name="image_models"> - </a>

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > core > models.py -

```py
import os
import uuid

def recipe_image_file_path(instance, filename):
    """Generate file path for new recipe image"""
    ext = filename.split('.')[-1]
    filename = f'{uuid.uuid4()}.{ext}'

    return os.path.join('uploads/recipe/', filename)


class Recipe(models.Model):
    image = models.ImageField(null=True, upload_to=recipe_image_file_path)
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > core > tests > test_models.py

```py
from unittest.mock import patch
from core.models import recipe_image_file_path

class UserAccountTests(TestCase):

    @patch('uuid.uuid4')
    def test_recipe_file_name_uuid(self, mock_uuid):
        """Test that image is saved in the correct location"""
        uuid = 'test-uuid'
        mock_uuid.return_value = uuid
        file_path = recipe_image_file_path(None, 'myimage.jpg')

        exp_path = f'uploads/recipe/{uuid}.jpg'
        self.assertEqual(file_path, exp_path)
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp;Command - \
`docker-compose run app sh -c "python manage.py makemigrations"`\
`docker-compose run app sh -c "python manage.py migrate"`\
`docker-compose run app sh -c "python manage.py test && flake8"`

### III. Create Image Endpoints <a href="" name="image_endpoints"> - </a>

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > serializers.py -

```py
class RecipeImageSerializer(serializers.ModelSerializer):
    """Serializer for uploading images to recipes"""

    class Meta:
        model = Recipe
        fields = ('id', 'image')
        read_only_fields = ('id',)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > views.py -

```py
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework import status
from .serializers import RecipeImageSerializer

class RecipeViewSet(viewsets.ModelViewSet):
    def get_serializer_class(self):
        """Return appropriate serializer class"""
        if self.action == 'retrieve':
            return RecipeDetailSerializer
        elif self.action == 'upload_image':
            return RecipeImageSerializer

        return self.serializer_class

    @action(methods=['POST'], detail=True, url_path='upload-image')
    def upload_image(self, request, pk=None):
        """Upload an image to a recipe"""
        recipe = self.get_object()
        serializer = self.get_serializer(recipe, data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > tests > test_recipe.py -

```py
import os
import tempfile
from PIL import Image

def image_upload_url(recipe_id):
    """Return URL for recipe image upload"""
    return reverse('recipe:recipe-upload-image', args=[recipe_id])

class RecipeImageUploadTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.user = get_user_model().objects.create_user(
            'user@user.com',
            'testpass'
        )
        self.client.force_authenticate(self.user)
        self.recipe = sample_recipe(user=self.user)

    def tearDown(self):
        self.recipe.image.delete()

    def test_upload_image_to_recipe(self):
        """Test uploading an image to recipe"""
        url = image_upload_url(self.recipe.id)
        with tempfile.NamedTemporaryFile(suffix='.jpg') as ntf:
            img = Image.new('RGB', (10, 10))
            img.save(ntf, format='JPEG')
            ntf.seek(0)
            response = self.client.post(url, {'image': ntf}, format='multipart')

        self.recipe.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('image', response.data)
        self.assertTrue(os.path.exists(self.recipe.image.path))

    def test_upload_image_bad_request(self):
        """Test uploading an invalid image"""
        url = image_upload_url(self.recipe.id)
        response = self.client.post(url, {'image': 'notimage'}, format='multipart')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/powershell.svg" /> &nbsp;&nbsp;Command - \
`docker-compose run app sh -c "python manage.py test && flake8"`


## 10. Filter the Endpoints <a href="" name="filter"> - </a>

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > views.py -

```py
class BaseRecipeAttrViewSet(viewsets.GenericViewSet, mixins.ListModelMixin, mixins.CreateModelMixin):
    def get_queryset(self):
        """Return objects for the current authenticated user only"""
        assigned_only = bool(
            int(self.request.query_params.get('assigned_only', 0))
        )
        queryset = self.queryset
        if assigned_only:
            queryset = queryset.filter(recipe__isnull=False)

        return queryset.filter(user=self.request.user).order_by('-name').distinct()


class RecipeViewSet(viewsets.ModelViewSet):
    def _params_to_ints(self, qs):
        """Convert a list of string IDs to a list of integers"""
        return [int(str_id) for str_id in qs.split(',')]

    def get_queryset(self):
        """Retrieve the recipes for the authenticated user"""
        tags = self.request.query_params.get('tags')
        ingredients = self.request.query_params.get('ingredients')
        queryset = self.queryset
        if tags:
            tag_ids = self._params_to_ints(tags)
            queryset = queryset.filter(tags__id__in=tag_ids)
        if ingredients:
            ingredient_ids = self._params_to_ints(ingredients)
            queryset = queryset.filter(ingredients__id__in=ingredient_ids)

        return queryset.filter(user=self.request.user)
```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > tests > test_recipe.py -

```py
class RecipeImageUploadTests(TestCase):
    def test_filter_recipes_by_tags(self):
        """Test returning recipes with specific tags"""
        recipe1 = sample_recipe(user=self.user, title='Thai vegetable curry')
        recipe2 = sample_recipe(user=self.user, title='Aubergine with tahini')
        tag1 = sample_tag(user=self.user, name='Vegan')
        tag2 = sample_tag(user=self.user, name='Vegetarian')
        recipe1.tags.add(tag1)
        recipe2.tags.add(tag2)
        recipe3 = sample_recipe(user=self.user, title='Fish and chips')

        response = self.client.get(
            RECIPES_URL,
            {'tags': f'{tag1.id},{tag2.id}'}
        )

        serializer1 = RecipeSerializer(recipe1)
        serializer2 = RecipeSerializer(recipe2)
        serializer3 = RecipeSerializer(recipe3)
        self.assertIn(serializer1.data, response.data)
        self.assertIn(serializer2.data, response.data)
        self.assertNotIn(serializer3.data, response.data)

    def test_filter_recipes_by_ingredients(self):
        """Test returning recipes with specific ingredients"""
        recipe1 = sample_recipe(user=self.user, title='Posh beans on toast')
        recipe2 = sample_recipe(user=self.user, title='Chicken cacciatore')
        ingredient1 = sample_ingredient(user=self.user, name='Feta cheese')
        ingredient2 = sample_ingredient(user=self.user, name='Chicken')
        recipe1.ingredients.add(ingredient1)
        recipe2.ingredients.add(ingredient2)
        recipe3 = sample_recipe(user=self.user, title='Steak and mushrooms')

        response = self.client.get(
            RECIPES_URL,
            {'ingredients': f'{ingredient1.id},{ingredient2.id}'}
        )

        serializer1 = RecipeSerializer(recipe1)
        serializer2 = RecipeSerializer(recipe2)
        serializer3 = RecipeSerializer(recipe3)
        self.assertIn(serializer1.data, response.data)
        self.assertIn(serializer2.data, response.data)
        self.assertNotIn(serializer3.data, response.data)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > tests > test_tags.py -

```py
from core.models import Tag, Recipe

class PrivateTagsApiTests(TestCase):
    def test_retrieve_tags_assigned_to_recipes(self):
        """Test filtering tags by those assigned to recipes"""
        tag1 = Tag.objects.create(user=self.user, name='Breakfast')
        tag2 = Tag.objects.create(user=self.user, name='Lunch')
        recipe = Recipe.objects.create(
            title='Coriander eggs on toast',
            time_minutes=10,
            price=5.00,
            user=self.user
        )
        recipe.tags.add(tag1)

        response = self.client.get(TAGS_URL, {'assigned_only': 1})

        serializer1 = TagSerializer(tag1)
        serializer2 = TagSerializer(tag2)
        self.assertIn(serializer1.data, response.data)
        self.assertNotIn(serializer2.data, response.data)

    def test_retrieve_tags_assigned_unique(self):
        """Test filtering tags by assigned returns unique items"""
        tag = Tag.objects.create(user=self.user, name='Breakfast')
        Tag.objects.create(user=self.user, name='Lunch')
        recipe1 = Recipe.objects.create(
            title='Pancakes',
            time_minutes=5,
            price=3.00,
            user=self.user
        )
        recipe1.tags.add(tag)
        recipe2 = Recipe.objects.create(
            title='Porridge',
            time_minutes=3,
            price=2.00,
            user=self.user
        )
        recipe2.tags.add(tag)

        response = self.client.get(TAGS_URL, {'assigned_only': 1})

        self.assertEqual(len(response.data), 1)

```

<img width="18" src="https://cdn.jsdelivr.net/npm/simple-icons@v4/icons/python.svg" />&nbsp;&nbsp; app > recipe > tests > test_ingredients.py -

```py
from core.models import Ingredient, Recipe

class PrivateIngredientsApiTests(TestCase):
    def test_retrieve_ingredients_assigned_to_recipes(self):
        """Test filtering ingredients by those assigned to recipes"""
        ingredient1 = Ingredient.objects.create(
            user=self.user, name='Apples'
        )
        ingredient2 = Ingredient.objects.create(
            user=self.user, name='Turkey'
        )
        recipe = Recipe.objects.create(
            title='Apple crumble',
            time_minutes=5,
            price=10,
            user=self.user
        )
        recipe.ingredients.add(ingredient1)

        res = self.client.get(INGREDIENTS_URL, {'assigned_only': 1})

        serializer1 = IngredientSerializer(ingredient1)
        serializer2 = IngredientSerializer(ingredient2)
        self.assertIn(serializer1.data, res.data)
        self.assertNotIn(serializer2.data, res.data)

    def test_retrieve_ingredients_assigned_unique(self):
        """Test filtering ingredients by assigned returns unique items"""
        ingredient = Ingredient.objects.create(user=self.user, name='Eggs')
        Ingredient.objects.create(user=self.user, name='Cheese')
        recipe1 = Recipe.objects.create(
            title='Eggs benedict',
            time_minutes=30,
            price=12.00,
            user=self.user
        )
        recipe1.ingredients.add(ingredient)
        recipe2 = Recipe.objects.create(
            title='Coriander eggs on toast',
            time_minutes=20,
            price=5.00,
            user=self.user
        )
        recipe2.ingredients.add(ingredient)

        res = self.client.get(INGREDIENTS_URL, {'assigned_only': 1})

        self.assertEqual(len(res.data), 1)

```