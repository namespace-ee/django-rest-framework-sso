import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory


@pytest.fixture
def user(db):
    return get_user_model().objects.create_user(username="alice", password="pw")


@pytest.fixture
def api_factory():
    return APIRequestFactory()
