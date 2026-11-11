from django.urls import path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"documents", views.DocumentViewSet)

urlpatterns = [
    path("login/", views.login_view),
]
