from django.urls import path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"documents", views.DocumentViewSet)

urlpatterns = [
    path("login/", views.login_view),
]

# Ces deux enregistrements ne sont pas des ressources d'API.
admin.site.register(views.Document, views.DocumentAdmin)
register("signed-pickle", views.dumps, views.loads)
