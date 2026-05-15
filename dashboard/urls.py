from django.contrib import admin
from django.urls import path

from dashboard.views import (
    home,
    source_dashboard,
    docker_dashboard,
    repo_dashboard,
)

urlpatterns = [
    path('admin/', admin.site.urls),

    path('', home),

    path('sourcecode/', source_dashboard),
    path('docker/', docker_dashboard),
    path('repos/', repo_dashboard),
]
