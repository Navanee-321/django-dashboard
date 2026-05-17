from django.contrib import admin
from django.urls import path

from dashboard.views import (
    home,
    source_dashboard,
    docker_dashboard,
    repo_vulnerabilities,
    docker_image_vulnerabilities,
    aws_dashboard,
)

urlpatterns = [

    path('admin/', admin.site.urls),

    path('', home),

    path('sourcecode/', source_dashboard),

    path('docker/', docker_dashboard),

    path('repo/', repo_vulnerabilities),

    path('docker-image/', docker_image_vulnerabilities),

    path('aws/', aws_dashboard, name='aws'),

]
