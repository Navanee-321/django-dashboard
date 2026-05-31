from django.contrib import admin
from django.urls import path

from dashboard.views import (
    home,
    source_dashboard,
    docker_dashboard,
    repo_dashboard,
    aws_dashboard,
    s3_findings,
    vpc_findings,
    cloudfront_findings,
    cloudfront_details,
)

urlpatterns = [
    path('admin/', admin.site.urls),

    path('', home),

    path('sourcecode/', source_dashboard),
    path('docker/', docker_dashboard),
    path('repos/', repo_dashboard),
    path('aws/', aws_dashboard, name='aws'),
    path('s3-findings/', s3_findings, name='s3-findings'),
    path('vpc-findings/', vpc_findings, name='vpc-findings'),
    path('cloudfront-findings/', cloudfront_findings, name='cloudfront-findings'),
    path('cloudfront-details/', cloudfront_details, name='cloudfront-details'),
]
