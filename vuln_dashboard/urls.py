from django.contrib import admin
from django.urls import path

from dashboard.views import (
    home,
    source_dashboard,
    docker_dashboard,
    repo_vulnerabilities,
    docker_image_vulnerabilities,
    aws_home,
    aws_dashboard,
    ec2_dashboard,
    s3_dashboard,
    ai_assistant,
    ec2_findings,
    iam_findings,
    s3_findings,
    vpc_findings,
    iam_users_no_mfa,
    iam_details,
    ec2_details,
    s3_details,
    vpc_details,
    cloudfront_findings,
    cloudfront_details
)

urlpatterns = [

    path('admin/', admin.site.urls),

    path('', home),

    path('sourcecode/', source_dashboard),

    path('docker/', docker_dashboard),

    path('repo/', repo_vulnerabilities),

    path('docker-image/', docker_image_vulnerabilities),

    path('aws/', aws_home, name='aws-home'),

    path('aws/inspector/', aws_dashboard, name='aws-inspector'),

    path('ec2/', ec2_dashboard, name='ec2'),

    path('s3/', s3_dashboard, name='s3'),

    path('ai/', ai_assistant, name='ai'),

    path('ec2-findings/', ec2_findings, name='ec2-findings'),

    path('iam-findings/', iam_findings, name='iam-findings'),

    path('s3-findings/', s3_findings, name='s3-findings'),

    path('vpc-findings/', vpc_findings, name='vpc-findings'),

    path('iam-users-no-mfa/', iam_users_no_mfa, name='iam-users-no-mfa'),

    path('iam-details/', iam_details, name='iam-details'),

    path('ec2-details/', ec2_details, name='ec2-details'),

    path('s3-details/', s3_details, name='s3-details'),

    path('vpc-details/', vpc_details, name='vpc-details'),

    path('cloudfront-findings/', cloudfront_findings, name='cloudfront-findings'),

    path('cloudfront-details/', cloudfront_details, name='cloudfront-details'),
]

