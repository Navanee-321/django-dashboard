from django.shortcuts import render

from .models import (
    SourceCodeVulnerability,
    DockerVulnerability,
    AWSInspectorFinding,
    AWSEC2Instance,
    AWSS3Bucket,
)


def home(request):

    source_total = SourceCodeVulnerability.objects.count()

    source_critical = SourceCodeVulnerability.objects.filter(
        severity='CRITICAL'
    ).count()

    source_high = SourceCodeVulnerability.objects.filter(
        severity='HIGH'
    ).count()

    source_medium = SourceCodeVulnerability.objects.filter(
        severity='MEDIUM'
    ).count()

    source_low = SourceCodeVulnerability.objects.filter(
        severity='LOW'
    ).count()


    docker_total = DockerVulnerability.objects.count()

    docker_critical = DockerVulnerability.objects.filter(
        severity='CRITICAL'
    ).count()

    docker_high = DockerVulnerability.objects.filter(
        severity='HIGH'
    ).count()

    docker_medium = DockerVulnerability.objects.filter(
        severity='MEDIUM'
    ).count()

    docker_low = DockerVulnerability.objects.filter(
        severity='LOW'
    ).count()


    aws_total = AWSInspectorFinding.objects.using(
        'aws_db'
    ).count()

    aws_critical = AWSInspectorFinding.objects.using(
        'aws_db'
    ).filter(severity='Critical').count()

    aws_high = AWSInspectorFinding.objects.using(
        'aws_db'
    ).filter(severity='High').count()

    aws_medium = AWSInspectorFinding.objects.using(
        'aws_db'
    ).filter(severity='Medium').count()

    aws_low = AWSInspectorFinding.objects.using(
        'aws_db'
    ).filter(severity='Low').count()


    context = {

        'source_total': source_total,
        'source_critical': source_critical,
        'source_high': source_high,
        'source_medium': source_medium,
        'source_low': source_low,

        'docker_total': docker_total,
        'docker_critical': docker_critical,
        'docker_high': docker_high,
        'docker_medium': docker_medium,
        'docker_low': docker_low,

        'aws_total': aws_total,
        'aws_critical': aws_critical,
        'aws_high': aws_high,
        'aws_medium': aws_medium,
        'aws_low': aws_low,
    }

    return render(request, 'home.html', context)

def aws_home(request):

    services = [

        {
            'name': 'Inspector',
            'url': '/aws/inspector/',
            'description': 'AWS Inspector Vulnerability Findings'
        },

        {
            'name': 'EC2',
            'url': '/ec2/',
            'description': 'AWS EC2 Inventory'
        },

        {
            'name': 'S3',
            'url': '/s3/',
            'description': 'AWS S3 Bucket Inventory'
        },

    ]

    return render(request, 'aws_home.html', {
        'services': services
    })

def source_dashboard(request):

    repo_data = []

    unique_repos = SourceCodeVulnerability.objects.values_list(
        'repo_name',
        flat=True
    ).distinct()

    for repo in unique_repos:

        repo_data.append({

            'repo_name': repo,

            'critical': SourceCodeVulnerability.objects.filter(
                repo_name=repo,
                severity='CRITICAL'
            ).count(),

            'high': SourceCodeVulnerability.objects.filter(
                repo_name=repo,
                severity='HIGH'
            ).count(),

            'medium': SourceCodeVulnerability.objects.filter(
                repo_name=repo,
                severity='MEDIUM'
            ).count(),

            'low': SourceCodeVulnerability.objects.filter(
                repo_name=repo,
                severity='LOW'
            ).count(),

        })

    return render(request, 'sourcecode.html', {
        'data': repo_data
    })


def repo_vulnerabilities(request):

    repo_name = request.GET.get('repo')

    severity = request.GET.get('severity')

    data = SourceCodeVulnerability.objects.filter(
        repo_name=repo_name
    )

    if severity:

        data = data.filter(
            severity__iexact=severity
        )

    return render(request, 'repo_vulnerabilities.html', {
        'data': data,
        'repo_name': repo_name,
        'severity': severity,
    })


def docker_dashboard(request):

    image_data = []

    unique_images = DockerVulnerability.objects.values_list(
        'image_name',
        flat=True
    ).distinct()

    for image in unique_images:

        image_data.append({

            'image_name': image,

            'critical': DockerVulnerability.objects.filter(
                image_name=image,
                severity='CRITICAL'
            ).count(),

            'high': DockerVulnerability.objects.filter(
                image_name=image,
                severity='HIGH'
            ).count(),

            'medium': DockerVulnerability.objects.filter(
                image_name=image,
                severity='MEDIUM'
            ).count(),

            'low': DockerVulnerability.objects.filter(
                image_name=image,
                severity='LOW'
            ).count(),

        })

    return render(request, 'docker.html', {
        'data': image_data
    })


def docker_image_vulnerabilities(request):

    image_name = request.GET.get('image')

    severity = request.GET.get('severity')

    data = DockerVulnerability.objects.filter(
        image_name=image_name
    )

    if severity:

        data = data.filter(
            severity__iexact=severity
        )

    return render(request, 'docker_image_vulnerabilities.html', {
        'data': data,
        'image_name': image_name,
        'severity': severity,
    })

from django.db.models import Count
from django.db import models


def aws_dashboard(request):

    severity = request.GET.get('severity')

    if severity:

        data = AWSInspectorFinding.objects.using(
            'aws_db'
        ).filter(
            severity=severity
        )[:100]

        return render(request, 'aws_details.html', {
            'data': data,
            'severity': severity,
        })


    aws_summary = AWSInspectorFinding.objects.using(
        'aws_db'
    ).values(
        'account_id'
    ).annotate(

        critical=Count(
            'id',
            filter=models.Q(severity='Critical')
        ),

        high=Count(
            'id',
            filter=models.Q(severity='High')
        ),

        medium=Count(
            'id',
            filter=models.Q(severity='Medium')
        ),

        low=Count(
            'id',
            filter=models.Q(severity='Low')
        ),

    )

    return render(request, 'aws.html', {
        'aws_summary': aws_summary
    })

def ec2_dashboard(request):

    data = AWSEC2Instance.objects.using(
        'aws_db'
    ).all()[:100]

    return render(request, 'ec2.html', {
        'data': data
    })

def s3_dashboard(request):

    data = AWSS3Bucket.objects.using(
        'aws_db'
    ).all()[:100]

    return render(request, 's3.html', {
        'data': data
    })

def ai_assistant(request):

    question = None

    results = None

    total_count = 0


    if request.method == 'POST':

        question = request.POST.get('question').lower()

        severity = None


        # Detect Severity

        if 'critical' in question:

            severity = 'CRITICAL'

        elif 'high' in question:

            severity = 'HIGH'

        elif 'medium' in question:

            severity = 'MEDIUM'

        elif 'low' in question:

            severity = 'LOW'


        # SOURCE CODE

        if 'source code' in question:

            data = SourceCodeVulnerability.objects.all()

            if severity:

                data = data.filter(
                    severity=severity
                )

            total_count = data.count()

            results = data[:20]


        # DOCKER

        elif 'docker' in question:

            data = DockerVulnerability.objects.all()

            if severity:

                data = data.filter(
                    severity=severity
                )

            total_count = data.count()

            results = data[:20]


        # AWS INSPECTOR

        elif 'aws' in question or 'inspector' in question:

            data = AWSInspectorFinding.objects.using(
                'aws_db'
            ).all()

            if severity:

                severity_map = {
                    'CRITICAL': 'Critical',
                    'HIGH': 'High',
                    'MEDIUM': 'Medium',
                    'LOW': 'Low',
                }

                data = data.filter(
                    severity=severity_map[severity]
                )

            total_count = data.count()

            results = data[:20]


        # EC2

        elif 'ec2' in question:

            data = AWSEC2Instance.objects.using(
                'aws_db'
            ).all()

            total_count = data.count()

            results = data[:20]


        # S3

        elif 's3' in question:

            if severity:

                results = [
                    'S3 buckets do not support severity filtering.'
                ]

            else:

                data = AWSS3Bucket.objects.using(
                    'aws_db'
                ).all()

                total_count = data.count()

                results = data[:20]


        # UNKNOWN QUESTION

        else:

            results = [
                'Sorry, I can only answer questions related to Source Code, Docker, AWS, EC2 and S3.'
            ]


    return render(request, 'ai.html', {
        'question': question,
        'results': results,
        'total_count': total_count
    })            
