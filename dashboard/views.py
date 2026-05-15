from django.shortcuts import render

from .models import (
    SourceCodeVulnerability,
    DockerVulnerability,
)


def home(request):

    source_total = SourceCodeVulnerability.objects.count()

    docker_total = DockerVulnerability.objects.count()

    critical = SourceCodeVulnerability.objects.filter(
        severity='CRITICAL'
    ).count()

    high = SourceCodeVulnerability.objects.filter(
        severity='HIGH'
    ).count()

    return render(request, 'home.html', {
        'source_total': source_total,
        'docker_total': docker_total,
        'critical': critical,
        'high': high,
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
