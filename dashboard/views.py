from django.shortcuts import render
from django.db import connections
from django.http import HttpResponse

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
            'name': 'Inspector Findings',
            'description': 'AWS Inspector vulnerabilities',
            'url': '/aws/inspector/'
        },

        {
            'name': 'IAM Findings',
            'description': 'IAM security findings',
            'url': '/iam-findings/'
        },

        {
            'name': 'EC2 Findings',
            'description': 'EC2 security findings',
            'url': '/ec2-findings/'
        },

        {
            'name': 'S3 Findings',
            'description': 'S3 security findings',
            'url': '/s3-findings/'
        },

        {
            'name': 'VPC Findings',
            'description': 'VPC security findings',
            'url': '/vpc-findings/'
        },

        {
            'name': 'CloudFront Findings',
            'description': 'CloudFront security findings',
            'url': '/cloudfront-findings/'
        }

    ]

    return render(
        request,
        'aws_home.html',
        {'services': services}
    )

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

def ec2_findings(request):

    findings = []

    with connections['aws_db'].cursor() as cursor:

        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_ec2_instance
            WHERE public_ip_address IS NOT NULL
        """)

        public_ip_count = cursor.fetchone()[0]

        findings.append({
            'severity': 'HIGH',
            'title': 'EC2 Instances With Public IP',
            'count': public_ip_count
        })


        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_vpc_security_group_rule
            WHERE cidr_ipv4 = '0.0.0.0/0'
            AND from_port = 22
        """)

        ssh_count = cursor.fetchone()[0]

        findings.append({
            'severity': 'CRITICAL',
            'title': 'SSH Open To Internet',
            'count': ssh_count
        })

    return render(
        request,
        'ec2_findings.html',
        {'findings': findings}
    )

def iam_findings(request):

    findings = []

    with connections['aws_db'].cursor() as cursor:

        # Users without MFA

        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_iam_user
            WHERE mfa_enabled = false
        """)

        mfa_count = cursor.fetchone()[0]

        findings.append({
            'severity': 'HIGH',
            'title': 'Users Without MFA',
            'count': mfa_count
        })


        # Administrator Access

        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_iam_user
            WHERE attached_policy_arns::text
            ILIKE '%AdministratorAccess%'
        """)

        admin_count = cursor.fetchone()[0]

        findings.append({
            'severity': 'MEDIUM',
            'title': 'Users With Administrator Access',
            'count': admin_count
        })

    return render(
        request,
        'iam_findings.html',
        {'findings': findings}
    )

def s3_findings(request):

    findings = []

    with connections['aws_db'].cursor() as cursor:

        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_s3_bucket
            WHERE bucket_policy_is_public = true
        """)

        findings.append({
            'severity': 'CRITICAL',
            'title': 'Public S3 Buckets',
            'count': cursor.fetchone()[0]
        })

        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_s3_bucket
            WHERE versioning_enabled = false
        """)

        findings.append({
            'severity': 'MEDIUM',
            'title': 'Versioning Disabled',
            'count': cursor.fetchone()[0]
        })

        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_s3_bucket
            WHERE block_public_acls = false
        """)

        findings.append({
            'severity': 'HIGH',
            'title': 'Block Public ACLs Disabled',
            'count': cursor.fetchone()[0]
        })

        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_s3_bucket
            WHERE block_public_policy = false
        """)

        findings.append({
            'severity': 'HIGH',
            'title': 'Block Public Policy Disabled',
            'count': cursor.fetchone()[0]
        })

        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_s3_bucket
            WHERE restrict_public_buckets = false
        """)

        findings.append({
            'severity': 'HIGH',
            'title': 'Restrict Public Buckets Disabled',
            'count': cursor.fetchone()[0]
        })

    return render(
        request,
        's3_findings.html',
        {'findings': findings}
    )
def vpc_findings(request):

    findings = []

    with connections['aws_db'].cursor() as cursor:

        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_vpc_security_group_rule
            WHERE cidr_ipv4 = '0.0.0.0/0'
            AND from_port = 22
        """)

        findings.append({
            'severity': 'CRITICAL',
            'title': 'SSH Open To Internet',
            'count': cursor.fetchone()[0]
        })

        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_vpc_security_group_rule
            WHERE cidr_ipv4 = '0.0.0.0/0'
            AND from_port = 3389
        """)

        findings.append({
            'severity': 'CRITICAL',
            'title': 'RDP Open To Internet',
            'count': cursor.fetchone()[0]
        })

        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_vpc_security_group_rule
            WHERE cidr_ipv4 = '0.0.0.0/0'
            AND ip_protocol = '-1'
        """)

        findings.append({
            'severity': 'CRITICAL',
            'title': 'All Traffic Open To Internet',
            'count': cursor.fetchone()[0]
        })

        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_vpc_security_group_rule
            WHERE cidr_ipv4 = '0.0.0.0/0'
            AND from_port = 80
        """)

        findings.append({
            'severity': 'MEDIUM',
            'title': 'HTTP Open To Internet',
            'count': cursor.fetchone()[0]
        })

    return render(
        request,
        'vpc_findings.html',
        {'findings': findings}
    )


def cloudfront_findings(request):

    findings = []

    with connections['aws_db'].cursor() as cursor:

        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_cloudfront_distribution
            WHERE origins::text ILIKE '%http-only%'
        """)

        findings.append({
            'severity': 'CRITICAL',
            'title': 'Origin Uses HTTP Only',
            'count': cursor.fetchone()[0]
        })

        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_cloudfront_distribution
            WHERE logging::text ILIKE '%"Enabled": false%'
        """)

        findings.append({
            'severity': 'HIGH',
            'title': 'CloudFront Logging Disabled',
            'count': cursor.fetchone()[0]
        })

        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_cloudfront_distribution
            WHERE web_acl_id IS NULL
            OR web_acl_id = ''
        """)

        findings.append({
            'severity': 'HIGH',
            'title': 'No WAF Attached',
            'count': cursor.fetchone()[0]
        })

        cursor.execute("""
            SELECT COUNT(*)
            FROM aws_2.aws_cloudfront_distribution
            WHERE restrictions::text ILIKE '%RestrictionType": "none"%'
        """)

        findings.append({
            'severity': 'LOW',
            'title': 'Geo Restriction Not Configured',
            'count': cursor.fetchone()[0]
        })

    return render(
        request,
        'cloudfront_findings.html',
        {'findings': findings}
    )

def iam_users_no_mfa(request):

    with connections['aws_db'].cursor() as cursor:

        cursor.execute("""
            SELECT name
            FROM aws_2.aws_iam_user
            WHERE mfa_enabled = false
        """)

        users = cursor.fetchall()

    return render(
        request,
        'iam_users_no_mfa.html',
        {'users': users}
    )


def iam_details(request):

    finding_type = request.GET.get('type')

    with connections['aws_db'].cursor() as cursor:

        if finding_type == 'no_mfa':

            title = "IAM Users Without MFA"

            cursor.execute("""
                SELECT name
                FROM aws_2.aws_iam_user
                WHERE mfa_enabled = false
            """)

        elif finding_type == 'admin':

            title = "IAM Users With Administrator Access"

            cursor.execute("""
                SELECT name
                FROM aws_2.aws_iam_user
                WHERE attached_policy_arns::text
                ILIKE '%AdministratorAccess%'
            """)

        else:
            return HttpResponse("Invalid finding type")

        data = cursor.fetchall()

    return render(
        request,
        'iam_details.html',
        {
            'title': title,
            'data': data
        }
    )

def ec2_details(request):

    finding_type = request.GET.get('type')

    with connections['aws_db'].cursor() as cursor:

        if finding_type == 'public_ip':

            title = "EC2 Instances With Public IP"

            cursor.execute("""
                SELECT title
                FROM aws_2.aws_ec2_instance
                WHERE public_ip_address IS NOT NULL
            """)

        else:
            return HttpResponse("Invalid finding type")

        data = cursor.fetchall()

    return render(
        request,
        'ec2_details.html',
        {
            'title': title,
            'data': data
        }
    )

def ec2_details(request):

    finding_type = request.GET.get('type')

    with connections['aws_db'].cursor() as cursor:

        if finding_type == 'public_ip':

            title = "EC2 Instances With Public IP"

            cursor.execute("""
                SELECT title
                FROM aws_2.aws_ec2_instance
                WHERE public_ip_address IS NOT NULL
            """)

        else:
            return HttpResponse("Invalid finding type")

        data = cursor.fetchall()

    return render(
        request,
        'details.html',
        {
            'title': title,
            'data': data
        }
    )


def s3_details(request):

    finding_type = request.GET.get('type')

    with connections['aws_db'].cursor() as cursor:

        if finding_type == 'public_bucket':

            title = "Public S3 Buckets"

            cursor.execute("""
                SELECT title
                FROM aws_2.aws_s3_bucket
                WHERE bucket_policy_is_public = true
            """)

        elif finding_type == 'versioning_disabled':

            title = "Versioning Disabled"

            cursor.execute("""
                SELECT title
                FROM aws_2.aws_s3_bucket
                WHERE versioning_enabled = false
            """)

        elif finding_type == 'block_public_acl':

            title = "Block Public ACLs Disabled"

            cursor.execute("""
                SELECT title
                FROM aws_2.aws_s3_bucket
                WHERE block_public_acls = false
            """)

        elif finding_type == 'block_public_policy':

            title = "Block Public Policy Disabled"

            cursor.execute("""
                SELECT title
                FROM aws_2.aws_s3_bucket
                WHERE block_public_policy = false
            """)

        elif finding_type == 'restrict_public_bucket':

            title = "Restrict Public Buckets Disabled"

            cursor.execute("""
                SELECT title
                FROM aws_2.aws_s3_bucket
                WHERE restrict_public_buckets = false
            """)

        else:
            return HttpResponse("Invalid finding type")

        data = cursor.fetchall()

    return render(
        request,
        'details.html',
        {
            'title': title,
            'data': data
        }
    )


def vpc_details(request):

    finding_type = request.GET.get('type')

    with connections['aws_db'].cursor() as cursor:

        if finding_type == 'ssh_open':

            title = "SSH Open To Internet"

            cursor.execute("""
                SELECT group_id
                FROM aws_2.aws_vpc_security_group_rule
                WHERE cidr_ipv4 = '0.0.0.0/0'
                AND from_port = 22
            """)

        elif finding_type == 'rdp_open':

            title = "RDP Open To Internet"

            cursor.execute("""
                SELECT group_id
                FROM aws_2.aws_vpc_security_group_rule
                WHERE cidr_ipv4 = '0.0.0.0/0'
                AND from_port = 3389
            """)

        elif finding_type == 'all_traffic':

            title = "All Traffic Open To Internet"

            cursor.execute("""
                SELECT group_id
                FROM aws_2.aws_vpc_security_group_rule
                WHERE cidr_ipv4 = '0.0.0.0/0'
                AND ip_protocol = '-1'
            """)

        elif finding_type == 'http_open':

            title = "HTTP Open To Internet"

            cursor.execute("""
                SELECT group_id
                FROM aws_2.aws_vpc_security_group_rule
                WHERE cidr_ipv4 = '0.0.0.0/0'
                AND from_port = 80
            """)

        else:
            return HttpResponse("Invalid finding type")

        data = cursor.fetchall()

    return render(
        request,
        'details.html',
        {
            'title': title,
            'data': data
        }
    )


def cloudfront_details(request):

    finding_type = request.GET.get('type')

    title = "CloudFront Details"

    with connections['aws_db'].cursor() as cursor:

        if finding_type == 'http_only':

            title = "Origin Uses HTTP Only"

            cursor.execute("""
                SELECT title
                FROM aws_2.aws_cloudfront_distribution
                WHERE origins::text ILIKE '%http-only%'
            """)

        elif finding_type == 'logging_disabled':

            title = "CloudFront Logging Disabled"

            cursor.execute("""
                SELECT title
                FROM aws_2.aws_cloudfront_distribution
                WHERE logging::text ILIKE '%"Enabled": false%'
            """)

        elif finding_type == 'no_waf':

            title = "No WAF Attached"

            cursor.execute("""
                SELECT title
                FROM aws_2.aws_cloudfront_distribution
                WHERE web_acl_id IS NULL
                OR web_acl_id = ''
            """)

        elif finding_type == 'no_geo':

            title = "Geo Restriction Not Configured"

            cursor.execute("""
                SELECT title
                FROM aws_2.aws_cloudfront_distribution
                WHERE restrictions::text ILIKE '%RestrictionType": "none"%'
            """)

        else:

            return HttpResponse("Invalid finding type")

        data = cursor.fetchall()

    return render(
        request,
        'details.html',
        {
            'title': title,
            'data': data
        }
    )
