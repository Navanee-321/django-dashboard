from django.db import models


class SourceCodeVulnerability(models.Model):
    repo_name = models.TextField(null=True)
    branch_name = models.TextField(null=True)
    scanner = models.TextField(null=True)
    type = models.TextField(null=True)
    severity = models.TextField(null=True)
    title = models.TextField(null=True)
    description = models.TextField(null=True)
    file_path = models.TextField(null=True)
    line_number = models.IntegerField(null=True)
    created_at = models.DateTimeField(null=True)

    class Meta:
        managed = False
        db_table = 'source_code_vulnerabilites'


class DockerVulnerability(models.Model):
    image_name = models.TextField(null=True)
    target = models.TextField(null=True)
    vulnerability_id = models.TextField(null=True)
    package_name = models.TextField(null=True)
    installed_version = models.TextField(null=True)
    fixed_version = models.TextField(null=True)
    severity = models.TextField(null=True)
    title = models.TextField(null=True)
    description = models.TextField(null=True)
    published_date = models.DateTimeField(null=True)
    inserted_at = models.DateTimeField(null=True)

    class Meta:
        managed = False
        db_table = 'docker_vulnerabilities'

