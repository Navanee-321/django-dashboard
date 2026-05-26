from django.db import models


class SourceCodeVulnerability(models.Model):
    repo_name = models.TextField(null=True)
    branch_name = models.TextField(null=True)
    scanner = models.TextField(null=True)
    type = models.TextField(null=True)
    severity = models.TextField(null=True)
    title = models.TextField(null=True)
    description = models.TextField(null=True)
    impact = models.TextField(null=True)
    recommendation = models.TextField(null=True)
    file_path = models.TextField(null=True)
    line_number = models.IntegerField(null=True)
    created_at = models.DateTimeField(null=True)

    def __str__(self):

        return f"{self.severity} - {self.title}"

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
    vulnerability_impact = models.TextField( null=True)
    recommendations = models.TextField(null=True)
    published_date = models.DateTimeField(null=True)
    inserted_at = models.DateTimeField(null=True)

    def __str__(self):

        return f"{self.severity} - {self.vulnerability_id}"

    class Meta:
        managed = False
        db_table = 'docker_vulnerabilities'

class AWSInspectorFinding(models.Model):

    severity = models.TextField(null=True)

    title = models.TextField(null=True)

    description = models.TextField(null=True)

    account_id = models.TextField(null=True)

    region = models.TextField(null=True)

    class Meta:
        managed = False
        db_table = '"aws_2"."aws_inspector_finding"'

class AWSEC2Instance(models.Model):

    instance_id = models.TextField(
        primary_key=True
    )

    instance_type = models.TextField(null=True)

    instance_state = models.TextField(null=True)

    public_ip_address = models.TextField(null=True)

    private_ip_address = models.TextField(null=True)

    region = models.TextField(null=True)

    account_id = models.TextField(null=True)

    def __str__(self):

        return f"{self.instance_id} - {self.instance_state}"

    class Meta:
        managed = False
        db_table = '"aws_2"."aws_ec2_instance"'

class AWSS3Bucket(models.Model):

    name = models.TextField(
        primary_key=True
    )

    bucket_policy_is_public = models.BooleanField(null=True)

    versioning_enabled = models.BooleanField(null=True)

    region = models.TextField(null=True)

    account_id = models.TextField(null=True)

    def __str__(self):

        return self.name

    class Meta:
        managed = False
        db_table = '"aws_2"."aws_s3_bucket"'
