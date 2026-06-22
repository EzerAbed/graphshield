import boto3
import json
import sys
import os
from datetime import datetime


class AWSScanner:
    def __init__(self, region='us-east-1'):
        self.region = region
        self.ec2 = boto3.client('ec2', region_name=region)
        self.s3 = boto3.client('s3', region_name=region)
        self.iam = boto3.client('iam', region_name=region)
        self.lam = boto3.client('lambda', region_name=region)
        self.rds = boto3.client('rds', region_name=region)
        self.ct = boto3.client('cloudtrail', region_name=region)

    def scan_ec2_instances(self):
        """Collect all EC2 instance configurations"""
        result = []
        resp = self.ec2.describe_instances()
        for reservation in resp['Reservations']:
            for instance in reservation['Instances']:
                if instance['State']['Name'] == 'terminated':
                    continue
                result.append({
                    'resource_type': 'ec2',
                    'instance_id': instance['InstanceId'],
                    'instance_type': instance.get('InstanceType', ''),
                    'state': instance['State']['Name'],
                    'public_ip': instance.get('PublicIpAddress', None),
                    'private_ip': instance.get('PrivateIpAddress', ''),
                    'internet_facing': instance.get('PublicIpAddress') is not None,
                    'subnet_id': instance.get('SubnetId', ''),
                    'vpc_id': instance.get('VpcId', ''),
                    'iam_profile': instance.get('IamInstanceProfile', {}).get('Arn', None),
                    'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                    'imds_v2': instance.get('MetadataOptions', {}).get('HttpTokens', 'optional'),
                    'ebs_encrypted': all(
                        m.get('Ebs', {}).get('DeleteOnTermination', False)
                        for m in instance.get('BlockDeviceMappings', [])
                    ),
                    'tags': {t['Key']: t['Value'] for t in instance.get('Tags', [])},
                })
        return result

    def scan_security_groups(self):
        """Collect all Security Group rules and evaluate exposure"""
        result = []
        sgs = self.ec2.describe_security_groups()['SecurityGroups']
        for sg in sgs:
            open_ssh = any(
                r.get('FromPort') == 22 and '0.0.0.0/0' in [ip['CidrIp'] for ip in r.get('IpRanges', [])]
                for r in sg.get('IpPermissions', [])
            )
            open_rdp = any(
                r.get('FromPort') == 3389 and '0.0.0.0/0' in [ip['CidrIp'] for ip in r.get('IpRanges', [])]
                for r in sg.get('IpPermissions', [])
            )
            open_all = any(
                r.get('IpProtocol') == '-1' and '0.0.0.0/0' in [ip['CidrIp'] for ip in r.get('IpRanges', [])]
                for r in sg.get('IpPermissions', [])
            )
            result.append({
                'resource_type': 'security_group',
                'group_id': sg['GroupId'],
                'group_name': sg['GroupName'],
                'vpc_id': sg.get('VpcId', ''),
                'ssh_open_world': open_ssh,
                'rdp_open_world': open_rdp,
                'all_traffic_open': open_all,
                'inbound_rule_count': len(sg.get('IpPermissions', [])),
                'rules': sg.get('IpPermissions', []),
            })
        return result

    def scan_s3_buckets(self):
        """Collect S3 bucket configurations and public access settings"""
        result = []
        buckets = self.s3.list_buckets().get('Buckets', [])
        for bucket in buckets:
            name = bucket['Name']
            if 'graphshield' not in name:
                continue  # Only scan our project buckets
            try:
                pub_block = self.s3.get_public_access_block(Bucket=name)['PublicAccessBlockConfiguration']
                is_public = not all([
                    pub_block.get('BlockPublicAcls'), pub_block.get('BlockPublicPolicy'),
                    pub_block.get('IgnorePublicAcls'), pub_block.get('RestrictPublicBuckets')
                ])
            except Exception:
                is_public = True  # No block = public
            try:
                self.s3.get_bucket_encryption(Bucket=name)
                encrypted = True
            except Exception:
                encrypted = False
            try:
                versioning = self.s3.get_bucket_versioning(Bucket=name).get('Status', 'Disabled')
            except Exception:
                versioning = 'Disabled'
            result.append({
                'resource_type': 's3',
                'bucket_name': name,
                'is_public': is_public,
                'encryption': encrypted,
                'versioning': versioning,
            })
        return result

    def scan_iam_roles(self):
        """Collect IAM roles and assess privilege level"""
        result = []
        roles = self.iam.list_roles()['Roles']
        for role in roles:
            if 'graphshield' not in role['RoleName']:
                continue
            attached = self.iam.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']
            inline = self.iam.list_role_policies(RoleName=role['RoleName'])['PolicyNames']
            has_admin = any('AdministratorAccess' in p.get('PolicyName', '') for p in attached)
            has_s3_star = False
            for pol_name in inline:
                doc = self.iam.get_role_policy(RoleName=role['RoleName'], PolicyName=pol_name)['PolicyDocument']
                for stmt in doc.get('Statement', []):
                    actions = stmt.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if 's3:*' in actions or '*' in actions:
                        has_s3_star = True
            privilege_depth = 3 if has_admin else (2 if has_s3_star else 1)
            result.append({
                'resource_type': 'iam_role',
                'role_name': role['RoleName'],
                'role_arn': role['Arn'],
                'has_admin_access': has_admin,
                'has_s3_wildcard': has_s3_star,
                'privilege_depth': privilege_depth,
                'attached_policies': [p['PolicyName'] for p in attached],
                'inline_policies': inline,
            })
        return result

    def scan_lambda_functions(self):
        """Collect Lambda function configs and check for public Function URLs"""
        result = []
        try:
            functions = self.lam.list_functions().get('Functions', [])
        except Exception:
            return result
        for fn in functions:
            name = fn['FunctionName']
            if 'graphshield' not in name:
                continue
            is_public = False
            try:
                url_config = self.lam.get_function_url_config(FunctionName=name)
                is_public = url_config.get('AuthType', 'AWS_IAM') == 'NONE'
            except Exception:
                is_public = False  # No Function URL configured

            has_wildcard_role = False
            role_arn = fn.get('Role', '')
            role_name = role_arn.split('/')[-1] if role_arn else None
            if role_name:
                try:
                    inline = self.iam.list_role_policies(RoleName=role_name)['PolicyNames']
                    for pol_name in inline:
                        doc = self.iam.get_role_policy(RoleName=role_name, PolicyName=pol_name)['PolicyDocument']
                        for stmt in doc.get('Statement', []):
                            actions = stmt.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if any(a == '*' or a.endswith(':*') for a in actions):
                                has_wildcard_role = True
                    attached = self.iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                    if any('AdministratorAccess' in p.get('PolicyName', '') for p in attached):
                        has_wildcard_role = True
                except Exception:
                    pass

            result.append({
                'resource_type': 'lambda',
                'function_name': name,
                'function_arn': fn.get('FunctionArn', ''),
                'runtime': fn.get('Runtime', ''),
                'role_arn': role_arn,
                'is_public_url': is_public,
                'has_wildcard_permissions': has_wildcard_role,
            })
        return result

    def scan_rds_instances(self):
        """Collect RDS instance configurations and exposure settings"""
        result = []
        try:
            instances = self.rds.describe_db_instances().get('DBInstances', [])
        except Exception:
            return result
        for db in instances:
            identifier = db.get('DBInstanceIdentifier', '')
            if 'graphshield' not in identifier:
                continue
            sg_ids = [sg['VpcSecurityGroupId'] for sg in db.get('VpcSecurityGroups', [])]
            result.append({
                'resource_type': 'rds',
                'db_identifier': identifier,
                'engine': db.get('Engine', ''),
                'publicly_accessible': db.get('PubliclyAccessible', False),
                'encrypted': db.get('StorageEncrypted', False),
                'security_groups': sg_ids,
                'multi_az': db.get('MultiAZ', False),
                'backup_retention_days': db.get('BackupRetentionPeriod', 0),
            })
        return result

    def scan_cloudtrail(self):
        """Check if CloudTrail logging is enabled"""
        try:
            trails = self.ct.describe_trails()['trailList']
            graphshield_trails = [t for t in trails if 'graphshield' in t.get('Name', '')]
            enabled = len(graphshield_trails) > 0
        except Exception:
            enabled = False
        return {'resource_type': 'cloudtrail', 'logging_enabled': enabled}

    def scan_all(self, scenario_id):
        """Run all scanners and return combined results"""
        print(f'Scanning scenario {scenario_id}...')
        return {
            'scenario_id': scenario_id,
            'scan_timestamp': datetime.utcnow().isoformat(),
            'region': self.region,
            'ec2_instances': self.scan_ec2_instances(),
            'security_groups': self.scan_security_groups(),
            's3_buckets': self.scan_s3_buckets(),
            'iam_roles': self.scan_iam_roles(),
            'lambda_functions': self.scan_lambda_functions(),
            'rds_instances': self.scan_rds_instances(),
            'cloudtrail': self.scan_cloudtrail(),
        }


if __name__ == '__main__':
    scenario_id = sys.argv[1] if len(sys.argv) > 1 else 'UNKNOWN'
    scanner = AWSScanner(region='us-east-1')
    data = scanner.scan_all(scenario_id)
    out_path = f'data/{scenario_id}_scan.json'
    os.makedirs('data', exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    print(f'Saved to {out_path}')
    print(f'Found: {len(data["ec2_instances"])} EC2, {len(data["s3_buckets"])} S3, '
          f'{len(data["iam_roles"])} IAM roles, {len(data["lambda_functions"])} Lambda, '
          f'{len(data["rds_instances"])} RDS')