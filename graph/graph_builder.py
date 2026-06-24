import re
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def _scenario_token(name):
    """Extract the scenario id token like 's10' from any graphshield-s10-... name."""
    if not name:
        return None
    m = re.search(r'graphshield-(s\d+)', name.lower())
    return m.group(1) if m else None


class AttackGraphBuilder:
    def __init__(self):
        self.G = nx.DiGraph()

    def build_from_scan(self, scan_data):
        # Only consider resources belonging to THIS scenario, so leftover
        # resources from other scenarios in the same account don't pollute
        # the graph. We key on the scenario id token (e.g. 's10').
        sid = scan_data.get('scenario_id', '').lower()  # e.g. 's10'

        def belongs(name):
            tok = _scenario_token(name)
            return tok == sid or tok is None  # keep this scenario's; ignore others

        ec2s = [e for e in scan_data.get('ec2_instances', [])
                if belongs(e.get('iam_profile')) or _scenario_token(
                    ';'.join(e.get('tags', {}).values()) if e.get('tags') else '') == sid]
        # EC2s are already scenario-specific in practice; keep all that are tagged
        # this scenario or have a matching profile. Fallback: keep all EC2s.
        if not ec2s:
            ec2s = scan_data.get('ec2_instances', [])

        s3s = [b for b in scan_data.get('s3_buckets', []) if belongs(b.get('bucket_name'))]
        roles = [r for r in scan_data.get('iam_roles', []) if belongs(r.get('role_name'))]
        rdss = scan_data.get('rds_instances', [])

        for ec2 in ec2s:
            self.G.add_node(ec2['instance_id'], type='ec2',
                            internet_facing=ec2.get('internet_facing', False),
                            has_iam=ec2.get('iam_profile') is not None,
                            iam_profile=ec2.get('iam_profile'))
        for s3 in s3s:
            self.G.add_node(s3['bucket_name'], type='s3',
                            is_public=s3.get('is_public', False),
                            criticality=3 if s3.get('is_public') else 1)
        for role in roles:
            self.G.add_node(role['role_name'], type='iam_role',
                            privilege_depth=role.get('privilege_depth', 1),
                            has_admin=role.get('has_admin_access', False),
                            has_s3_wildcard=role.get('has_s3_wildcard', False))
        for db in rdss:
            self.G.add_node(db['db_identifier'], type='rds',
                            publicly_accessible=db.get('publicly_accessible', False),
                            criticality=3)
        self.G.add_node('INTERNET', type='external', criticality=0)

        # INTERNET -> EC2 (internet-facing)
        for ec2 in ec2s:
            if ec2.get('internet_facing', False):
                self.G.add_edge('INTERNET', ec2['instance_id'], weight=1.0,
                                description='Direct internet access to EC2')

        # EC2 -> IAM role : match by scenario token, not name-substring
        for ec2 in ec2s:
            prof_tok = _scenario_token(ec2.get('iam_profile'))
            if prof_tok:
                for role in roles:
                    if _scenario_token(role['role_name']) == prof_tok:
                        self.G.add_edge(ec2['instance_id'], role['role_name'], weight=0.9,
                                        description='EC2 assumes IAM role via instance profile')

        # IAM role -> S3 (role has wildcard/admin)
        for role in roles:
            if role.get('has_s3_wildcard') or role.get('has_admin_access'):
                for s3 in s3s:
                    self.G.add_edge(role['role_name'], s3['bucket_name'], weight=0.95,
                                    description='IAM role grants S3 access')

        # IAM role -> RDS (admin roles can reach DB tier)
        for role in roles:
            if role.get('has_admin_access'):
                for db in rdss:
                    self.G.add_edge(role['role_name'], db['db_identifier'], weight=0.8,
                                    description='IAM role can reach RDS')

        # INTERNET -> S3 (public bucket, direct)
        for s3 in s3s:
            if s3.get('is_public', False):
                self.G.add_edge('INTERNET', s3['bucket_name'], weight=1.0,
                                description='S3 bucket public from internet')

        # INTERNET -> RDS (publicly accessible DB)
        for db in rdss:
            if db.get('publicly_accessible', False):
                self.G.add_edge('INTERNET', db['db_identifier'], weight=1.0,
                                description='RDS publicly accessible')

        return self.G

    def find_attack_paths(self, target_types=None):
        if target_types is None:
            target_types = ['s3', 'rds']
        attack_paths = []
        targets = [n for n, d in self.G.nodes(data=True) if d.get('type') in target_types]
        for target in targets:
            try:
                for path in nx.all_simple_paths(self.G, 'INTERNET', target, cutoff=6):
                    w = 1.0
                    for i in range(len(path) - 1):
                        w *= self.G.edges[path[i], path[i + 1]].get('weight', 0.5)
                    attack_paths.append({
                        'path': path, 'length': len(path), 'target': target,
                        'path_probability': w, 'description': ' -> '.join(path),
                    })
            except nx.NetworkXNoPath:
                pass
        attack_paths.sort(key=lambda x: x['path_probability'], reverse=True)
        return attack_paths

    def visualize(self, output_path='graph/attack_graph.png'):
        color_map = {'external': 'red', 'ec2': 'orange', 'iam_role': 'gold',
                     's3': 'lightblue', 'rds': 'purple'}
        colors = [color_map.get(self.G.nodes[n].get('type', ''), 'gray') for n in self.G.nodes()]
        plt.figure(figsize=(14, 10))
        pos = nx.spring_layout(self.G, seed=42)
        nx.draw(self.G, pos, node_color=colors, with_labels=True, node_size=1500,
                font_size=8, arrows=True, arrowsize=20)
        plt.title('GraphShield Attack Graph')
        plt.savefig(output_path, bbox_inches='tight')
        print(f'Graph saved: {output_path}')