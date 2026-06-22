import json
import pandas as pd
import os

def extract_features(scan_data):
    """
    Convert a raw AWS scan result into a flat feature vector.
    Returns a dictionary of features for one scenario.
    """
    features = {}
    sid = scan_data['scenario_id']
    features['scenario_id'] = sid

    # --- EC2 FEATURES ---
    ec2s = scan_data.get('ec2_instances', [])
    features['ec2_count']               = len(ec2s)
    features['ec2_internet_facing']     = sum(1 for e in ec2s if e.get('internet_facing', False))
    features['ec2_with_iam_profile']    = sum(1 for e in ec2s if e.get('iam_profile') is not None)
    features['ec2_imdsv2_disabled']     = sum(1 for e in ec2s if e.get('imds_v2') == 'optional')
    features['ec2_unencrypted_disk']    = sum(1 for e in ec2s if not e.get('ebs_encrypted', True))
    features['ec2_has_public_ip']       = int(any(e.get('public_ip') for e in ec2s))

    # --- SECURITY GROUP FEATURES ---
    sgs = scan_data.get('security_groups', [])
    features['sg_ssh_open_world']       = sum(1 for s in sgs if s.get('ssh_open_world', False))
    features['sg_rdp_open_world']       = sum(1 for s in sgs if s.get('rdp_open_world', False))
    features['sg_all_traffic_open']     = sum(1 for s in sgs if s.get('all_traffic_open', False))
    features['sg_max_rule_count']       = max((s.get('inbound_rule_count', 0) for s in sgs), default=0)

    # --- S3 FEATURES ---
    s3s = scan_data.get('s3_buckets', [])
    features['s3_count']                = len(s3s)
    features['s3_public_count']         = sum(1 for b in s3s if b.get('is_public', False))
    features['s3_unencrypted_count']    = sum(1 for b in s3s if not b.get('encryption', False))
    features['s3_has_public']           = int(any(b.get('is_public') for b in s3s))

    # --- IAM FEATURES ---
    iam = scan_data.get('iam_roles', [])
    features['iam_role_count']          = len(iam)
    features['iam_admin_roles']         = sum(1 for r in iam if r.get('has_admin_access', False))
    features['iam_s3_wildcard_roles']   = sum(1 for r in iam if r.get('has_s3_wildcard', False))
    features['iam_max_privilege_depth'] = max((r.get('privilege_depth', 0) for r in iam), default=0)

    # --- CLOUDTRAIL FEATURES ---
    ct = scan_data.get('cloudtrail', {})
    features['cloudtrail_enabled']      = int(ct.get('logging_enabled', False))

    # --- COMBINATION FEATURES (critical for ML) ---
    # These capture dangerous combinations that isolated checks miss
    features['internet_ec2_with_iam']   = int(
        features['ec2_internet_facing'] > 0 and features['ec2_with_iam_profile'] > 0
    )
    features['open_ssh_with_iam']       = int(
        features['sg_ssh_open_world'] > 0 and features['ec2_with_iam_profile'] > 0
    )
    features['public_s3_with_iam']      = int(
        features['s3_has_public'] and features['iam_role_count'] > 0
    )
    features['full_chain_present']      = int(
        features['ec2_internet_facing'] > 0 and
        features['sg_ssh_open_world'] > 0 and
        features['iam_max_privilege_depth'] >= 2
    )
    features['no_logging_with_exposure'] = int(
        not features['cloudtrail_enabled'] and
        (features['ec2_internet_facing'] > 0 or features['s3_has_public'])
    )

    return features


def build_dataset(data_dir='data', output_path='dataset/features.csv'):
    """Process all scan files and build the feature dataset"""
    rows = []
    for fname in sorted(os.listdir(data_dir)):
        if not fname.endswith('_scan.json'):
            continue
        path = os.path.join(data_dir, fname)
        with open(path) as f:
            scan = json.load(f)
        features = extract_features(scan)
        rows.append(features)
        print(f'Processed: {fname} -> scenario {features["scenario_id"]}')

    df = pd.DataFrame(rows)
    os.makedirs('dataset', exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f'\nDataset saved: {output_path} ({len(df)} rows, {len(df.columns)} features)')
    return df


if __name__ == '__main__':
    df = build_dataset()
    print('\nFeature columns:')
    print(list(df.columns))
    print('\nFirst few rows:')
    print(df.head())