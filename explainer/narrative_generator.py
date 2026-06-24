"""
explainer/narrative_generator.py  (Phase 7 — Explainability Layer)

Turns a single scenario into human-readable security intelligence:
  1. predicts the risk level with the trained Random Forest
  2. names the most critical attack PATH found in the graph
  3. explains WHY the configuration is risky, using both SHAP feature
     contributions and the graph evidence
  4. lists remediation actions ranked by impact

This is the layer that makes GraphShield "intelligence" rather than a
classifier: it converts model output + graph structure into an analyst-style
explanation such as
  "This is rated High because an internet-facing EC2 instance holds an
   over-privileged IAM role that can reach a sensitive S3 bucket
   (INTERNET -> i-0abc -> graphshield-s10-ec2-role -> ...-target)."
"""
import json
import os
import joblib
import numpy as np
import pandas as pd

from normalizer.feature_extractor import extract_features
from graph.graph_builder import AttackGraphBuilder
from graph.graph_features import compute_graph_features

try:
    import shap
    HAS_SHAP = True
except Exception:
    HAS_SHAP = False

RISK_LABELS = {0: 'Safe', 1: 'Low Risk', 2: 'Medium Risk', 3: 'High Risk', 4: 'Critical'}

# Feature -> plain-English meaning (used when a feature drives the prediction)
FEATURE_EXPLANATIONS = {
    'full_chain_present': 'a complete attack chain exists (internet-facing EC2 + open SSH + over-privileged IAM)',
    'open_ssh_with_iam': 'SSH is open to the internet on an EC2 instance that holds IAM credentials',
    'internet_ec2_with_iam': 'an internet-accessible EC2 instance has an IAM role attached, enabling credential theft',
    'public_s3_with_iam': 'a public S3 bucket exists alongside IAM roles that can access it',
    'no_logging_with_exposure': 'CloudTrail logging is disabled, so attacker activity would go undetected',
    'iam_admin_roles': 'an IAM role with AdministratorAccess is present (full account takeover possible)',
    'iam_s3_wildcard_roles': 'an IAM role grants wildcard S3 permissions instead of least privilege',
    'sg_ssh_open_world': 'SSH port 22 is open to 0.0.0.0/0 (the entire internet)',
    'sg_rdp_open_world': 'RDP port 3389 is open to 0.0.0.0/0 (the entire internet)',
    'sg_all_traffic_open': 'all inbound traffic is allowed from the internet (no network restrictions)',
    'ec2_internet_facing': 'one or more EC2 instances are directly exposed to the internet',
    'ec2_imdsv2_disabled': 'EC2 instance metadata service v1 is allowed, enabling SSRF-based credential theft',
    'ec2_unencrypted_disk': 'EC2 root volumes are not encrypted',
    's3_has_public': 'at least one S3 bucket is publicly accessible without authentication',
    'iam_max_privilege_depth': 'high-privilege IAM roles exist in the environment',
    # graph-derived
    'graph_num_attack_paths': 'multiple distinct attack paths reach sensitive resources from the internet',
    'graph_max_path_probability': 'at least one attack path has a high end-to-end exploit probability',
    'graph_shortest_path_len': 'a short attack path exists, meaning few steps are needed to reach a target',
    'graph_max_reachable_privilege': 'an attack path leads to high-privilege resources',
    'graph_num_reachable_targets': 'several sensitive resources are reachable from the internet',
}


def _feature_vector_for_model(scan_data, model_features):
    """Build the exact feature row the model expects (flat + graph), in order."""
    flat = extract_features(scan_data)
    graph = compute_graph_features(scan_data)
    combined = {**flat, **graph}
    row = {f: combined.get(f, 0) for f in model_features}
    return pd.DataFrame([row])[model_features]


def generate_narrative(scan_data,
                       model_path='ml/models/random_forest.pkl',
                       feature_list_path='ml/models/feature_list.json'):
    model = joblib.load(model_path)

    # Recover the exact feature order the model was trained on
    if os.path.exists(feature_list_path):
        with open(feature_list_path) as f:
            model_features = json.load(f)
    else:
        # fall back to the model's known feature names if available
        model_features = list(getattr(model, 'feature_names_in_', []))

    X = _feature_vector_for_model(scan_data, model_features)
    prediction = int(model.predict(X)[0])
    risk_label = RISK_LABELS.get(prediction, 'Unknown')

    # Build the graph + find the top attack path
    builder = AttackGraphBuilder()
    builder.build_from_scan(scan_data)
    paths = builder.find_attack_paths()

    # SHAP contributions for THIS prediction (which features pushed it here)
    top_features = []
    if HAS_SHAP:
        try:
            explainer = shap.TreeExplainer(model)
            sv = explainer.shap_values(X)
            # multiclass -> list per class; pick the predicted class
            if isinstance(sv, list):
                contrib = sv[prediction][0]
            else:
                arr = np.array(sv)
                contrib = arr[0, :, prediction] if arr.ndim == 3 else arr[0]
            order = np.argsort(np.abs(contrib))[::-1]
            for idx in order[:6]:
                if contrib[idx] > 0:  # only features that INCREASED the risk
                    top_features.append(model_features[idx])
        except Exception:
            top_features = []

    # Fall back to model feature importances if SHAP unavailable
    if not top_features and hasattr(model, 'feature_importances_'):
        imp = pd.Series(model.feature_importances_, index=model_features)
        # only mention features that are actually "on" in this scenario
        active = [f for f in imp.sort_values(ascending=False).index
                  if X.iloc[0].get(f, 0) and f in FEATURE_EXPLANATIONS]
        top_features = active[:5]

    # ---- assemble the narrative ----
    lines = []
    lines.append(f'RISK ASSESSMENT: {risk_label}')
    lines.append('=' * 50)

    if paths:
        top = paths[0]
        lines.append('')
        lines.append('MOST CRITICAL ATTACK PATH:')
        lines.append(f'  {top["description"]}')
        lines.append(f'  End-to-end exploit probability: {top["path_probability"] * 100:.0f}%')
        if len(paths) > 1:
            lines.append(f'  ({len(paths)} attack paths found in total)')
    else:
        lines.append('')
        lines.append('No direct internet-to-resource attack path was found in the graph.')
        lines.append('Risk (if any) stems from configuration weaknesses rather than a reachable chain.')

    lines.append('')
    lines.append(f'WHY THIS IS RATED {risk_label.upper()}:')
    if prediction == 0:
        lines.append('  - No exploitable attack paths or dangerous configuration '
                     'combinations were detected.')
    else:
        explained = 0
        for feat in top_features:
            if feat in FEATURE_EXPLANATIONS:
                lines.append(f'  - {FEATURE_EXPLANATIONS[feat]}')
                explained += 1
        if explained == 0:
            lines.append('  - No high-risk configuration patterns were detected.')

    lines.append('')
    lines.append('RECOMMENDED ACTIONS (ranked by impact):')
    for i, rec in enumerate(build_recommendations(scan_data), 1):
        lines.append(f'  {i}. {rec}')

    return '\n'.join(lines)


def build_recommendations(scan_data):
    flat = extract_features(scan_data)
    recs = []
    if flat.get('full_chain_present'):
        recs.append('CRITICAL: Break the attack chain — remove the IAM instance profile from the '
                    'internet-facing EC2, or restrict its inbound access immediately.')
    if flat.get('sg_ssh_open_world', 0) > 0:
        recs.append('HIGH: Restrict SSH (port 22) to specific trusted IP ranges; never allow 0.0.0.0/0.')
    if flat.get('sg_rdp_open_world', 0) > 0:
        recs.append('HIGH: Restrict RDP (port 3389) to a VPN or specific IPs; never expose it to the internet.')
    if flat.get('iam_admin_roles', 0) > 0:
        recs.append('HIGH: Replace AdministratorAccess with a least-privilege policy scoped to required actions.')
    if flat.get('iam_s3_wildcard_roles', 0) > 0:
        recs.append('HIGH: Replace wildcard S3 permissions (s3:*) with specific actions on specific buckets.')
    if flat.get('s3_has_public'):
        recs.append('HIGH: Enable S3 Block Public Access on all buckets and audit bucket policies.')
    if not flat.get('cloudtrail_enabled'):
        recs.append('MEDIUM: Enable CloudTrail in all regions to capture an audit trail of API activity.')
    if flat.get('ec2_imdsv2_disabled', 0) > 0:
        recs.append('MEDIUM: Enforce IMDSv2 (http_tokens=required) to prevent SSRF-based credential theft.')
    if flat.get('ec2_unencrypted_disk', 0) > 0:
        recs.append('LOW: Enable EBS encryption on EC2 root and data volumes.')
    if not recs:
        recs.append('No critical issues found. Maintain monitoring and review IAM policies periodically.')
    return recs


if __name__ == '__main__':
    import sys
    scenario = sys.argv[1] if len(sys.argv) > 1 else 'S10'
    path = f'data/{scenario}_scan.json'
    with open(path) as f:
        scan = json.load(f)
    print(generate_narrative(scan))