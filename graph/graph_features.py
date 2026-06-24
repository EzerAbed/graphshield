"""
graph_features.py  (Phase 5 -> Phase 6 bridge)

Closes the gap between the attack graph and the ML model. For each scanned
scenario we build the attack graph, then derive STRUCTURAL features that
describe the shape of the attack surface (how many ways in, how short the
paths, how reachable the sensitive resources are). These features are then
merged into the flat feature table so the ML model in Phase 6 learns from
"structural graph properties combined with learned exploitability signals"
exactly as the GraphShield abstract describes.
"""
import json
import os
import pandas as pd
import networkx as nx

from graph.graph_builder import AttackGraphBuilder


def compute_graph_features(scan_data):
    """Return a dict of graph-structural features for one scenario."""
    builder = AttackGraphBuilder()
    G = builder.build_from_scan(scan_data)
    paths = builder.find_attack_paths()

    sid = scan_data['scenario_id']

    # Basic graph size
    num_nodes = G.number_of_nodes()
    num_edges = G.number_of_edges()

    # Attack-path structural properties
    num_attack_paths = len(paths)
    if paths:
        path_lengths = [p['length'] for p in paths]
        path_probs = [p['path_probability'] for p in paths]
        shortest_path_len = min(path_lengths)
        max_path_probability = max(path_probs)
        mean_path_probability = sum(path_probs) / len(path_probs)
    else:
        # No INTERNET -> sensitive-resource path exists
        shortest_path_len = 0
        max_path_probability = 0.0
        mean_path_probability = 0.0

    # How many distinct sensitive resources (S3/RDS) are reachable from INTERNET
    reachable_targets = set()
    for p in paths:
        reachable_targets.add(p['target'])
    num_reachable_targets = len(reachable_targets)

    # Out-degree of INTERNET = number of direct entry points (exposed front doors)
    internet_out_degree = G.out_degree('INTERNET') if 'INTERNET' in G else 0

    # Highest privilege depth reachable along any attack path
    max_reachable_privilege = 0
    for p in paths:
        for node in p['path']:
            depth = G.nodes[node].get('privilege_depth', 0) if node in G else 0
            if depth > max_reachable_privilege:
                max_reachable_privilege = depth

    return {
        'scenario_id': sid,
        'graph_num_nodes': num_nodes,
        'graph_num_edges': num_edges,
        'graph_num_attack_paths': num_attack_paths,
        'graph_shortest_path_len': shortest_path_len,
        'graph_max_path_probability': round(max_path_probability, 4),
        'graph_mean_path_probability': round(mean_path_probability, 4),
        'graph_num_reachable_targets': num_reachable_targets,
        'graph_internet_entry_points': internet_out_degree,
        'graph_max_reachable_privilege': max_reachable_privilege,
    }


def build_graph_feature_table(data_dir='data', output_path='dataset/graph_features.csv'):
    rows = []
    for fname in sorted(os.listdir(data_dir)):
        if not fname.endswith('_scan.json'):
            continue
        with open(os.path.join(data_dir, fname)) as f:
            scan = json.load(f)
        feats = compute_graph_features(scan)
        rows.append(feats)
        print(f'Graph features: {fname} -> {feats["graph_num_attack_paths"]} paths, '
              f'max_prob={feats["graph_max_path_probability"]}')
    df = pd.DataFrame(rows)
    os.makedirs('dataset', exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f'\nGraph feature table saved: {output_path} ({len(df)} rows)')
    return df


if __name__ == '__main__':
    build_graph_feature_table()
