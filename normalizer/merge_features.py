"""
merge_features.py  (Phase 6 prep)

Merges three tables into the final ML training set:
  1. dataset/features.csv         (flat config features, Phase 3)
  2. dataset/graph_features.csv   (graph-structural features, Phase 5 bridge)
  3. labels                       (risk_level etc., Phase 4)

Output: dataset/labeled_dataset.csv  with BOTH flat and graph features + labels.
"""
import pandas as pd

flat = pd.read_csv('dataset/features.csv')
graph = pd.read_csv('dataset/graph_features.csv')

merged = flat.merge(graph, on='scenario_id', how='left')
merged.to_csv('dataset/features_combined.csv', index=False)
print(f'Combined feature table: {len(merged)} rows, {len(merged.columns)} columns')
print('Graph columns added:', [c for c in graph.columns if c != 'scenario_id'])
