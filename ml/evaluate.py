"""
ml/evaluate.py  (Phase 9 — Evaluation)

Proves the research contribution: GraphShield (graph-aware ML) versus a
conventional rule-based scanner that treats every finding in isolation.

We compare on the SAME labeled dataset and report:
  1. Risk-classification quality (weighted F1, accuracy)
  2. Alert-noise reduction  (how often each approach raises a false
     High/Critical alarm on a genuinely Safe/Low configuration)
  3. Attack-path detection  (does the graph find the chains the
     rule-based scanner is structurally blind to?)

Outputs:
  ml/results/evaluation_report.txt
  ml/results/baseline_vs_graphshield.png
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.metrics import f1_score, accuracy_score, classification_report

os.makedirs('ml/results', exist_ok=True)

CLASS_NAMES = ['Safe', 'Low', 'Medium', 'High', 'Critical']

# ----------------------------------------------------------------------
# Load data + the trained GraphShield model
# ----------------------------------------------------------------------
df = pd.read_csv('dataset/labeled_dataset.csv').dropna(subset=['risk_level'])
df['risk_level'] = df['risk_level'].astype(int)

with open('ml/models/feature_list.json') as f:
    FEATURES = json.load(f)

X = df[FEATURES]
y_true = df['risk_level'].values

model = joblib.load('ml/models/random_forest.pkl')
y_graphshield = model.predict(X)


# ----------------------------------------------------------------------
# Baseline: conventional rule-based scanner
# Counts isolated findings, ignores how they chain together. This mirrors
# how a simple CSPM rule engine assigns severity.
# ----------------------------------------------------------------------
def baseline_predict(row):
    score = 0
    if row.get('sg_ssh_open_world', 0) > 0:
        score += 1
    if row.get('sg_rdp_open_world', 0) > 0:
        score += 1
    if row.get('s3_has_public', 0):
        score += 1
    if row.get('iam_admin_roles', 0) > 0:
        score += 1
    if row.get('iam_s3_wildcard_roles', 0) > 0:
        score += 1
    if not row.get('cloudtrail_enabled', 0):
        score += 1
    return min(score, 4)


y_baseline = df.apply(baseline_predict, axis=1).values

# ----------------------------------------------------------------------
# 1. Classification quality
# ----------------------------------------------------------------------
gs_f1 = f1_score(y_true, y_graphshield, average='weighted')
gs_acc = accuracy_score(y_true, y_graphshield)
base_f1 = f1_score(y_true, y_baseline, average='weighted')
base_acc = accuracy_score(y_true, y_baseline)
improvement = (gs_f1 - base_f1) * 100

present = sorted(set(y_true) | set(y_graphshield) | set(y_baseline))
present_names = [CLASS_NAMES[i] for i in present]

# ----------------------------------------------------------------------
# 2. Alert noise: false High/Critical (>=3) on genuinely low-risk (<=1) configs
# ----------------------------------------------------------------------
low_risk_mask = y_true <= 1
n_low = max(1, low_risk_mask.sum())
gs_false_alerts = ((np.array(y_graphshield)[low_risk_mask] >= 3).sum()) / n_low
base_false_alerts = ((np.array(y_baseline)[low_risk_mask] >= 3).sum()) / n_low

# ----------------------------------------------------------------------
# 3. Attack-path detection (graph-only capability the baseline cannot do)
# ----------------------------------------------------------------------
paths_detected = int((df.get('graph_num_attack_paths', pd.Series([0])) > 0).sum())
total_scenarios = len(df)

# ----------------------------------------------------------------------
# Build report
# ----------------------------------------------------------------------
lines = []
lines.append('=' * 60)
lines.append('GRAPHSHIELD vs RULE-BASED BASELINE — EVALUATION REPORT')
lines.append('=' * 60)
lines.append('')
lines.append(f'Dataset: {total_scenarios} scenarios, {len(FEATURES)} features '
             f'({len([f for f in FEATURES if f.startswith("graph_")])} graph-derived)')
lines.append('')
lines.append('--- 1. RISK CLASSIFICATION QUALITY ---')
lines.append(f'{"Approach":<28}{"Weighted F1":>14}{"Accuracy":>12}')
lines.append(f'{"GraphShield (graph + ML)":<28}{gs_f1:>14.3f}{gs_acc:>12.3f}')
lines.append(f'{"Rule-based baseline":<28}{base_f1:>14.3f}{base_acc:>12.3f}')
lines.append(f'{"Improvement":<28}{("+%.1f%%" % improvement):>14}')
lines.append('')
lines.append('--- 2. ALERT NOISE (false High/Critical on low-risk configs) ---')
lines.append(f'GraphShield false critical-alert rate: {gs_false_alerts*100:.1f}%')
lines.append(f'Baseline    false critical-alert rate: {base_false_alerts*100:.1f}%')
if base_false_alerts > 0:
    reduction = (1 - gs_false_alerts / base_false_alerts) * 100 if base_false_alerts else 0
    lines.append(f'Noise reduction: {reduction:.1f}%')
lines.append('')
lines.append('--- 3. ATTACK-PATH DETECTION (graph capability) ---')
lines.append(f'Scenarios with at least one INTERNET->target attack path: '
             f'{paths_detected}/{total_scenarios}')
lines.append('The rule-based baseline cannot model multi-step attack paths at all; '
             'it only counts isolated findings.')
lines.append('')
lines.append('--- GraphShield per-class report ---')
lines.append(classification_report(y_true, y_graphshield, labels=present,
                                    target_names=present_names, zero_division=0))
lines.append('--- Baseline per-class report ---')
lines.append(classification_report(y_true, y_baseline, labels=present,
                                    target_names=present_names, zero_division=0))

report = '\n'.join(lines)
print(report)
with open('ml/results/evaluation_report.txt', 'w') as f:
    f.write(report)
print('Report saved: ml/results/evaluation_report.txt')

# ----------------------------------------------------------------------
# Comparison chart
# ----------------------------------------------------------------------
fig, axes = plt.subplots(1, 2, figsize=(12, 5))

# Left: F1 / accuracy bars
metrics = ['Weighted F1', 'Accuracy']
gs_vals = [gs_f1, gs_acc]
base_vals = [base_f1, base_acc]
xpos = np.arange(len(metrics))
w = 0.35
axes[0].bar(xpos - w/2, gs_vals, w, label='GraphShield', color='steelblue')
axes[0].bar(xpos + w/2, base_vals, w, label='Rule-based', color='indianred')
axes[0].set_xticks(xpos); axes[0].set_xticklabels(metrics)
axes[0].set_ylim(0, 1); axes[0].set_title('Classification Quality')
axes[0].legend(); axes[0].grid(axis='y', alpha=0.3)

# Right: false-alert rate
axes[1].bar(['GraphShield', 'Rule-based'],
            [gs_false_alerts*100, base_false_alerts*100],
            color=['steelblue', 'indianred'])
axes[1].set_ylabel('False critical-alert rate (%)')
axes[1].set_title('Alert Noise on Low-Risk Configs')
axes[1].grid(axis='y', alpha=0.3)

plt.tight_layout()
plt.savefig('ml/results/baseline_vs_graphshield.png', bbox_inches='tight')
print('Chart saved: ml/results/baseline_vs_graphshield.png')