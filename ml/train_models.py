"""
ml/train_models.py  (Phase 6)

Trains and compares four classifiers (Random Forest, XGBoost, Decision Tree,
Logistic Regression) on the combined feature set (flat configuration features
+ graph-structural features). Because the dataset is small (25 scenarios across
5 risk classes, with the Safe class having only 2 samples), the splitting and
cross-validation are adapted so they do not crash on rare classes:

  - test split size and stratification adapt to the smallest class
  - StratifiedKFold n_splits is capped at the smallest class count
  - SHAP feature importance is produced for the best tree model

Outputs:
  ml/models/*.pkl         trained models + scaler
  ml/results/cm_*.png     confusion matrices
  ml/results/shap_summary.png
  ml/results/model_comparison.csv
"""
import os
import warnings
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score

warnings.filterwarnings('ignore')

try:
    import xgboost as xgb
    HAS_XGB = True
except Exception:
    HAS_XGB = False
    print('WARNING: xgboost not installed; skipping XGBoost. Install with: pip install xgboost')

try:
    import shap
    HAS_SHAP = True
except Exception:
    HAS_SHAP = False
    print('WARNING: shap not installed; skipping SHAP plot. Install with: pip install shap')

os.makedirs('ml/models', exist_ok=True)
os.makedirs('ml/results', exist_ok=True)

# ----------------------------------------------------------------------
# Load data
# ----------------------------------------------------------------------
df = pd.read_csv('dataset/labeled_dataset.csv')
df = df.dropna(subset=['risk_level'])
df['risk_level'] = df['risk_level'].astype(int)

# Flat configuration features (Phase 3)
FEATURE_COLS = [
    'ec2_count', 'ec2_internet_facing', 'ec2_with_iam_profile',
    'ec2_imdsv2_disabled', 'ec2_unencrypted_disk', 'ec2_has_public_ip',
    'sg_ssh_open_world', 'sg_rdp_open_world', 'sg_all_traffic_open', 'sg_max_rule_count',
    's3_count', 's3_public_count', 's3_unencrypted_count', 's3_has_public',
    'iam_role_count', 'iam_admin_roles', 'iam_s3_wildcard_roles', 'iam_max_privilege_depth',
    'cloudtrail_enabled',
    'internet_ec2_with_iam', 'open_ssh_with_iam', 'public_s3_with_iam',
    'full_chain_present', 'no_logging_with_exposure',
]

# Graph-structural features (Phase 5 -> bridge). Added so the model learns from
# "structural graph properties combined with learned exploitability signals".
GRAPH_FEATURE_COLS = [
    'graph_num_nodes', 'graph_num_edges', 'graph_num_attack_paths',
    'graph_shortest_path_len', 'graph_max_path_probability',
    'graph_mean_path_probability', 'graph_num_reachable_targets',
    'graph_internet_entry_points', 'graph_max_reachable_privilege',
]

# Only keep columns that actually exist (defensive)
FEATURE_COLS = [c for c in FEATURE_COLS if c in df.columns]
GRAPH_FEATURE_COLS = [c for c in GRAPH_FEATURE_COLS if c in df.columns]
ALL_FEATURES = FEATURE_COLS + GRAPH_FEATURE_COLS

print(f'Using {len(FEATURE_COLS)} flat + {len(GRAPH_FEATURE_COLS)} graph = {len(ALL_FEATURES)} features')

X = df[ALL_FEATURES]
y = df['risk_level']

# Persist the exact feature order so downstream tools (Phase 7 explainer,
# Phase 8 dashboard) build their input rows identically.
import json as _json
with open('ml/models/feature_list.json', 'w') as _f:
    _json.dump(ALL_FEATURES, _f)

CLASS_NAMES = ['Safe', 'Low', 'Medium', 'High', 'Critical']
present_labels = sorted(y.unique())
present_names = [CLASS_NAMES[i] for i in present_labels]

# ----------------------------------------------------------------------
# Small-dataset-safe split configuration
# ----------------------------------------------------------------------
min_class_count = y.value_counts().min()
print(f'Smallest class has {min_class_count} samples; '
      f'class distribution:\n{y.value_counts().sort_index().to_string()}')

# Cap CV folds at the smallest class size (must be >= 2)
n_splits = max(2, min(5, int(min_class_count)))
print(f'Using StratifiedKFold with n_splits={n_splits}')

# Stratified split only works if every class has >= 2 samples. If the smallest
# class has < 2 we fall back to a non-stratified split.
can_stratify = min_class_count >= 2
strat = y if can_stratify else None

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=strat
)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
joblib.dump(scaler, 'ml/models/scaler.pkl')

# ----------------------------------------------------------------------
# Models
# ----------------------------------------------------------------------
models = {
    'Random Forest': RandomForestClassifier(n_estimators=200, random_state=42),
    'Decision Tree': DecisionTreeClassifier(random_state=42, max_depth=6),
    'Logistic Regression': LogisticRegression(max_iter=2000, random_state=42),
}
if HAS_XGB:
    # Do NOT hard-set num_class: with tiny CV folds a class can be absent,
    # which makes a fixed num_class crash/return nan. Letting XGBoost infer
    # the class count per fold keeps cross-validation stable.
    models['XGBoost'] = xgb.XGBClassifier(
        eval_metric='mlogloss', random_state=42, verbosity=0
    )

cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
results = {}

for name, model in models.items():
    print(f'\n=== Training: {name} ===')
    use_scaled = (name == 'Logistic Regression')
    X_tr = X_train_scaled if use_scaled else X_train
    X_te = X_test_scaled if use_scaled else X_test

    # Cross-validation on the training portion
    try:
        cv_scores = cross_val_score(model, X_tr, y_train, cv=cv, scoring='f1_weighted')
        cv_mean, cv_std = cv_scores.mean(), cv_scores.std()
    except Exception as e:
        print(f'  (CV skipped: {e})')
        cv_mean, cv_std = float('nan'), float('nan')
    print(f'  CV F1 (weighted): {cv_mean:.3f} +/- {cv_std:.3f}')

    # Fit on train, evaluate on held-out test
    model.fit(X_tr, y_train)
    preds = model.predict(X_te)
    f1 = f1_score(y_test, preds, average='weighted')
    acc = accuracy_score(y_test, preds)
    print(f'  Test F1: {f1:.3f}   Test Accuracy: {acc:.3f}')
    print(classification_report(y_test, preds, labels=present_labels,
                                target_names=present_names, zero_division=0))

    results[name] = {'cv_f1': cv_mean, 'test_f1': f1, 'accuracy': acc, 'model': model}
    joblib.dump(model, f'ml/models/{name.lower().replace(" ", "_")}.pkl')

    # Confusion matrix
    cm = confusion_matrix(y_test, preds, labels=present_labels)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=present_names, yticklabels=present_names)
    plt.title(f'{name} — Confusion Matrix')
    plt.ylabel('True'); plt.xlabel('Predicted')
    plt.tight_layout()
    plt.savefig(f'ml/results/cm_{name.replace(" ", "_")}.png', bbox_inches='tight')
    plt.close()

# ----------------------------------------------------------------------
# Comparison table
# ----------------------------------------------------------------------
print('\n========== MODEL COMPARISON ==========')
print(f'{"Model":<22}{"CV F1":>9}{"Test F1":>9}{"Accuracy":>10}')
comparison_rows = []
for name, r in sorted(results.items(), key=lambda x: (-x[1]['test_f1'])):
    print(f'{name:<22}{r["cv_f1"]:>9.3f}{r["test_f1"]:>9.3f}{r["accuracy"]:>10.3f}')
    comparison_rows.append({'model': name, 'cv_f1': r['cv_f1'],
                            'test_f1': r['test_f1'], 'accuracy': r['accuracy']})
pd.DataFrame(comparison_rows).to_csv('ml/results/model_comparison.csv', index=False)
print('\nComparison saved: ml/results/model_comparison.csv')

# ----------------------------------------------------------------------
# Feature importance (Random Forest) + SHAP
# ----------------------------------------------------------------------
best_tree = results.get('Random Forest', {}).get('model')
if best_tree is not None:
    importances = pd.Series(best_tree.feature_importances_, index=ALL_FEATURES)
    importances = importances.sort_values(ascending=False)
    print('\nTop 12 features by Random Forest importance:')
    print(importances.head(12).to_string())

    # Highlight whether graph features matter
    graph_imp = importances[importances.index.isin(GRAPH_FEATURE_COLS)].sum()
    print(f'\nGraph features account for {graph_imp*100:.1f}% of total importance.')

    plt.figure(figsize=(8, 6))
    importances.head(15).iloc[::-1].plot(kind='barh', color='steelblue')
    plt.title('Top 15 Feature Importances (Random Forest)')
    plt.tight_layout()
    plt.savefig('ml/results/feature_importance.png', bbox_inches='tight')
    plt.close()
    print('Feature importance plot saved: ml/results/feature_importance.png')

    if HAS_SHAP:
        try:
            explainer = shap.TreeExplainer(best_tree)
            shap_values = explainer.shap_values(X_test)
            plt.figure()
            shap.summary_plot(shap_values, X_test, feature_names=ALL_FEATURES, show=False)
            plt.savefig('ml/results/shap_summary.png', bbox_inches='tight')
            plt.close()
            print('SHAP summary plot saved: ml/results/shap_summary.png')
        except Exception as e:
            print(f'(SHAP plot skipped: {e})')

print('\nPhase 6 complete. Models in ml/models/, plots/metrics in ml/results/.')