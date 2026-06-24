"""
dashboard/app.py  (Phase 8 — Dashboard)

A Streamlit UI that ties the whole GraphShield pipeline together. The analyst
loads a scenario scan (or a saved scan JSON), and the dashboard shows:
  - headline risk level predicted by the trained model
  - resource KPIs (EC2 / S3 / IAM / Lambda / RDS counts)
  - the ranked attack paths found in the graph
  - the plain-English narrative (Phase 7 explainability)
  - ranked remediation actions
  - the underlying feature vector (flat + graph)

Run with:   streamlit run dashboard/app.py
Opens at:   http://localhost:8501
"""
import os
import sys
import json
import glob

import pandas as pd
import streamlit as st

# Make project modules importable when run via `streamlit run`
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from normalizer.feature_extractor import extract_features
from graph.graph_builder import AttackGraphBuilder
from graph.graph_features import compute_graph_features
from explainer.narrative_generator import generate_narrative

st.set_page_config(page_title='GraphShield', page_icon='🛡️', layout='wide')

RISK_COLORS = {
    'Safe': '#2e7d32', 'Low Risk': '#9e9d24', 'Medium Risk': '#f9a825',
    'High Risk': '#ef6c00', 'Critical': '#c62828',
}
RISK_NAMES = {0: 'Safe', 1: 'Low Risk', 2: 'Medium Risk', 3: 'High Risk', 4: 'Critical'}

st.title('🛡️ GraphShield')
st.caption('Explainable graph-based cloud attack-path intelligence with ML-driven risk prioritization')


# ---------------------------------------------------------------- helpers
def load_scan_options():
    files = sorted(glob.glob('data/*_scan.json'))
    return {os.path.basename(f).replace('_scan.json', ''): f for f in files}


def predict_risk(scan_data):
    import joblib
    model = joblib.load('ml/models/random_forest.pkl')
    with open('ml/models/feature_list.json') as f:
        feats = json.load(f)
    flat = extract_features(scan_data)
    graph = compute_graph_features(scan_data)
    combined = {**flat, **graph}
    row = pd.DataFrame([{f: combined.get(f, 0) for f in feats}])[feats]
    pred = int(model.predict(row)[0])
    return RISK_NAMES.get(pred, 'Unknown'), combined


# ---------------------------------------------------------------- sidebar
st.sidebar.header('Load a scan')
scan_options = load_scan_options()

scan_data = None
if scan_options:
    choice = st.sidebar.selectbox('Choose a scanned scenario', list(scan_options.keys()))
    if choice:
        with open(scan_options[choice]) as f:
            scan_data = json.load(f)
else:
    st.sidebar.info('No scan files found in data/. Upload one below.')

uploaded = st.sidebar.file_uploader('Or upload a scan JSON', type='json')
if uploaded:
    scan_data = json.load(uploaded)


# ---------------------------------------------------------------- main
if scan_data is None:
    st.info('Select a scanned scenario from the sidebar (or upload a scan JSON) to begin.')
    st.stop()

# Build graph + paths
builder = AttackGraphBuilder()
builder.build_from_scan(scan_data)
paths = builder.find_attack_paths()

# Predict risk
try:
    risk_label, combined = predict_risk(scan_data)
except Exception as e:
    risk_label, combined = 'Model not trained', {}
    st.warning(f'Could not load the trained model — run ml/train_models.py first. ({e})')

# Headline risk banner
color = RISK_COLORS.get(risk_label, '#555')
st.markdown(
    f"<div style='background:{color};padding:18px;border-radius:10px;'>"
    f"<h2 style='color:white;margin:0;'>Risk Assessment: {risk_label}</h2>"
    f"<p style='color:white;margin:4px 0 0 0;'>Scenario: {scan_data.get('scenario_id','(uploaded)')}</p>"
    f"</div>",
    unsafe_allow_html=True,
)

st.write('')

# KPI row
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric('EC2', len(scan_data.get('ec2_instances', [])))
c2.metric('S3 buckets', len(scan_data.get('s3_buckets', [])))
c3.metric('IAM roles', len(scan_data.get('iam_roles', [])))
c4.metric('Lambda', len(scan_data.get('lambda_functions', [])))
c5.metric('Attack paths', len(paths))

st.divider()

# Two columns: attack paths + narrative
left, right = st.columns(2)

with left:
    st.subheader('Attack paths')
    if paths:
        for i, p in enumerate(paths[:6], 1):
            prob = p['path_probability']
            badge = '🔴' if prob > 0.7 else ('🟠' if prob > 0.4 else '🟢')
            st.markdown(f"**{badge} Path {i} — {prob*100:.0f}% exploit probability**")
            st.code(' → '.join(p['path']), language=None)
    else:
        st.success('No internet-to-resource attack path found in the graph.')

with right:
    st.subheader('Security intelligence')
    try:
        narrative = generate_narrative(scan_data)
        st.text(narrative)
    except Exception as e:
        st.warning(f'Narrative unavailable (train the model first): {e}')

st.divider()

# Feature vector expander
with st.expander('Underlying feature vector (flat + graph)'):
    if combined:
        graph_cols = {k: v for k, v in combined.items() if k.startswith('graph_')}
        flat_cols = {k: v for k, v in combined.items()
                     if not k.startswith('graph_') and k != 'scenario_id'}
        st.markdown('**Configuration features**')
        st.dataframe(pd.DataFrame([flat_cols]))
        st.markdown('**Graph-structural features**')
        st.dataframe(pd.DataFrame([graph_cols]))

st.caption('GraphShield — batch proof-of-concept on AWS. '
           'Continuous operation, multi-cloud, and CVE enrichment are future work.')