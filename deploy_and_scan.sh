#!/bin/bash
export PATH="/c/tools/terraform:$PATH"   # adjust if your terraform.exe is elsewhere

GRAPHSHIELD_DIR=~/Desktop/graphshield
SCANNER=$GRAPHSHIELD_DIR/scanner/aws_scanner.py
SCENARIOS_DIR=$GRAPHSHIELD_DIR/terraform/scenarios

# Call the venv's python directly — do NOT rely on `activate` in a
# non-interactive shell (that's what made every scan fail last run).
PYTHON="$GRAPHSHIELD_DIR/venv/Scripts/python.exe"

cd "$GRAPHSHIELD_DIR" || { echo "FATAL: cannot cd to $GRAPHSHIELD_DIR"; exit 1; }

# Sanity check before doing anything expensive
"$PYTHON" -c "import boto3" 2>/dev/null
if [ $? -ne 0 ]; then
  echo "FATAL: boto3 not importable by $PYTHON — aborting before deploy."
  echo "Run: $PYTHON -m pip install boto3"
  exit 1
fi

# Ordered list — S10 through S25 only
SCENARIOS=(
  "S10_classic_chain_1:S10"
  "S11_classic_chain_2:S11"
  "S12_lateral_movement:S12"
  "S13_privilege_escalation:S13"
  "S14_full_compromise:S14"
  "S15_open_rdp_admin:S15"
  "S16_public_s3_no_protection:S16"
  "S17_network_exposure_no_iam:S17"
  "S18_orphaned_admin_public_s3:S18"
  "S19_hygiene_debt:S19"
  "S20_secure_multi_resource:S20"
  "S21_public_s3_with_logging:S21"
  "S22_readonly_iam_internet_ec2:S22"
  "S23_wildcard_trust_policy:S23"
  "S24_public_lambda_scoped:S24"
  "S25_partial_mitigations:S25"
)

for ENTRY in "${SCENARIOS[@]}"; do
  FOLDER="${ENTRY%%:*}"
  SCENARIO_ID="${ENTRY##*:}"
  SCENARIO_PATH="$SCENARIOS_DIR/$FOLDER"

  echo ""
  echo "========================================"
  echo "Processing $SCENARIO_ID — $FOLDER"
  echo "========================================"

  cd "$SCENARIO_PATH" || { echo "ERROR: folder $FOLDER not found — skipping"; continue; }

  if [ ! -d ".terraform" ]; then
    echo "Initializing Terraform..."
    terraform init -no-color
  fi

  echo "Deploying $SCENARIO_ID..."
  terraform apply -auto-approve -no-color
  if [ $? -ne 0 ]; then
    echo "ERROR: Deploy failed for $SCENARIO_ID — running destroy to clean up partial resources"
    terraform destroy -auto-approve -no-color
    cd "$GRAPHSHIELD_DIR"
    continue
  fi

  echo "Waiting 15s for resources to stabilize..."
  sleep 15

  echo "Scanning $SCENARIO_ID..."
  cd "$GRAPHSHIELD_DIR"
  "$PYTHON" "$SCANNER" "$SCENARIO_ID"

  echo "Destroying $SCENARIO_ID..."
  cd "$SCENARIO_PATH"
  terraform destroy -auto-approve -no-color
  if [ $? -ne 0 ]; then
    echo "WARNING: Destroy failed for $SCENARIO_ID — CHECK AWS CONSOLE MANUALLY"
  fi

  echo "Done: $SCENARIO_ID"
  cd "$GRAPHSHIELD_DIR"
  sleep 5
done

echo ""
echo "========================================"
echo "All scenarios processed!"
ls "$GRAPHSHIELD_DIR/data/"
echo "========================================"