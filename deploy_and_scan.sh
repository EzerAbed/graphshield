#!/bin/bash
# GraphShield — deploy, scan, destroy all scenarios

GRAPHSHIELD_DIR=~/Desktop/Lab5/graphshield
SCANNER=$GRAPHSHIELD_DIR/scanner/aws_scanner.py
SCENARIOS_DIR=$GRAPHSHIELD_DIR/terraform/scenarios

cd $GRAPHSHIELD_DIR
source venv/Scripts/activate

# List of all scenarios and their IDs
declare -A SCENARIOS=(
  ["S01_baseline_secure"]="S01"
  ["S02_public_s3_only"]="S02"
  ["S03_open_ssh_only"]="S03"
  ["S04_no_cloudtrail"]="S04"
  ["S05_weak_iam_only"]="S05"
  ["S06_public_s3_weak_iam"]="S06"
  ["S07_open_ssh_ec2_credentials"]="S07"
  ["S08_no_mfa_admin_user"]="S08"
  ["S09_exposed_lambda"]="S09"
  ["S10_classic_chain_1"]="S10"
  ["S11_classic_chain_2"]="S11"
  ["S12_lateral_movement"]="S12"
  ["S13_privilege_escalation"]="S13"
  ["S14_full_compromise"]="S14"
  ["S15_open_rdp_admin"]="S15"
  ["S16_public_s3_no_protection"]="S16"
  ["S17_network_exposure_no_iam"]="S17"
  ["S18_orphaned_admin_public_s3"]="S18"
  ["S19_hygiene_debt"]="S19"
)

for FOLDER in "${!SCENARIOS[@]}"; do
  SCENARIO_ID="${SCENARIOS[$FOLDER]}"
  SCENARIO_PATH="$SCENARIOS_DIR/$FOLDER"

  echo ""
  echo "========================================"
  echo "Processing $SCENARIO_ID — $FOLDER"
  echo "========================================"

  cd $SCENARIO_PATH

  # Init only if not already done
  if [ ! -d ".terraform" ]; then
    echo "Initializing Terraform..."
    terraform init -no-color
  fi

  # Deploy
  echo "Deploying $SCENARIO_ID..."
  terraform apply -auto-approve -no-color
  if [ $? -ne 0 ]; then
    echo "ERROR: Deploy failed for $SCENARIO_ID — skipping"
    cd $GRAPHSHIELD_DIR
    continue
  fi

  # Wait a moment for resources to stabilize
  sleep 10

  # Scan
  echo "Scanning $SCENARIO_ID..."
  cd $GRAPHSHIELD_DIR
  python $SCANNER $SCENARIO_ID

  # Destroy
  echo "Destroying $SCENARIO_ID..."
  cd $SCENARIO_PATH
  terraform destroy -auto-approve -no-color
  if [ $? -ne 0 ]; then
    echo "WARNING: Destroy failed for $SCENARIO_ID — check AWS console manually!"
  fi

  echo "Done: $SCENARIO_ID"
  cd $GRAPHSHIELD_DIR

  # Small pause between scenarios
  sleep 5
done

echo ""
echo "========================================"
echo "All scenarios processed!"
echo "Scan files in: data/"
ls $GRAPHSHIELD_DIR/data/
echo "========================================"