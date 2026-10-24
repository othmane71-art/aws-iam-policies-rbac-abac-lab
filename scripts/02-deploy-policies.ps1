# Déploie les données de test, les politiques, le rôle temporaire et la règle ABAC. Idempotent.
# Prérequis : scripts/01-provision-identities.ps1 exécuté.

$env:AWS_ACCESS_KEY_ID = "test"
$env:AWS_SECRET_ACCESS_KEY = "test"
$env:AWS_DEFAULT_REGION = "eu-west-3"
$env:AWS_ENDPOINT_URL = "http://localhost:4566"

$B = "iam-policies-sensor-1"
$ACC = aws sts get-caller-identity --query Account --output text
$dir = (Resolve-Path (Join-Path $PSScriptRoot "../policies")).Path

# Données : trois dossiers de sensibilités différentes
aws s3 mb "s3://$B" | Out-Null
$tmp = Join-Path $env:TEMP "iam-lab-data"
New-Item -ItemType Directory -Force $tmp | Out-Null
"Rapport T1"           | Set-Content -Encoding ascii "$tmp/q1.txt"
"Salaires 2026"        | Set-Content -Encoding ascii "$tmp/salaires.txt"
"Information publique" | Set-Content -Encoding ascii "$tmp/info.txt"
aws s3 cp "$tmp/q1.txt"       "s3://$B/rapports/q1.txt"
aws s3 cp "$tmp/salaires.txt" "s3://$B/finance/salaires.txt"
aws s3 cp "$tmp/info.txt"     "s3://$B/public/info.txt"

function Ensure-Policy($name, $file) {
  $arn = "arn:aws:iam::${ACC}:policy/$name"
  aws iam get-policy --policy-arn $arn 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) {
    aws iam create-policy --policy-name $name --policy-document "file://$dir/$file" | Out-Null
  }
  return $arn
}

# RBAC : une politique par groupe
aws iam attach-group-policy --group-name auditeurs --policy-arn (Ensure-Policy "lecture-rapports" "lecture-rapports.json")
aws iam attach-group-policy --group-name developpeurs --policy-arn (Ensure-Policy "ecriture-public" "ecriture-public.json")

# Rôle temporaire : confiance, permissions, droit de l'assumer
aws iam get-role --role-name lecteur-finance 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
  aws iam create-role --role-name lecteur-finance --assume-role-policy-document "file://$dir/confiance-lecteur-finance.json" | Out-Null
}
aws iam put-role-policy --role-name lecteur-finance --policy-name lecture-finance --policy-document "file://$dir/lecture-finance.json"
aws iam put-user-policy --user-name claire --policy-name assume-lecteur-finance --policy-document "file://$dir/assume-lecteur-finance.json"

# ABAC : une règle comparant les étiquettes team
aws iam put-user-policy --user-name alice --policy-name abac-files --policy-document "file://$dir/abac-files.json"

Write-Host "Déploiement terminé."
