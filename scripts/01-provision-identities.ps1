# Reconstruit les identités : utilisateurs, groupes, profils CLI.
# Idempotent : peut être relancé sans créer de clés en double.
# Prérequis : LocalStack démarré avec ENFORCE_IAM=1 sur 127.0.0.1:4566. Aucun secret n'est stocké dans ce script.

$env:AWS_ACCESS_KEY_ID = "test"
$env:AWS_SECRET_ACCESS_KEY = "test"
$env:AWS_DEFAULT_REGION = "eu-west-3"
$env:AWS_ENDPOINT_URL = "http://localhost:4566"

$users  = @{ alice = "data"; bob = "audit"; claire = "reseau" }
$groups = @{ developpeurs = "alice"; auditeurs = "bob"; "admins-reseau" = "claire" }

foreach ($u in $users.Keys) {
  aws iam get-user --user-name $u 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) {
    aws iam create-user --user-name $u --tags "Key=team,Value=$($users[$u])" | Out-Null
    $k = aws iam create-access-key --user-name $u --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text
    $a, $s = $k -split "\s+"
    aws configure set aws_access_key_id $a --profile $u
    aws configure set aws_secret_access_key $s --profile $u
    aws configure set region eu-west-3 --profile $u
  } else {
    Write-Host "$u existe déjà : aucune nouvelle clé créée"
  }
}

foreach ($g in $groups.Keys) {
  aws iam get-group --group-name $g 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) { aws iam create-group --group-name $g | Out-Null }
  aws iam add-user-to-group --user-name $($groups[$g]) --group-name $g
}

aws iam list-users --query "Users[].{Nom:UserName,Equipe:Tags[0].Value}" --output table
