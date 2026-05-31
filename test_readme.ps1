$ErrorActionPreference = "Continue"
$PORT = 9456
$C = "python -m secure_drop.client --port $PORT"

if (!(Test-Path test_files)) { New-Item -ItemType Directory -Force test_files | Out-Null }
if (!(Test-Path downloads)) { New-Item -ItemType Directory -Force downloads | Out-Null }
Set-Content -Path test_files/alice_secret.txt -Value "Alice's secret message" -NoNewline

Write-Host "`n=== 9.9 One-time download test ==="
$UPLOAD_OUT = Invoke-Expression "$C --user alice --cert pki/alice/alice_cert.json --key pki/alice/alice_private_key.pem upload --recipient bob --file test_files/alice_secret.txt --expires 3600"
$FILE_ID = $UPLOAD_OUT | python -c "import json,sys; print(json.loads(sys.stdin.read())['file_id'])"
Write-Host "Uploaded file for one-time download test, ID: $FILE_ID"
Write-Host "Bob downloading for the first time (should succeed)..."
Invoke-Expression "$C --user bob --cert pki/bob/bob_cert.json --key pki/bob/bob_private_key.pem download `"$FILE_ID`" --out downloads/bob_first.txt"
Write-Host "Bob downloading for the second time (should fail)..."
Invoke-Expression "$C --user bob --cert pki/bob/bob_cert.json --key pki/bob/bob_private_key.pem download `"$FILE_ID`" --out downloads/bob_second.txt"

Write-Host "`n=== 9.10 Expiration test ==="
$UPLOAD_OUT = Invoke-Expression "$C --user alice --cert pki/alice/alice_cert.json --key pki/alice/alice_private_key.pem upload --recipient bob --file test_files/alice_secret.txt --expires 1"
$EXP_FILE_ID = $UPLOAD_OUT | python -c "import json,sys; print(json.loads(sys.stdin.read())['file_id'])"
Write-Host "Uploaded file with 1 second expiration, ID: $EXP_FILE_ID"
Write-Host "Waiting 2 seconds..."
Start-Sleep -Seconds 2
Write-Host "Bob downloading expired file (should fail)..."
Invoke-Expression "$C --user bob --cert pki/bob/bob_cert.json --key pki/bob/bob_private_key.pem download `"$EXP_FILE_ID`" --out downloads/expired.txt"

Write-Host "`n=== 9.11 Revocation test ==="
$UPLOAD_OUT = Invoke-Expression "$C --user alice --cert pki/alice/alice_cert.json --key pki/alice/alice_private_key.pem upload --recipient bob --file test_files/alice_secret.txt --expires 3600"
$REV_FILE_ID = $UPLOAD_OUT | python -c "import json,sys; print(json.loads(sys.stdin.read())['file_id'])"
Write-Host "Uploaded file for revocation, ID: $REV_FILE_ID"
Write-Host "Alice revokes the file..."
Invoke-Expression "$C --user alice --cert pki/alice/alice_cert.json --key pki/alice/alice_private_key.pem revoke `"$REV_FILE_ID`""
Write-Host "Bob downloading revoked file (should fail)..."
Invoke-Expression "$C --user bob --cert pki/bob/bob_cert.json --key pki/bob/bob_private_key.pem download `"$REV_FILE_ID`" --out downloads/revoked.txt"
