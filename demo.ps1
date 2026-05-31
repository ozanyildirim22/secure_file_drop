$ErrorActionPreference = "Stop"
$PORT = 9456
if (Test-Path -Path pki) { Remove-Item -Recurse -Force pki }
if (Test-Path -Path storage) { Remove-Item -Recurse -Force storage }
if (Test-Path -Path downloads) { Remove-Item -Recurse -Force downloads }
if (Test-Path -Path test_files) { Remove-Item -Recurse -Force test_files }

python -m secure_drop.ca init --ca-dir pki/ca
python -m secure_drop.ca issue server --role server --ca-dir pki/ca --out-dir pki/server
python -m secure_drop.ca issue alice --role client --ca-dir pki/ca --out-dir pki/alice
python -m secure_drop.ca issue bob --role client --ca-dir pki/ca --out-dir pki/bob
python -m secure_drop.ca issue mallory --role client --ca-dir pki/ca --out-dir pki/mallory

New-Item -ItemType Directory -Force -Path storage | Out-Null
New-Item -ItemType Directory -Force -Path test_files | Out-Null
New-Item -ItemType Directory -Force -Path downloads | Out-Null

Set-Content -Path test_files/alice_secret.txt -Value "Secret message from Alice to Bob." -NoNewline

$serverJob = Start-Job -ScriptBlock {
    Set-Location $using:PWD
    python -m secure_drop.server --host 127.0.0.1 --port $using:PORT --storage storage/server > storage/server_stdout.log 2>&1
}

Start-Sleep -Seconds 2

try {
    $C = "python -m secure_drop.client --port $PORT"

    Invoke-Expression "$C --user alice --cert pki/alice/alice_cert.json --key pki/alice/alice_private_key.pem register"
    Invoke-Expression "$C --user bob --cert pki/bob/bob_cert.json --key pki/bob/bob_private_key.pem register"
    Invoke-Expression "$C --user mallory --cert pki/mallory/mallory_cert.json --key pki/mallory/mallory_private_key.pem register"

    $UPLOAD_OUT = Invoke-Expression "$C --user alice --cert pki/alice/alice_cert.json --key pki/alice/alice_private_key.pem upload --recipient bob --file test_files/alice_secret.txt --expires 3600 --note 'Read this privately, Bob.'"
    Write-Output $UPLOAD_OUT

    $FILE_ID = $UPLOAD_OUT | python -c "import json,sys; print(json.loads(sys.stdin.read())['file_id'])"
    Write-Output "File id: $FILE_ID"

    Write-Output '--- Mallory unauthorized download attempt (must fail) ---'
    try {
        Invoke-Expression "$C --user mallory --cert pki/mallory/mallory_cert.json --key pki/mallory/mallory_private_key.pem download `"$FILE_ID`" --out downloads/mallory.txt"
    } catch {
        Write-Output "Mallory download failed as expected."
    }

    Write-Output '--- Bob list ---'
    Invoke-Expression "$C --user bob --cert pki/bob/bob_cert.json --key pki/bob/bob_private_key.pem list"

    Write-Output '--- Bob download ---'
    Invoke-Expression "$C --user bob --cert pki/bob/bob_cert.json --key pki/bob/bob_private_key.pem download `"$FILE_ID`" --out downloads/bob_secret.txt"

    Write-Output '--- Server log tail ---'
    Get-Content storage/server/server.log -Tail 20
} finally {
    Stop-Job $serverJob
    Remove-Job $serverJob
}
