#!/usr/bin/env bash
set -euo pipefail
PORT=9456
rm -rf pki storage downloads test_files
python -m secure_drop.ca init --ca-dir pki/ca
python -m secure_drop.ca issue server --role server --ca-dir pki/ca --out-dir pki/server
python -m secure_drop.ca issue alice --role client --ca-dir pki/ca --out-dir pki/alice
python -m secure_drop.ca issue bob --role client --ca-dir pki/ca --out-dir pki/bob
python -m secure_drop.ca issue mallory --role client --ca-dir pki/ca --out-dir pki/mallory
mkdir -p storage test_files downloads
printf 'Secret message from Alice to Bob.\n' > test_files/alice_secret.txt
python -m secure_drop.server --host 127.0.0.1 --port $PORT --storage storage/server > storage/server_stdout.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
sleep 1
C="python -m secure_drop.client --port $PORT"
$C --user alice --cert pki/alice/alice_cert.json --key pki/alice/alice_private_key.pem register
$C --user bob --cert pki/bob/bob_cert.json --key pki/bob/bob_private_key.pem register
$C --user mallory --cert pki/mallory/mallory_cert.json --key pki/mallory/mallory_private_key.pem register
UPLOAD_OUT=$($C --user alice --cert pki/alice/alice_cert.json --key pki/alice/alice_private_key.pem upload --recipient bob --file test_files/alice_secret.txt --expires 3600 --note 'Read this privately, Bob.')
echo "$UPLOAD_OUT"
FILE_ID=$(python -c "import json,sys; print(json.loads(sys.stdin.read())['file_id'])" <<< "$UPLOAD_OUT")
echo "File id: $FILE_ID"
echo '--- Mallory unauthorized download attempt (must fail) ---'
$C --user mallory --cert pki/mallory/mallory_cert.json --key pki/mallory/mallory_private_key.pem download "$FILE_ID" --out downloads/mallory.txt || true
echo '--- Bob list ---'
$C --user bob --cert pki/bob/bob_cert.json --key pki/bob/bob_private_key.pem list
echo '--- Bob download ---'
$C --user bob --cert pki/bob/bob_cert.json --key pki/bob/bob_private_key.pem download "$FILE_ID" --out downloads/bob_secret.txt
echo '--- Server log tail ---'
tail -n 20 storage/server/server.log
