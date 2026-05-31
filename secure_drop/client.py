import argparse, os, socket, uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .common import *
from .handshake import client_handshake, load_ca_public

def connect(args):
    cert = read_json(args.cert); key = load_private_key(args.key)
    sock = socket.create_connection((args.host, args.port), timeout=10)
    chan, sid = client_handshake(sock, args.user, cert, key, args.ca_public)
    return sock, chan, cert, key

def req_base():
    return {"request_id": uuid.uuid4().hex, "timestamp": now()}

def send_req(chan, typ, **fields):
    r = req_base(); r['type'] = typ; r.update(fields); chan.send(r); return chan.recv()

def get_cert(chan, user):
    res = send_req(chan, 'GET_CERT', user=user)
    if not res.get('ok'): raise SystemExit('GET_CERT failed: ' + res.get('error','unknown'))
    return res['certificate']

def cmd_register(args):
    # Registration with the server is implicit: a successful authenticated connection stores the cert.
    sock, chan, *_ = connect(args)
    print(f"Registered/announced certificate for user '{args.user}' to the server.")
    sock.close()

def cmd_upload(args):
    sock, chan, cert, key = connect(args)
    recipient_cert = get_cert(chan, args.recipient)
    ca_pub = load_ca_public(args.ca_public)
    ok, msg = verify_certificate(recipient_cert, ca_pub, expected_role='client', expected_subject=args.recipient)
    if not ok: raise SystemExit('recipient certificate invalid: ' + msg)
    plaintext = open(args.file, 'rb').read()
    file_id = uuid.uuid4().hex
    upload_ts = now(); expires_at = upload_ts + args.expires
    file_key = os.urandom(32)
    iv = os.urandom(12)
    aad = canonical({"file_id":file_id,"sender_id":args.user,"recipient_id":args.recipient})
    ciphertext = AESGCM(file_key).encrypt(iv, plaintext, aad)
    note = args.note or ''
    note_iv = os.urandom(12)
    encrypted_note = B64(AESGCM(file_key).encrypt(note_iv, note.encode('utf-8'), aad)) if note else None
    visible = {
        "file_id": file_id, "sender_id": args.user, "recipient_id": args.recipient,
        "upload_timestamp": upload_ts, "expires_at": expires_at,
        "ciphertext_hash": sha256_b64(ciphertext), "plaintext_hash": sha256_b64(plaintext),
        "file_size": len(plaintext)
    }
    wrapped_key = rsa_encrypt(cert_public_key(recipient_cert), file_key)
    signed_fields = dict(visible)
    sig = rsa_sign(key, canonical(signed_fields))
    pkg = {
        "file_id": file_id,
        "visible_metadata": visible,
        "sender_certificate": cert,
        "recipient_certificate": recipient_cert,
        "wrapped_file_key": wrapped_key,
        "file_iv": B64(iv),
        "file_aad": B64(aad),
        "ciphertext": B64(ciphertext),
        "encrypted_note": encrypted_note,
        "note_iv": B64(note_iv) if note else None,
        "signed_fields": signed_fields,
        "sender_signature": sig,
        "algorithms": {"file_encryption":"AES-256-GCM","key_wrap":"RSA-OAEP-SHA256","signature":"RSA-PSS-SHA256"}
    }
    res = send_req(chan, 'UPLOAD', package=pkg)
    print(json.dumps(res, indent=2))
    sock.close()

def cmd_list(args):
    sock, chan, *_ = connect(args)
    res = send_req(chan, 'LIST', scope=args.scope)
    if not res.get('ok'):
        print('LIST failed:', res.get('error'))
    else:
        if not res['files']:
            print('No files.')
        for f in res['files']:
            print(json.dumps(f, indent=2))
    sock.close()

def cmd_download(args):
    sock, chan, cert, key = connect(args)
    res = send_req(chan, 'DOWNLOAD', file_id=args.file_id)
    if not res.get('ok'):
        print('DOWNLOAD failed:', res.get('error')); sock.close(); return
    pkg = res['package']
    sender_cert = pkg['sender_certificate']
    ca_pub = load_ca_public(args.ca_public)
    ok, msg = verify_certificate(sender_cert, ca_pub, expected_role='client')
    if not ok: raise SystemExit('sender certificate invalid: '+msg)
    sender_pub = cert_public_key(sender_cert)
    if not rsa_verify(sender_pub, pkg['sender_signature'], canonical(pkg['signed_fields'])):
        raise SystemExit('sender signature verification failed')
    file_key = rsa_decrypt(key, pkg['wrapped_file_key'])
    plaintext = AESGCM(file_key).decrypt(UB64(pkg['file_iv']), UB64(pkg['ciphertext']), UB64(pkg['file_aad']))
    if sha256_b64(plaintext) != pkg['visible_metadata'].get('plaintext_hash'):
        raise SystemExit('plaintext hash mismatch')
    out = args.out or os.path.join('downloads', pkg['file_id'] + '.bin')
    ensure_dir(os.path.dirname(out) or '.')
    with open(out, 'wb') as f: f.write(plaintext)
    note = None
    if pkg.get('encrypted_note'):
        note = AESGCM(file_key).decrypt(UB64(pkg['note_iv']), UB64(pkg['encrypted_note']), UB64(pkg['file_aad'])).decode('utf-8')
    ack = send_req(chan, 'ACK_DOWNLOAD', file_id=args.file_id)
    print(f'Downloaded and verified file to: {out}')
    print('ACK:', json.dumps(ack, indent=2))
    if note is not None:
        print('Encrypted note decrypted:', note)
    sock.close()

def cmd_revoke(args):
    sock, chan, *_ = connect(args)
    res = send_req(chan, 'REVOKE', file_id=args.file_id)
    print(json.dumps(res, indent=2)); sock.close()

def main():
    p = argparse.ArgumentParser(description='Secure File Drop client')
    p.add_argument('--host', default='127.0.0.1'); p.add_argument('--port', type=int, default=9000)
    p.add_argument('--user', required=True); p.add_argument('--cert', required=True); p.add_argument('--key', required=True)
    p.add_argument('--ca-public', default='pki/ca/ca_public_key.pem')
    sub = p.add_subparsers(dest='cmd', required=True)
    sub.add_parser('register')
    u = sub.add_parser('upload'); u.add_argument('--recipient', required=True); u.add_argument('--file', required=True); u.add_argument('--expires', type=int, default=3600); u.add_argument('--note', default='')
    l = sub.add_parser('list'); l.add_argument('--scope', choices=['recipient','sender'], default='recipient')
    d = sub.add_parser('download'); d.add_argument('file_id'); d.add_argument('--out')
    r = sub.add_parser('revoke'); r.add_argument('file_id')
    args = p.parse_args()
    {'register':cmd_register,'upload':cmd_upload,'list':cmd_list,'download':cmd_download,'revoke':cmd_revoke}[args.cmd](args)
    import sys, os
    sys.stdout.flush(); sys.stderr.flush()
    os._exit(0)
if __name__ == '__main__': main()
