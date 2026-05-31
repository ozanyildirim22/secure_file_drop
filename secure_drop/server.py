import argparse, os, socket, threading, uuid
from .common import *
from .handshake import server_handshake, load_ca_public

class ServerState:
    def __init__(self, storage_dir, logger):
        self.storage_dir = storage_dir
        self.meta_path = os.path.join(storage_dir, 'metadata.json')
        self.cert_dir = os.path.join(storage_dir, 'client_certs')
        self.packages_dir = os.path.join(storage_dir, 'packages')
        ensure_dir(self.cert_dir); ensure_dir(self.packages_dir)
        self.lock = threading.RLock()
        self.metadata = read_json(self.meta_path, {}) or {}
        self.replay = RequestReplayCache()
        self.logger = logger
    def save(self): write_json(self.meta_path, self.metadata)
    def remember_cert(self, user, cert): write_json(os.path.join(self.cert_dir, user + '.cert.json'), cert)
    def get_cert(self, user): return read_json(os.path.join(self.cert_dir, user + '.cert.json'))

def response(ok, **kwargs):
    d = {"ok": ok}; d.update(kwargs); return d

def check_req(state, user, req):
    rid, ts = req.get('request_id'), req.get('timestamp')
    if not rid or not ts: return False, 'missing request_id or timestamp'
    ok, reason = state.replay.check_and_store(user, rid, int(ts))
    if not ok: state.logger.warning('replay/freshness failure user=%s reason=%s request_id=%s', user, reason, rid)
    return ok, reason

def handle_client(conn, addr, args, state, server_cert, server_key):
    user = '?'
    try:
        chan, user, client_cert = server_handshake(conn, args.server_id, server_cert, server_key, args.ca_public, state.logger)
        state.logger.info('connection authenticated user=%s addr=%s', user, addr)
        with state.lock:
            state.remember_cert(user, client_cert)
        while True:
            req = chan.recv()
            typ = req.get('type')
            ok, reason = check_req(state, user, req)
            if not ok:
                chan.send(response(False, error=reason)); continue
            if typ == 'GET_CERT':
                target = req.get('user')
                cert = state.get_cert(target)
                if not cert: chan.send(response(False, error='certificate not known by server; target user must connect once'))
                else: chan.send(response(True, certificate=cert))
            elif typ == 'UPLOAD':
                pkg = req.get('package')
                if not isinstance(pkg, dict): chan.send(response(False, error='bad package')); continue
                file_id = pkg.get('file_id') or uuid.uuid4().hex
                pkg['file_id'] = file_id
                visible = pkg.get('visible_metadata', {})
                if visible.get('sender_id') != user:
                    state.logger.warning('upload rejected sender mismatch auth=%s package=%s', user, visible.get('sender_id'))
                    chan.send(response(False, error='sender mismatch')); continue
                if not state.get_cert(visible.get('recipient_id','')):
                    chan.send(response(False, error='recipient certificate unknown')); continue
                sender_cert = state.get_cert(user)
                sender_pub = cert_public_key(sender_cert)
                sig_payload = pkg.get('signed_fields')
                sig = pkg.get('sender_signature')
                if not sig_payload or not sig or not rsa_verify(sender_pub, sig, canonical(sig_payload)):
                    state.logger.warning('upload signature verification failed sender=%s file_id=%s', user, file_id)
                    chan.send(response(False, error='sender signature invalid')); continue
                must_match = ['file_id','sender_id','recipient_id','ciphertext_hash','upload_timestamp','expires_at']
                if any(sig_payload.get(k) != visible.get(k, pkg.get(k)) for k in must_match):
                    chan.send(response(False, error='signed fields do not match package')); continue
                with state.lock:
                    path = os.path.join(state.packages_dir, file_id + '.json')
                    if file_id in state.metadata:
                        chan.send(response(False, error='file_id already exists')); continue
                    write_json(path, pkg)
                    state.metadata[file_id] = {
                        'file_id': file_id, 'sender_id': visible['sender_id'], 'recipient_id': visible['recipient_id'],
                        'upload_timestamp': visible['upload_timestamp'], 'expires_at': visible['expires_at'],
                        'status': 'pending', 'revoked': False, 'download_started': False,
                        'download_completed': False, 'successful_download_time': None,
                        'package_path': path
                    }
                    state.save()
                state.logger.info('file uploaded file_id=%s sender=%s recipient=%s expires_at=%s', file_id, user, visible['recipient_id'], visible['expires_at'])
                chan.send(response(True, file_id=file_id))
            elif typ == 'LIST':
                scope = req.get('scope','recipient')
                with state.lock:
                    rows = []
                    for m in state.metadata.values():
                        if (scope == 'recipient' and m['recipient_id'] == user) or (scope == 'sender' and m['sender_id'] == user):
                            safe = {k:m[k] for k in ['file_id','sender_id','recipient_id','upload_timestamp','expires_at','status','revoked','download_completed']}
                            safe['expired'] = now() > int(m['expires_at'])
                            rows.append(safe)
                chan.send(response(True, files=rows))
            elif typ == 'DOWNLOAD':
                file_id = req.get('file_id')
                with state.lock:
                    m = state.metadata.get(file_id)
                    if not m:
                        chan.send(response(False, error='file not found')); continue
                    if m['recipient_id'] != user:
                        state.logger.warning('unauthorized download attempt user=%s file_id=%s intended=%s', user, file_id, m['recipient_id'])
                        chan.send(response(False, error='not authorized for this file')); continue
                    if m['revoked']:
                        state.logger.warning('revoked file retrieval rejected user=%s file_id=%s', user, file_id)
                        chan.send(response(False, error='file revoked')); continue
                    if now() > int(m['expires_at']):
                        m['status'] = 'expired'; state.save()
                        state.logger.warning('expired file retrieval rejected user=%s file_id=%s', user, file_id)
                        chan.send(response(False, error='file expired')); continue
                    if m['download_completed']:
                        state.logger.warning('one-time repeated download rejected user=%s file_id=%s', user, file_id)
                        chan.send(response(False, error='file already downloaded once')); continue
                    pkg = read_json(m['package_path'])
                    m['download_started'] = True; state.save()
                chan.send(response(True, package=pkg))
            elif typ == 'ACK_DOWNLOAD':
                file_id = req.get('file_id')
                with state.lock:
                    m = state.metadata.get(file_id)
                    if not m or m['recipient_id'] != user:
                        chan.send(response(False, error='not authorized')); continue
                    if m['download_completed']:
                        chan.send(response(False, error='already completed')); continue
                    # Successful retrieval is defined as recipient-side decrypt+verify followed by this authenticated ACK.
                    m['status'] = 'downloaded'; m['download_completed'] = True; m['successful_download_time'] = now(); state.save()
                state.logger.info('one-time download completed file_id=%s recipient=%s', file_id, user)
                chan.send(response(True, status='downloaded'))
            elif typ == 'REVOKE':
                file_id = req.get('file_id')
                with state.lock:
                    m = state.metadata.get(file_id)
                    if not m or m['sender_id'] != user:
                        state.logger.warning('unauthorized revocation user=%s file_id=%s', user, file_id)
                        chan.send(response(False, error='not authorized')); continue
                    if m['download_completed']:
                        chan.send(response(False, error='cannot revoke after successful download')); continue
                    if m['revoked']:
                        chan.send(response(True, status='already revoked')); continue
                    m['revoked'] = True; m['status'] = 'revoked'; state.save()
                state.logger.info('file revoked file_id=%s sender=%s', file_id, user)
                chan.send(response(True, status='revoked'))
            else:
                chan.send(response(False, error='unknown request type'))
    except Exception as e:
        state.logger.warning('connection closed user=%s addr=%s reason=%s', user, addr, e)
    finally:
        try: conn.close()
        except Exception: pass

def main():
    p = argparse.ArgumentParser(description='Secure File Drop server')
    p.add_argument('--host', default='127.0.0.1'); p.add_argument('--port', type=int, default=9000)
    p.add_argument('--server-id', default='server')
    p.add_argument('--cert', default='pki/server/server_cert.json'); p.add_argument('--key', default='pki/server/server_private_key.pem')
    p.add_argument('--ca-public', default='pki/ca/ca_public_key.pem'); p.add_argument('--storage', default='storage/server')
    args = p.parse_args()
    logger = setup_logger('sfd-server', os.path.join(args.storage, 'server.log'))
    server_cert = read_json(args.cert); server_key = load_private_key(args.key)
    state = ServerState(args.storage, logger)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((args.host, args.port)); s.listen(50)
        logger.info('server listening host=%s port=%s', args.host, args.port)
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr, args, state, server_cert, server_key), daemon=True).start()
if __name__ == '__main__': main()
