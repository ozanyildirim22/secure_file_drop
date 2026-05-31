import os, socket
from cryptography.hazmat.primitives.asymmetric import ec
from .common import *

def load_ca_public(ca_pub_path):
    with open(ca_pub_path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

def client_handshake(sock: socket.socket, client_id, client_cert, client_key, ca_pub_path):
    ca_pub = load_ca_public(ca_pub_path)
    ok, msg = verify_certificate(client_cert, ca_pub, expected_role='client', expected_subject=client_id)
    if not ok: raise ValueError('own certificate invalid: '+msg)
    eph = ec.generate_private_key(ec.SECP256R1())
    client_hello = {"type":"HELLO","version":PROTOCOL_VERSION,"role":"client","certificate":client_cert,"nonce":B64(os.urandom(32)),"ecdh_public":ec_public_bytes(eph.public_key())}
    send_json(sock, client_hello)
    server_hello = recv_json(sock)
    ok, msg = verify_certificate(server_hello.get('certificate'), ca_pub, expected_role='server')
    if not ok: raise ValueError('server certificate invalid: '+msg)
    server_pub = cert_public_key(server_hello['certificate'])
    client_proof = {"type":"PROOF","subject":client_id,"signature":rsa_sign(client_key, canonical({"client_hello":client_hello,"server_hello":server_hello,"signer":client_id}))}
    send_json(sock, client_proof)
    server_proof = recv_json(sock)
    server_id = server_hello['certificate']['body']['subject_id']
    valid = rsa_verify(server_pub, server_proof.get('signature',''), canonical({"client_hello":client_hello,"server_hello":server_hello,"signer":server_id}))
    if not valid: raise ValueError('server proof-of-possession failed')
    shared = eph.exchange(ec.ECDH(), ec_public_from_b64(server_hello['ecdh_public']))
    th = transcript_hash(client_hello, server_hello)
    send_key, recv_key = derive_channel_keys(shared, th, 'client')
    return SecureChannel(sock, send_key, recv_key), server_id

def server_handshake(sock: socket.socket, server_id, server_cert, server_key, ca_pub_path, logger=None):
    ca_pub = load_ca_public(ca_pub_path)
    client_hello = recv_json(sock)
    ok, msg = verify_certificate(client_hello.get('certificate'), ca_pub, expected_role='client')
    if not ok:
        if logger: logger.warning('certificate verification failed: %s', msg)
        raise ValueError('client certificate invalid: '+msg)
    client_id = client_hello['certificate']['body']['subject_id']
    eph = ec.generate_private_key(ec.SECP256R1())
    server_hello = {"type":"HELLO","version":PROTOCOL_VERSION,"role":"server","certificate":server_cert,"nonce":B64(os.urandom(32)),"ecdh_public":ec_public_bytes(eph.public_key())}
    send_json(sock, server_hello)
    client_proof = recv_json(sock)
    client_pub = cert_public_key(client_hello['certificate'])
    valid = rsa_verify(client_pub, client_proof.get('signature',''), canonical({"client_hello":client_hello,"server_hello":server_hello,"signer":client_id}))
    if not valid:
        if logger: logger.warning('proof-of-possession failed for %s', client_id)
        raise ValueError('client proof-of-possession failed')
    server_proof = {"type":"PROOF","subject":server_id,"signature":rsa_sign(server_key, canonical({"client_hello":client_hello,"server_hello":server_hello,"signer":server_id}))}
    send_json(sock, server_proof)
    shared = eph.exchange(ec.ECDH(), ec_public_from_b64(client_hello['ecdh_public']))
    th = transcript_hash(client_hello, server_hello)
    send_key, recv_key = derive_channel_keys(shared, th, 'server')
    return SecureChannel(sock, send_key, recv_key), client_id, client_hello['certificate']
