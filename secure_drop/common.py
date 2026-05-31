import base64, json, os, socket, struct, time, uuid, pathlib, logging
from dataclasses import dataclass
from typing import Any, Dict, Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

B64 = lambda b: base64.b64encode(b).decode('ascii')
UB64 = lambda s: base64.b64decode(s.encode('ascii'))
MAX_FRAME = 64 * 1024 * 1024
CERT_VALID_SECONDS = 365 * 24 * 3600
PROTOCOL_VERSION = "SFD/1.0"

def now() -> int:
    return int(time.time())

def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')

def ensure_dir(path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)

def write_json(path, obj):
    ensure_dir(os.path.dirname(path))
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, sort_keys=True)

def read_json(path, default=None):
    if not os.path.exists(path):
        return default
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def generate_rsa_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)

def save_private_key(key, path):
    ensure_dir(os.path.dirname(path))
    with open(path, 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

def load_private_key(path):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def public_key_pem(public_key) -> str:
    return public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

def load_public_key_from_pem(pem: str):
    return serialization.load_pem_public_key(pem.encode('utf-8'))

def rsa_sign(private_key, data: bytes) -> str:
    sig = private_key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return B64(sig)

def rsa_verify(public_key, sig_b64: str, data: bytes) -> bool:
    try:
        public_key.verify(UB64(sig_b64), data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except InvalidSignature:
        return False

def rsa_encrypt(public_key, plaintext: bytes) -> str:
    return B64(public_key.encrypt(plaintext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)))

def rsa_decrypt(private_key, ciphertext_b64: str) -> bytes:
    return private_key.decrypt(UB64(ciphertext_b64), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def sha256_b64(data: bytes) -> str:
    h = hashes.Hash(hashes.SHA256()); h.update(data); return B64(h.finalize())

def make_certificate(subject_id: str, role: str, public_key_pem_str: str, ca_private_key) -> Dict[str, Any]:
    body = {
        "version": 1,
        "subject_id": subject_id,
        "role": role,
        "public_key_pem": public_key_pem_str,
        "issued_at": now(),
        "expires_at": now() + CERT_VALID_SECONDS,
        "serial": uuid.uuid4().hex,
        "issuer": "Simple-SFD-CA",
    }
    return {"body": body, "signature": rsa_sign(ca_private_key, canonical(body))}

def verify_certificate(cert: Dict[str, Any], ca_public_key, expected_role: Optional[str]=None, expected_subject: Optional[str]=None) -> Tuple[bool, str]:
    try:
        body = cert["body"]
        if body.get("version") != 1:
            return False, "unsupported cert version"
        if expected_role and body.get("role") != expected_role:
            return False, "unexpected cert role"
        if expected_subject and body.get("subject_id") != expected_subject:
            return False, "unexpected cert subject"
        t = now()
        if body.get("issued_at", 0) > t + 60 or body.get("expires_at", 0) < t:
            return False, "certificate time invalid"
        if not rsa_verify(ca_public_key, cert.get("signature", ""), canonical(body)):
            return False, "CA signature invalid"
        load_public_key_from_pem(body["public_key_pem"])
        return True, "ok"
    except Exception as e:
        return False, f"certificate parse error: {e}"

def cert_public_key(cert):
    return load_public_key_from_pem(cert["body"]["public_key_pem"])

def send_frame(sock: socket.socket, payload: bytes):
    if len(payload) > MAX_FRAME:
        raise ValueError("frame too large")
    sock.sendall(struct.pack("!I", len(payload)) + payload)

def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("socket closed")
        data += chunk
    return data

def recv_frame(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 4)
    (ln,) = struct.unpack("!I", header)
    if ln > MAX_FRAME:
        raise ValueError("frame too large")
    return recv_exact(sock, ln)

def send_json(sock, obj):
    send_frame(sock, canonical(obj))

def recv_json(sock):
    return json.loads(recv_frame(sock).decode('utf-8'))

@dataclass
class SecureChannel:
    sock: socket.socket
    send_key: bytes
    recv_key: bytes
    send_seq: int = 0
    recv_seq: int = 0
    def send(self, obj: Dict[str, Any]):
        self.send_seq += 1
        nonce = self.send_seq.to_bytes(12, 'big')
        pt = canonical(obj)
        ct = AESGCM(self.send_key).encrypt(nonce, pt, self.send_seq.to_bytes(8, 'big'))
        send_json(self.sock, {"seq": self.send_seq, "ct": B64(ct)})
    def recv(self) -> Dict[str, Any]:
        frame = recv_json(self.sock)
        seq = int(frame["seq"])
        if seq != self.recv_seq + 1:
            raise ValueError(f"bad channel sequence: got {seq}, expected {self.recv_seq+1}")
        nonce = seq.to_bytes(12, 'big')
        pt = AESGCM(self.recv_key).decrypt(nonce, UB64(frame["ct"]), seq.to_bytes(8, 'big'))
        self.recv_seq = seq
        return json.loads(pt.decode('utf-8'))

def derive_channel_keys(shared_secret: bytes, transcript_hash: bytes, role: str):
    km = HKDF(algorithm=hashes.SHA256(), length=64, salt=transcript_hash, info=b"SFD channel keys v1").derive(shared_secret)
    c2s, s2c = km[:32], km[32:]
    return (c2s, s2c) if role == "client" else (s2c, c2s)

def ec_public_bytes(pub) -> str:
    return B64(pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))

def ec_public_from_b64(s: str):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), UB64(s))

def transcript_hash(*msgs: Dict[str, Any]) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    for m in msgs:
        h.update(canonical(m))
    return h.finalize()

def setup_logger(name, log_file):
    ensure_dir(os.path.dirname(log_file))
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        logger.addHandler(fh)
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        logger.addHandler(sh)
    return logger

class RequestReplayCache:
    def __init__(self, ttl=300):
        self.ttl = ttl; self.seen = {}
    def check_and_store(self, user, request_id, timestamp):
        t = now()
        for k,v in list(self.seen.items()):
            if v < t - self.ttl: del self.seen[k]
        if abs(int(timestamp) - t) > self.ttl:
            return False, "timestamp outside freshness window"
        k = (user, request_id)
        if k in self.seen:
            return False, "duplicate request id"
        self.seen[k] = t
        return True, "ok"
