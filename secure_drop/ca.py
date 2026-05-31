import argparse, os
from .common import *

def init_ca(base):
    ensure_dir(base)
    key_path = os.path.join(base, 'ca_private_key.pem')
    pub_path = os.path.join(base, 'ca_public_key.pem')
    if os.path.exists(key_path):
        raise SystemExit(f'CA already exists at {base}')
    key = generate_rsa_private_key()
    save_private_key(key, key_path)
    with open(pub_path, 'w', encoding='utf-8') as f:
        f.write(public_key_pem(key.public_key()))
    print(f'Created CA in {base}')

def issue(base, subject, role, outdir):
    ca_key = load_private_key(os.path.join(base, 'ca_private_key.pem'))
    key = generate_rsa_private_key()
    cert = make_certificate(subject, role, public_key_pem(key.public_key()), ca_key)
    ensure_dir(outdir)
    save_private_key(key, os.path.join(outdir, f'{subject}_private_key.pem'))
    write_json(os.path.join(outdir, f'{subject}_cert.json'), cert)
    print(f'Issued {role} certificate for {subject} in {outdir}')

def main():
    p = argparse.ArgumentParser(description='Simple CA for Secure File Drop')
    sub = p.add_subparsers(dest='cmd', required=True)
    a = sub.add_parser('init'); a.add_argument('--ca-dir', default='pki/ca')
    b = sub.add_parser('issue'); b.add_argument('subject'); b.add_argument('--role', choices=['client','server'], required=True); b.add_argument('--ca-dir', default='pki/ca'); b.add_argument('--out-dir', required=True)
    args = p.parse_args()
    if args.cmd == 'init': init_ca(args.ca_dir)
    elif args.cmd == 'issue': issue(args.ca_dir, args.subject, args.role, args.out_dir)
if __name__ == '__main__': main()
