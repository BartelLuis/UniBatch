"""Offline account provisioning. Never accepts passwords as command-line arguments."""
import argparse
import getpass
import json
import re
import unicodedata
from pathlib import Path
from cryptography.fernet import Fernet
from app.security import password_hash

parser = argparse.ArgumentParser()
parser.add_argument('command', choices=['key', 'user'])
parser.add_argument('--file', required=True)
parser.add_argument('--name')
parser.add_argument('--role', choices=['admin', 'operator', 'approver', 'viewer'], default='admin')
args = parser.parse_args()
path = Path(args.file)
path.parent.mkdir(parents=True, exist_ok=True)
if args.command == 'key':
    with path.open('xb') as f:
        f.write(Fernet.generate_key())
else:
    if not args.name:
        parser.error('--name required')
    name = unicodedata.normalize('NFKC', args.name).strip().casefold()
    if not re.fullmatch(r'[a-z0-9_.@-]{1,80}', name):
        parser.error('ad: ist für Verzeichniskonten reserviert')
    password = getpass.getpass('Passwort (mindestens 16 Zeichen): ')
    if len(password) < 16 or password != getpass.getpass('Wiederholen: '):
        parser.error('Passwort zu kurz oder Bestätigung abweichend')
    users = json.loads(path.read_text()) if path.exists() else {}
    if any(unicodedata.normalize('NFKC', value).strip().casefold() == name and value != name for value in users):
        parser.error('Der normalisierte Kontoname ist bereits vorhanden')
    users[name] = {'role': args.role, 'password': password_hash(password), 'scope': ['*']}
    path.write_text(json.dumps(users, indent=2), encoding='utf-8')
