import asyncio
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from fastapi import HTTPException

from app.storage import Store
from app.process_lock import ProcessLock


SCHEMA = [
    '''CREATE TABLE IF NOT EXISTS app_servers(id TEXT PRIMARY KEY,name TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,blob BLOB NOT NULL,status TEXT DEFAULT 'unknown',last_sync REAL,error TEXT,site_count INTEGER DEFAULT 0)''',
    '''CREATE TABLE IF NOT EXISTS app_sites(server TEXT,site TEXT,name TEXT,tags TEXT DEFAULT '[]',synced REAL,internal_reference TEXT,PRIMARY KEY(server,site))''',
    '''CREATE TABLE IF NOT EXISTS batch_jobs(id TEXT PRIMARY KEY,creator TEXT,approver TEXT,state TEXT,created REAL,ready_at REAL,approved_at REAL,run_after REAL,kind TEXT,operation TEXT,reason TEXT,blob BLOB,parent TEXT,cancel_requested INTEGER DEFAULT 0,error TEXT)''',
    '''CREATE TABLE IF NOT EXISTS batch_targets(job TEXT,idx INTEGER,server TEXT,site TEXT,object TEXT,operation TEXT,status TEXT,blob BLOB,PRIMARY KEY(job,idx),FOREIGN KEY(job) REFERENCES batch_jobs(id))''',
    '''CREATE TABLE IF NOT EXISTS batch_scope(job TEXT,server TEXT,PRIMARY KEY(job,server),FOREIGN KEY(job) REFERENCES batch_jobs(id))''',
    '''CREATE TABLE IF NOT EXISTS app_settings(key TEXT PRIMARY KEY,value TEXT)''',
    '''CREATE TABLE IF NOT EXISTS app_templates(id TEXT PRIMARY KEY,name TEXT,kind TEXT,operation TEXT,creator TEXT,created REAL,blob BLOB)''',
    '''CREATE TABLE IF NOT EXISTS app_audit(seq INTEGER PRIMARY KEY,timestamp REAL,actor TEXT,action TEXT,detail TEXT,previous TEXT,hash TEXT,signature TEXT)''',
    'CREATE INDEX IF NOT EXISTS sites_search ON app_sites(server,name)',
    'CREATE INDEX IF NOT EXISTS targets_status ON batch_targets(job,status)',
    'CREATE INDEX IF NOT EXISTS jobs_state ON batch_jobs(state,run_after)',
]


class Service:
    def __init__(self, config):
        self.config = config
        config.data_dir.mkdir(parents=True, exist_ok=True)
        if config.demo:
            key_path = config.data_dir / 'demo.key'
            if not key_path.exists():
                with key_path.open('xb') as file:
                    file.write(Fernet.generate_key())
                try:
                    key_path.chmod(0o600)
                except OSError:
                    pass
        else:
            if not config.encryption_key_file:
                raise RuntimeError('ENCRYPTION_KEY_FILE required')
            key_path = Path(config.encryption_key_file)
        key = key_path.read_bytes().strip()
        self.cipher = Fernet(key)
        self.audit_key = hmac.new(key, b'unifi-batch:audit:v2', hashlib.sha256).digest()
        self.process_lock = ProcessLock(config.data_dir / '.service.lock')
        self.store = Store(config.data_dir / 'batch.sqlite')
        for statement in SCHEMA:
            self.store.execute(statement)
        if 'internal_reference' not in {row['name'] for row in self.store.query('PRAGMA table_info(app_sites)')}:
            self.store.execute('ALTER TABLE app_sites ADD COLUMN internal_reference TEXT')
            self.store.execute('UPDATE app_servers SET last_sync=NULL')
        self.store.execute('CREATE INDEX IF NOT EXISTS sites_internal_reference ON app_sites(server,internal_reference)')
        mode='demo' if config.demo else 'production'
        previous_mode=self.store.one("SELECT value FROM app_settings WHERE key='mode'")
        if (previous_mode and previous_mode['value']!=mode) or (not config.demo and (config.data_dir/'demo.key').exists()):
            self.store.close();self.process_lock.close()
            raise RuntimeError('Demo- und Produktivdaten dürfen nicht dasselbe Datenverzeichnis verwenden')
        self.store.execute("INSERT OR IGNORE INTO app_settings(key,value) VALUES('mode',?)",(mode,))
        if not self.store.one("SELECT key FROM app_settings WHERE key='scope_migration_v2'"):
            with self.store.transaction():
                for row in self.store.query('SELECT id,blob FROM batch_jobs'):
                    self.store.execute('DELETE FROM batch_scope WHERE job=?',(row['id'],))
                    for server in {t['server'] for t in self.decrypt(row['blob'])['targets']}:
                        self.store.execute('INSERT INTO batch_scope VALUES(?,?)',(row['id'],server))
                self.store.execute("INSERT INTO app_settings(key,value) VALUES('scope_migration_v2','done')")
        self.store.execute("UPDATE batch_jobs SET state='interrupted',error='Prozess wurde unterbrochen; Ergebnisse vor erneutem Ausrollen prüfen' WHERE state IN ('running','queued')")
        self.tasks = set()
        self.planning = set()
        self.active_job = None
        self.syncs = {}
        self.sync_task = None
        self.stopping = False
        self.planner_limit = asyncio.Semaphore(3)
        self.controller_locks = {}
        self.initialize_servers()

    def encrypt(self, value):
        return self.cipher.encrypt(json.dumps(value, ensure_ascii=False).encode())

    def decrypt(self, value):
        return json.loads(self.cipher.decrypt(value))

    def audit(self, actor, action, detail):
        detail = str(detail)[:2000]
        with self.store.transaction():
            row = self.store.one('SELECT hash FROM app_audit ORDER BY seq DESC LIMIT 1')
            previous = row['hash'] if row else '0' * 64
            stamp = time.time()
            encoded = json.dumps([stamp, actor, action, detail, previous], separators=(',', ':')).encode()
            digest = hashlib.sha256(encoded).hexdigest()
            signature = hmac.new(self.audit_key, digest.encode(), hashlib.sha256).hexdigest()
            self.store.execute('INSERT INTO app_audit(timestamp,actor,action,detail,previous,hash,signature) VALUES(?,?,?,?,?,?,?)',
                               (stamp, actor, action, detail, previous, digest, signature))

    def validate_server(self, data):
        from app.unifi import validate_origin
        validate_origin(data['origin'], self.config.allowed_controller_hosts or None)
        if data['api_prefix'] not in ('/proxy/network/integration/v1', '/integration/v1'):
            raise HTTPException(422, 'Nur lokale Network-Integration-API-Präfixe erlaubt')
        if not data.get('key'):
            raise HTTPException(422, 'Lokaler API-Key erforderlich')
        radius_mode = data.get('radius_auth_mode', 'api_key')
        if radius_mode not in ('api_key', 'local_account'):
            raise HTTPException(422, 'Ungültige RADIUS-API-Anmeldemethode')
        if radius_mode == 'api_key':
            data.pop('radius_username', None)
            data.pop('radius_password', None)
        if data.get('radius_legacy_enabled') and data['api_prefix'] != '/proxy/network/integration/v1':
            raise HTTPException(422, 'Der klassische RADIUS-Adapter setzt einen lokalen UniFi OS Server voraus')
        if data.get('radius_legacy_enabled') and radius_mode == 'local_account':
            if not (data.get('radius_username') or '').strip() or not data.get('radius_password'):
                raise HTTPException(422, 'Für die lokale RADIUS-API-Anmeldung werden Benutzername und Passwort benötigt')
        if data.get('ca_file') and not self.config.demo:
            path = Path(data['ca_file']).resolve()
            allowed = Path('/run/secrets').resolve()
            if not path.is_relative_to(allowed):
                raise HTTPException(422, 'CA-Dateien müssen unter /run/secrets liegen')
        return data

    def initialize_servers(self):
        if self.store.one('SELECT id FROM app_servers LIMIT 1'):
            return
        if self.config.demo:
            for number in range(1, 13):
                data = {'origin': f'https://uos-{number:02d}.intern.example', 'api_prefix': '/proxy/network/integration/v1', 'key': 'simulation', 'ca_file': None}
                self.store.execute('INSERT INTO app_servers(id,name,blob) VALUES(?,?,?)',
                                   (f'demo-{number:02d}', f'UniFi OS Server {number:02d}', self.encrypt(data)))
        elif self.config.servers_file:
            values = json.loads(Path(self.config.servers_file).read_text(encoding='utf-8-sig'))
            for server in values:
                from app.jobs import segment
                segment(server['id'])
                data = {'origin': server['origin'].rstrip('/'), 'api_prefix': server.get('api_prefix', '/proxy/network/integration/v1'),
                        'key': Path(server['key_file']).read_text().strip(), 'ca_file': server.get('ca_file'),
                        'radius_legacy_enabled': bool(server.get('radius_legacy_enabled', False)),
                        'radius_auth_mode': server.get('radius_auth_mode', 'api_key'),
                        'radius_username': server.get('radius_username')}
                if server.get('radius_password_file'):
                    data['radius_password'] = Path(server['radius_password_file']).read_text().rstrip('\r\n')
                self.validate_server(data)
                self.store.execute('INSERT INTO app_servers(id,name,blob) VALUES(?,?,?)', (server['id'], server['name'], self.encrypt(data)))

    def servers(self, user):
        rows = self.store.query('SELECT * FROM app_servers ORDER BY name,id')
        return [self.public_server(row) for row in rows if '*' in user['scope'] or row['id'] in user['scope']]

    def public_server(self, row):
        config = self.decrypt(row['blob'])
        return {k: row[k] for k in ('id', 'name', 'enabled', 'status', 'last_sync', 'error', 'site_count')} | {
            'enabled': bool(row['enabled']),
            'origin': config['origin'], 'api_prefix': config['api_prefix'], 'ca_file': config.get('ca_file'), 'has_key': bool(config.get('key')),
            'radius_legacy_enabled': bool(config.get('radius_legacy_enabled', False)),
            'radius_auth_mode': config.get('radius_auth_mode', 'api_key'),
            'radius_username': config.get('radius_username'), 'has_radius_password': bool(config.get('radius_password')),
            'radius_supported': self.config.demo or bool(config.get('radius_legacy_enabled', False))}

    def server(self, server_id, enabled=True):
        row = self.store.one('SELECT * FROM app_servers WHERE id=?', (server_id,))
        if not row:
            raise HTTPException(404, 'Server unbekannt')
        if enabled and not row['enabled']:
            raise HTTPException(409, 'Server ist deaktiviert')
        return self.decrypt(row['blob']) | {'id': row['id'], 'name': row['name']}

    async def request(self, server_id, method, path, payload=None):
        if '/radius/configurations' in path:
            reference = self.radius_reference(server_id, path)
            if self.config.demo:
                return await self.client.request(self.server(server_id), method, path, payload)
            return await self.radius_client.request(self.server(server_id), method, path, payload, site_reference=reference)
        return await self.client.request(self.server(server_id), method, path, payload)

    async def collection(self, server_id, path):
        if '/radius/configurations' in path:
            reference = self.radius_reference(server_id, path)
            if self.config.demo:
                return await self.client.collection(self.server(server_id), path)
            return await self.radius_client.collection(self.server(server_id), path, site_reference=reference)
        return await self.client.collection(self.server(server_id), path)

    def radius_reference(self, server_id, path):
        match = re.fullmatch(r'/sites/([A-Za-z0-9_-]{1,80})/radius/configurations(?:/[A-Za-z0-9_-]{1,80}(?:/references)?)?', path)
        if not match:
            raise HTTPException(422, 'Ungültiger RADIUS-Konfigurationspfad')
        server = self.server(server_id)
        if not self.config.demo and not server.get('radius_legacy_enabled'):
            raise HTTPException(409, 'RADIUS-Verwaltung muss am UniFi OS Server im Tool aktiviert werden')
        site = self.store.one('SELECT internal_reference FROM app_sites WHERE server=? AND site=?', (server_id, match[1]))
        if not site or not site['internal_reference']:
            raise HTTPException(409, 'Für die RADIUS-Verwaltung zuerst das Site-Inventar synchronisieren')
        reference = site['internal_reference']
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', reference):
            raise HTTPException(502, 'Der lokale UniFi-Site-Verweis ist ungültig')
        if self.store.one('SELECT COUNT(*) n FROM app_sites WHERE server=? AND internal_reference=?', (server_id, reference))['n'] != 1:
            raise HTTPException(409, 'Der lokale UniFi-Site-Verweis ist nicht eindeutig')
        return reference

    def spawn(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    async def start(self):
        from app.unifi import DemoClient, LocalClient
        self.client = DemoClient(self.store) if self.config.demo else LocalClient(allowed_hosts=self.config.allowed_controller_hosts or None)
        if not self.config.demo:
            from app.radius import RadiusClient
            self.radius_client = RadiusClient(allowed_hosts=self.config.allowed_controller_hosts or None)
            if self.store.one('SELECT site FROM app_sites WHERE internal_reference IS NULL LIMIT 1'):
                self.store.execute('UPDATE app_servers SET last_sync=NULL')
        if self.config.demo and (not self.store.one('SELECT site FROM app_sites LIMIT 1') or self.store.one('SELECT site FROM app_sites WHERE internal_reference IS NULL LIMIT 1')):
            await self.sync_inventory([row['id'] for row in self.store.query('SELECT id FROM app_servers WHERE enabled=1')])
        self.spawn(self.scheduler())
        self.spawn(self.inventory_scheduler())

    async def close(self):
        self.stopping = True
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        if hasattr(self, 'client'):
            await self.client.close()
        if hasattr(self, 'radius_client'):
            await self.radius_client.close()
        self.store.close()
        self.process_lock.close()

    async def inventory_scheduler(self):
        while not self.stopping:
            if not self.sync_task or self.sync_task.done():
                rows = self.store.query('SELECT id FROM app_servers WHERE enabled=1 AND (last_sync IS NULL OR last_sync<?)', (time.time()-self.config.inventory_interval,))
                if rows:
                    self.sync_task = self.spawn(self.sync_inventory([row['id'] for row in rows]))
            await asyncio.sleep(min(30, self.config.inventory_interval))

    async def sync_inventory(self, server_ids, sync_id=None):
        sync_id = sync_id or secrets.token_hex(12)
        status = self.syncs.setdefault(sync_id, {'id': sync_id, 'state': 'running', 'completed': 0, 'total': len(server_ids), 'errors': []})
        gate = asyncio.Semaphore(4)
        async def one(server_id):
            async with gate:
                try:
                    sites = await self.collection(server_id, '/sites')
                    now = time.time()
                    references = [site['internalReference'] for site in sites if site.get('internalReference')]
                    if len(set(references)) != len(references) or any(not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', ref) for ref in references):
                        raise HTTPException(502, 'UniFi liefert ungültige oder mehrdeutige lokale Site-Verweise')
                    with self.store.transaction():
                        for site in sites:
                            from app.jobs import segment
                            segment(site['id'])
                            self.store.execute('INSERT INTO app_sites(server,site,name,synced,internal_reference) VALUES(?,?,?,?,?) ON CONFLICT(server,site) DO UPDATE SET name=excluded.name,synced=excluded.synced,internal_reference=excluded.internal_reference',
                                               (server_id, site['id'], site.get('name', site['id']), now, site.get('internalReference')))
                        self.store.execute('DELETE FROM app_sites WHERE server=? AND synced<?', (server_id, now))
                        self.store.execute("UPDATE app_servers SET status='online',error=NULL,last_sync=?,site_count=? WHERE id=?", (now, len(sites), server_id))
                except Exception:
                    self.store.execute("UPDATE app_servers SET status='error',error='Synchronisierung fehlgeschlagen; Verbindung, Zertifikat und API-Rechte prüfen' WHERE id=?", (server_id,))
                    status['errors'].append(server_id)
                finally:
                    status['completed'] += 1
        await asyncio.gather(*(one(server) for server in server_ids))
        status['state'] = 'completed' if not status['errors'] else 'partial'
        if len(self.syncs) > 100:
            for key in list(self.syncs)[:-50]:
                if self.syncs[key]['state'] not in ('running', 'queued'):
                    del self.syncs[key]
        return status

    async def scheduler(self):
        from app.jobs import plan_job, execute_job
        while not self.stopping:
            for row in self.store.query("SELECT id FROM batch_jobs WHERE state='planning' ORDER BY created LIMIT 3"):
                if row['id'] not in self.planning:
                    self.planning.add(row['id'])
                    async def plan_one(job_id):
                        try:
                            async with self.planner_limit:
                                await plan_job(self, job_id)
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            self.store.execute("UPDATE batch_jobs SET state='planning_failed',error='Vorschau konnte nicht abgeschlossen werden' WHERE id=?", (job_id,))
                        finally:
                            self.planning.discard(job_id)
                    self.spawn(plan_one(row['id']))
            if not self.active_job:
                row = self.store.one("SELECT id FROM batch_jobs WHERE state='queued' AND (run_after IS NULL OR run_after<=?) ORDER BY run_after,created LIMIT 1", (time.time(),))
                if row:
                    self.active_job = row['id']
                    async def run_one(job_id):
                        try:
                            await execute_job(self, job_id)
                        except asyncio.CancelledError:
                            self.store.execute("UPDATE batch_jobs SET state='interrupted' WHERE id=? AND state='running'", (job_id,))
                            raise
                        except Exception:
                            self.store.execute("UPDATE batch_jobs SET state='stopped',error='Ausführung unerwartet beendet; Zielergebnisse prüfen' WHERE id=?", (job_id,))
                        finally:
                            self.active_job = None
                    self.spawn(run_one(row['id']))
            await asyncio.sleep(.1)
