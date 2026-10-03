"""Persistent local and LDAP identities, scoped authorization, and GUI APIs."""
import asyncio
import hashlib
import hmac
import json
import re
import secrets
import time
import unicodedata
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from app.directory import DEFAULT_CONFIG, authenticate, authorize, validate_config
from app.security import password_hash, verify_password

PERMISSIONS = ('view', 'plan', 'approve', 'execute', 'users.manage', 'roles.manage', 'servers.manage', 'audit.export')
BUILTIN_ROLES = {
    'viewer': {'name': 'Lesen', 'permissions': ['view']},
    'operator': {'name': 'Betrieb', 'permissions': ['view', 'plan', 'execute']},
    'approver': {'name': 'Freigabe', 'permissions': ['view', 'approve']},
    'admin': {'name': 'Administration', 'permissions': list(PERMISSIONS)},
}
SESSION_SECONDS = 1800
IDLE_SECONDS = 900
LAST_SEEN_INTERVAL = 30


class Model(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Login(Model):
    name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256)


class UserCreate(Model):
    name: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=16, max_length=256)
    role: str = Field(max_length=64)
    scope: list[str] = Field(default_factory=lambda: ['*'], max_length=256)


class UserEdit(Model):
    role: str | None = Field(default=None, max_length=64)
    scope: list[str] | None = Field(default=None, max_length=256)
    enabled: StrictBool | None = None
    password: str | None = Field(default=None, min_length=16, max_length=256)


class RoleCreate(Model):
    id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=100)
    permissions: list[str] = Field(min_length=1, max_length=len(PERMISSIONS))


class RoleEdit(Model):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    permissions: list[str] | None = Field(default=None, min_length=1, max_length=len(PERMISSIONS))


class PasswordChange(Model):
    current_password: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=16, max_length=256)


class DirectoryEdit(Model):
    enabled: StrictBool = False
    url: str = Field(default='', max_length=1024)
    base_dn: str = Field(default='', max_length=1024)
    bind_dn: str = Field(default='', max_length=1024)
    ca_file: str = Field(default='', max_length=1024)
    bind_password: str | None = Field(default=None, max_length=1024)
    role_groups: dict[str, str] = Field(default_factory=dict)
    scope: list[str] = Field(default_factory=lambda: ['*'], max_length=256)
    user_attribute: str = 'sAMAccountName'
    object_class: str = 'user'
    group_attribute: str = 'memberOf'
    nested_ad_groups: StrictBool = False


def canonical_name(value, directory_allowed=True):
    value = unicodedata.normalize('NFKC', value).strip().casefold()
    directory = value.startswith('ad:')
    expression = r'ad:[a-z0-9_.@-]{1,96}' if directory else r'[a-z0-9_.@-]{1,80}'
    if not re.fullmatch(expression, value) or (directory and not directory_allowed):
        raise HTTPException(422, 'Ungültiger Kontoname; ad: ist für Verzeichniskonten reserviert')
    return value


def normalized_scope(scope):
    if not scope or len(scope) > 256 or any(s != '*' and not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}', s) for s in scope):
        raise HTTPException(422, 'Ungültiger Server-Berechtigungsbereich')
    if '*' in scope and scope != ['*']:
        raise HTTPException(422, 'Der globale Bereich darf nicht mit Servern kombiniert werden')
    return sorted(set(scope))


def normalized_permissions(permissions):
    if not permissions or set(permissions) - set(PERMISSIONS):
        raise HTTPException(422, 'Unbekannte Berechtigung')
    if 'view' not in permissions:
        raise HTTPException(422, 'Jede Rolle benötigt die Berechtigung view')
    return sorted(set(permissions))


class AuthService:
    def __init__(self, ctx):
        self.ctx, self.store = ctx, ctx.store
        for sql in (
            'CREATE TABLE IF NOT EXISTS auth_roles(id TEXT PRIMARY KEY,name TEXT NOT NULL,permissions TEXT NOT NULL,builtin INTEGER NOT NULL DEFAULT 0)',
            'CREATE TABLE IF NOT EXISTS auth_users(name TEXT PRIMARY KEY,password TEXT,role TEXT NOT NULL,scope TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,directory INTEGER NOT NULL DEFAULT 0,created REAL NOT NULL,updated REAL NOT NULL,version INTEGER NOT NULL DEFAULT 1)',
            'CREATE TABLE IF NOT EXISTS auth_sessions(token_hash TEXT PRIMARY KEY,name TEXT NOT NULL,version INTEGER NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,last_seen REAL NOT NULL)',
            'CREATE INDEX IF NOT EXISTS auth_sessions_name ON auth_sessions(name)',
            'CREATE TABLE IF NOT EXISTS auth_attempts(id INTEGER PRIMARY KEY,key TEXT NOT NULL,stamp REAL NOT NULL)',
            'CREATE INDEX IF NOT EXISTS auth_attempts_key ON auth_attempts(key,stamp)',
            'CREATE TABLE IF NOT EXISTS auth_settings(key TEXT PRIMARY KEY,value BLOB NOT NULL)',
        ):
            self.store.execute(sql)
        with self.store.transaction():
            for role_id, role in BUILTIN_ROLES.items():
                self.store.execute('INSERT OR IGNORE INTO auth_roles(id,name,permissions,builtin) VALUES(?,?,?,1)',
                                   (role_id, role['name'], json.dumps(role['permissions'])))
            if not self.store.one("SELECT key FROM auth_settings WHERE key='csrf_key'"):
                self.store.execute('INSERT INTO auth_settings(key,value) VALUES(?,?)', ('csrf_key', ctx.cipher.encrypt(secrets.token_bytes(32))))
            self.csrf_key = ctx.cipher.decrypt(self.store.one("SELECT value FROM auth_settings WHERE key='csrf_key'")['value'])
            self._bootstrap_users()
            self._bootstrap_directory()
            if not ctx.config.demo:
                try:
                    self._assert_admin_remains()
                except HTTPException:
                    raise RuntimeError('Mindestens eine aktive lokale Administration mit users.manage, roles.manage und globalem Server-Bereich ist erforderlich') from None
        self.dummy_password = password_hash(secrets.token_urlsafe(32))
        self.directory_checks = {}
        self.work_slots = asyncio.Semaphore(4)

    async def _blocking(self, function, *args):
        # Bound scrypt memory use and simultaneous directory connections. UniFi
        # jobs have separate concurrency controls and cannot exhaust these slots.
        async with self.work_slots:
            return await asyncio.to_thread(function, *args)

    def _bootstrap_users(self):
        if self.store.one("SELECT key FROM auth_settings WHERE key='users_imported'"):
            return
        if self.ctx.config.demo:
            users = {name: {'role': role, 'password': password_hash(password)} for name, role, password in (
                ('admin', 'admin', 'admin-demo-2026'), ('operator', 'operator', 'demo-operator-2026'), ('approver', 'approver', 'demo-approver-2026'))}
        elif self.ctx.config.users_file:
            users = json.loads(Path(self.ctx.config.users_file).read_text(encoding='utf-8-sig'))
        else:
            users = {}
        now = time.time()
        for raw_name, data in users.items():
            name = canonical_name(raw_name, directory_allowed=False)
            self._role(data['role'])
            scope = normalized_scope(data.get('scope', ['*']))
            enabled = data.get('enabled', True)
            if type(enabled) is not bool:
                raise RuntimeError('Ungültiger Konto-Aktivierungsstatus in der Kontodatei')
            encoded = data['password']
            if not isinstance(encoded, str) or not re.fullmatch(r'scrypt\$[0-9a-f]{32}\$[0-9a-f]{128}', encoded):
                raise RuntimeError('Ungültiger Passwort-Hash in der Kontodatei')
            if self._user(name):
                raise RuntimeError('Kontodatei enthält doppelte normalisierte Kontonamen')
            self.store.execute('INSERT INTO auth_users(name,password,role,scope,enabled,created,updated) VALUES(?,?,?,?,?,?,?)',
                               (name, encoded, data['role'], json.dumps(scope), int(enabled), now, now))
        self.store.execute('INSERT INTO auth_settings(key,value) VALUES(?,?)', ('users_imported', b'1'))

    def _bootstrap_directory(self):
        if self.store.one("SELECT key FROM auth_settings WHERE key='directory'"):
            return
        config, secret = dict(DEFAULT_CONFIG), None
        if self.ctx.config.ldap_config_file:
            raw = json.loads(Path(self.ctx.config.ldap_config_file).read_text(encoding='utf-8-sig'))
            config = validate_config({'enabled': True} | raw)
            for role in config['role_groups']:
                self._role(role)
            secret = raw.get('bind_password')
            if raw.get('bind_password_file'):
                secret = Path(raw['bind_password_file']).read_text(encoding='utf-8').strip()
            if config['enabled'] and not secret:
                raise RuntimeError('Die aktive Verzeichnisanbindung benötigt ein Bind-Passwort')
        self.store.execute('INSERT INTO auth_settings(key,value) VALUES(?,?)',
                           ('directory', self.ctx.cipher.encrypt(json.dumps({'config': config, 'secret': secret}).encode())))

    def _role(self, role):
        row = self.store.one('SELECT * FROM auth_roles WHERE id=?', (role,))
        if not row:
            raise HTTPException(422, 'Unbekannte Rolle')
        return row | {'permissions': json.loads(row['permissions']), 'builtin': bool(row['builtin'])}

    def _user(self, name):
        return self.store.one('SELECT * FROM auth_users WHERE name=?', (name,))

    @staticmethod
    def public_user(row):
        return {key: row[key] for key in ('name', 'role', 'created', 'updated')} | {
            'scope': json.loads(row['scope']), 'enabled': bool(row['enabled']), 'directory': bool(row['directory'])}

    def user(self, name):
        """Current public identity for queued work; never returns password material."""
        row = self._user(name)
        if not row:
            return None
        role = self.store.one('SELECT permissions FROM auth_roles WHERE id=?', (row['role'],))
        public = self.public_user(row) | {'permissions': json.loads(role['permissions']) if role else []}
        if row['directory']:
            config = self.directory()
            public['enabled'] = bool(public['enabled'] and config['enabled'] and row['role'] in config['role_groups'])
        return public

    def directory(self, public=True):
        row = self.store.one("SELECT value FROM auth_settings WHERE key='directory'")
        value = json.loads(self.ctx.cipher.decrypt(row['value']))
        return value['config'] | {'bind_password_set': bool(value['secret'])} if public else value

    async def reauthorize(self, name):
        """Current queued-work identity, including fresh LDAPS membership checks.

        Positive and negative directory checks are cached for at most 60 seconds;
        local account/configuration/role changes invalidate the versioned cache.
        """
        row = self._user(name)
        if not row or not row['enabled']:
            return None
        if not row['directory']:
            return self.user(name)
        value = self.directory(public=False)
        if not value['config']['enabled']:
            return None
        fingerprint = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
        cache = self.directory_checks.get(name)
        if cache and cache['version'] == row['version'] and cache['config'] == fingerprint and cache['stamp'] + 60 > time.monotonic():
            return self.user(name) if cache['valid'] else None
        try:
            role = await self._blocking(authorize, value['config'], name[3:], value['secret'])
        except Exception:
            role = None
        with self.store.transaction():
            current = self._user(name)
            if not current or not current['enabled'] or current['version'] != row['version'] or value != self.directory(public=False):
                return None
            if not role or not self.store.one('SELECT id FROM auth_roles WHERE id=?', (role,)):
                self._revoke(name)
                self.ctx.audit(name, 'directory_authorization_denied', 'Verzeichnisberechtigung nicht bestätigt; Sitzungen widerrufen')
                valid = False
            else:
                valid = True
                if current['role'] != role:
                    self._revoke(name)
                    self.store.execute('UPDATE auth_users SET role=? WHERE name=?', (role, name))
                    self.ctx.audit(name, 'directory_role_changed', role)
            current = self._user(name)
            self.directory_checks[name] = {'stamp': time.monotonic(), 'version': current['version'], 'config': fingerprint, 'valid': valid}
        return self.user(name) if valid else None

    def _grant(self, actor, role, scope):
        """Delegated administrators cannot grant authority they do not have."""
        permissions = self._role(role)['permissions']
        if not set(permissions).issubset(actor['permissions']):
            raise HTTPException(403, 'Die Rolle überschreitet die eigenen Berechtigungen')
        if '*' not in actor['scope'] and ('*' in scope or not set(scope).issubset(actor['scope'])):
            raise HTTPException(403, 'Der Bereich überschreitet die eigenen Server-Berechtigungen')

    @staticmethod
    def _grant_permissions(actor, permissions):
        if not set(permissions).issubset(actor['permissions']):
            raise HTTPException(403, 'Die Rolle überschreitet die eigenen Berechtigungen')

    def _manage_role(self, actor, role_id):
        for row in self.store.query('SELECT role,scope FROM auth_users WHERE role=?', (role_id,)):
            self._grant(actor, row['role'], json.loads(row['scope']))
        config = self.directory()
        if role_id in config['role_groups']:
            self._grant(actor, role_id, config['scope'])

    def _csrf(self, token_hash):
        return hmac.new(self.csrf_key, token_hash.encode(), hashlib.sha256).hexdigest()

    def _origin(self, request):
        if request.method not in ('GET', 'HEAD', 'OPTIONS') and request.headers.get('origin') != self.ctx.config.origin:
            raise HTTPException(403, 'Ungültiger Ursprung')

    def identity(self, request, permission=None):
        self._origin(request)
        token = request.cookies.get('session', '')
        if not token or len(token) > 200:
            raise HTTPException(401, 'Bitte anmelden')
        digest = hashlib.sha256(token.encode()).hexdigest()
        session = self.store.one('SELECT * FROM auth_sessions WHERE token_hash=?', (digest,))
        now = time.time()
        row = self._user(session['name']) if session else None
        if not session or not row or not row['enabled'] or session['expires'] <= now or session['last_seen'] + IDLE_SECONDS <= now or session['version'] != row['version']:
            self.store.execute('DELETE FROM auth_sessions WHERE token_hash=?', (digest,))
            raise HTTPException(401, 'Bitte anmelden')
        user = self.user(row['name'])
        if not user['enabled']:
            raise HTTPException(401, 'Bitte anmelden')
        if permission and permission not in user['permissions']:
            raise HTTPException(403, 'Keine Berechtigung')
        csrf = self._csrf(digest)
        if request.method not in ('GET', 'HEAD', 'OPTIONS') and not hmac.compare_digest(request.headers.get('x-csrf-token', ''), csrf):
            raise HTTPException(403, 'Ungültiger CSRF-Token')
        if now - session['last_seen'] >= LAST_SEEN_INTERVAL:
            self.store.execute('UPDATE auth_sessions SET last_seen=? WHERE token_hash=?', (now, digest))
        return user | {'csrf': csrf}

    @staticmethod
    def require_scope(user, server):
        if '*' not in user['scope'] and server not in user['scope']:
            raise HTTPException(403, 'Server liegt außerhalb des Berechtigungsbereichs')

    def _revoke(self, name):
        self.store.execute('DELETE FROM auth_sessions WHERE name=?', (name,))
        self.store.execute('UPDATE auth_users SET version=version+1,updated=? WHERE name=?', (time.time(), name))

    def _assert_admin_remains(self, replacement_user=None, replacement_role=None):
        roles = {row['id']: json.loads(row['permissions']) for row in self.store.query('SELECT id,permissions FROM auth_roles')}
        if replacement_role:
            roles[replacement_role[0]] = replacement_role[1]
        for row in self.store.query('SELECT name,role,enabled,scope FROM auth_users WHERE directory=0'):
            if replacement_user and row['name'] == replacement_user['name']:
                row = row | replacement_user
            if row['enabled'] and json.loads(row['scope']) == ['*'] and {'users.manage', 'roles.manage'}.issubset(roles.get(row['role'], [])):
                return
        raise HTTPException(409, 'Die letzte aktive lokale Administration mit globalem Server-Bereich muss erhalten bleiben')

    def _rate_limit(self, request, name):
        now = time.time()
        address = request.client.host if request.client else 'unknown'
        with self.store.transaction():
            self.store.execute('DELETE FROM auth_attempts WHERE stamp<?', (now - 900,))
            for key, limit in ((f'ip:{address}', 30), (f'user:{name}', 10)):
                count = self.store.one('SELECT COUNT(*) AS count FROM auth_attempts WHERE key=?', (key,))['count']
                if count >= limit:
                    raise HTTPException(429, 'Zu viele Versuche. Nach 15 Minuten erneut versuchen.', headers={'Retry-After': '900'})
            for key in (f'ip:{address}', f'user:{name}'):
                self.store.execute('INSERT INTO auth_attempts(key,stamp) VALUES(?,?)', (key, now))

    def install(self, app):
        @app.post('/api/login')
        async def login(data: Login, request: Request):
            self._origin(request)
            name = canonical_name(data.name)
            self._rate_limit(request, name)
            directory = name.startswith('ad:')
            row, valid, role = self._user(name), False, None
            if directory:
                value = self.directory(public=False)
                if value['config']['enabled'] and (not row or row['enabled']):
                    try:
                        role = await self._blocking(authenticate, value['config'], name[3:], data.password, value['secret'])
                        valid = bool(role and self.store.one('SELECT id FROM auth_roles WHERE id=?', (role,)))
                    except Exception:
                        valid = False
            else:
                valid = await self._blocking(verify_password, data.password, row['password'] if row and not row['directory'] else self.dummy_password)
                valid = bool(valid and row and row['enabled'] and not row['directory'])
            if not valid:
                self.ctx.audit('anonymous', 'login_failed', 'Anmeldung abgewiesen')
                raise HTTPException(401, 'Anmeldung fehlgeschlagen')
            now = time.time()
            token = secrets.token_urlsafe(32)
            digest = hashlib.sha256(token.encode()).hexdigest()
            with self.store.transaction():
                current = self._user(name)
                if current and (not current['enabled'] or (row and current['version'] != row['version'])):
                    raise HTTPException(401, 'Anmeldung fehlgeschlagen')
                if directory:
                    # A configuration change during LDAPS cannot authorize a stale result.
                    if value != self.directory(public=False):
                        raise HTTPException(401, 'Anmeldung fehlgeschlagen')
                    if not current:
                        self.store.execute('INSERT INTO auth_users(name,role,scope,directory,created,updated) VALUES(?,?,?,1,?,?)',
                                           (name, role, json.dumps(value['config']['scope']), now, now))
                    elif current['role'] != role:
                        self._revoke(name)
                        self.store.execute('UPDATE auth_users SET role=? WHERE name=?', (role, name))
                    self.directory_checks.pop(name, None)
                current = self._user(name)
                self.store.execute('DELETE FROM auth_sessions WHERE expires<=? OR last_seen<=?', (now, now-IDLE_SECONDS))
                self.store.execute('INSERT INTO auth_sessions(token_hash,name,version,created,expires,last_seen) VALUES(?,?,?,?,?,?)',
                                   (digest, name, current['version'], now, now+SESSION_SECONDS, now))
            self.ctx.audit(name, 'login', 'Anmeldung erfolgreich')
            response = JSONResponse(self.user(name) | {'csrf': self._csrf(digest)})
            response.set_cookie('session', token, httponly=True, secure=not self.ctx.config.demo, samesite='strict', max_age=SESSION_SECONDS, path='/')
            return response

        @app.post('/api/logout')
        async def logout(request: Request):
            user = self.identity(request)
            digest = hashlib.sha256(request.cookies['session'].encode()).hexdigest()
            self.store.execute('DELETE FROM auth_sessions WHERE token_hash=?', (digest,))
            self.ctx.audit(user['name'], 'logout', 'Abmeldung')
            response = JSONResponse({'ok': True})
            response.delete_cookie('session', httponly=True, secure=not self.ctx.config.demo, samesite='strict', path='/')
            return response

        @app.get('/api/me')
        async def me(request: Request):
            return self.identity(request) | {'demo': self.ctx.config.demo, 'writes': getattr(self.ctx.config, 'writes', False)}

        @app.get('/api/users')
        async def users(request: Request):
            actor = self.identity(request, 'users.manage')
            visible = []
            for row in self.store.query('SELECT * FROM auth_users ORDER BY name'):
                try:
                    self._grant(actor, row['role'], json.loads(row['scope']))
                except HTTPException:
                    continue
                visible.append(self.public_user(row))
            return visible

        @app.post('/api/users')
        async def create_user(data: UserCreate, request: Request):
            actor = self.identity(request, 'users.manage')
            name = canonical_name(data.name, directory_allowed=False)
            self._role(data.role)
            scope = normalized_scope(data.scope)
            self._grant(actor, data.role, scope)
            encoded = await self._blocking(password_hash, data.password)
            with self.store.transaction():
                self.identity(request, 'users.manage')
                self._grant(self.user(actor['name']), data.role, scope)
                if self._user(name):
                    raise HTTPException(409, 'Kontoname bereits vorhanden')
                now = time.time()
                self.store.execute('INSERT INTO auth_users(name,password,role,scope,created,updated) VALUES(?,?,?,?,?,?)',
                                   (name, encoded, data.role, json.dumps(scope), now, now))
                self.ctx.audit(actor['name'], 'user_created', name)
            return self.public_user(self._user(name))

        @app.patch('/api/users/{name}')
        async def edit_user(name: str, data: UserEdit, request: Request):
            actor = self.identity(request, 'users.manage')
            name = canonical_name(name)
            row = self._user(name)
            if not row:
                raise HTTPException(404, 'Konto unbekannt')
            self._grant(actor, row['role'], json.loads(row['scope']))
            values = data.model_dump(exclude_unset=True)
            if not values or any(value is None for value in values.values()):
                raise HTTPException(422, 'Keine gültigen Kontoänderungen angegeben')
            if row['directory'] and ('password' in values or 'role' in values):
                raise HTTPException(422, 'Rolle und Passwort des Verzeichniskontos werden im Verzeichnis verwaltet')
            if values.get('enabled') is False and name == actor['name']:
                raise HTTPException(409, 'Das eigene Konto kann nicht deaktiviert werden')
            if 'role' in values:
                self._role(values['role'])
            self._grant(actor, values.get('role', row['role']), values.get('scope', json.loads(row['scope'])))
            if 'scope' in values:
                values['scope'] = json.dumps(normalized_scope(values['scope']))
            if 'password' in values:
                values['password'] = await self._blocking(password_hash, values['password'])
            with self.store.transaction():
                self.identity(request, 'users.manage')
                current = self._user(name)
                self._grant(self.user(actor['name']), current['role'], json.loads(current['scope']))
                self._grant(self.user(actor['name']), values.get('role', current['role']), json.loads(values.get('scope', current['scope'])))
                self._assert_admin_remains(current | values)
                fields = ','.join(f'{key}=?' for key in values)
                self.store.execute(f'UPDATE auth_users SET {fields} WHERE name=?', tuple(values.values()) + (name,))  # nosec B608 # UserEdit forbids extra keys; all values are bound parameters.
                self._revoke(name)
                self.ctx.audit(actor['name'], 'user_updated', name + ':' + ','.join(sorted(values)))
            return self.public_user(self._user(name))

        @app.get('/api/roles')
        async def roles(request: Request):
            user = self.identity(request)
            if not {'users.manage', 'roles.manage'}.intersection(user['permissions']):
                raise HTTPException(403, 'Keine Berechtigung')
            return [row | {'permissions': json.loads(row['permissions']), 'builtin': bool(row['builtin'])}
                    for row in self.store.query('SELECT * FROM auth_roles ORDER BY builtin DESC,id')]

        @app.post('/api/roles')
        async def create_role(data: RoleCreate, request: Request):
            actor = self.identity(request, 'roles.manage')
            if not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', data.id) or not data.name.strip():
                raise HTTPException(422, 'Ungültige Rollenbezeichnung')
            permissions = normalized_permissions(data.permissions)
            self._grant_permissions(actor, permissions)
            with self.store.transaction():
                if self.store.one('SELECT id FROM auth_roles WHERE id=?', (data.id,)):
                    raise HTTPException(409, 'Rollen-ID bereits vorhanden')
                self.store.execute('INSERT INTO auth_roles(id,name,permissions) VALUES(?,?,?)', (data.id, data.name.strip(), json.dumps(permissions)))
                self.ctx.audit(actor['name'], 'role_created', data.id)
            return self._role(data.id)

        @app.patch('/api/roles/{role_id}')
        async def edit_role(role_id: str, data: RoleEdit, request: Request):
            actor = self.identity(request, 'roles.manage')
            role = self._role(role_id)
            if role['builtin']:
                raise HTTPException(409, 'Standardrollen sind unveränderlich; eine eigene Rolle erstellen')
            self._grant_permissions(actor, role['permissions'])
            self._manage_role(actor, role_id)
            values = data.model_dump(exclude_unset=True)
            if not values or any(value is None for value in values.values()):
                raise HTTPException(422, 'Keine gültigen Rollenänderungen angegeben')
            if 'name' in values:
                if not values['name'].strip():
                    raise HTTPException(422, 'Rollenname darf nicht leer sein')
                values['name'] = values['name'].strip()
            if 'permissions' in values:
                permissions = normalized_permissions(values['permissions'])
                self._grant_permissions(actor, permissions)
                values['permissions'] = json.dumps(permissions)
            with self.store.transaction():
                if 'permissions' in values:
                    self._assert_admin_remains(replacement_role=(role_id, permissions))
                fields = ','.join(f'{key}=?' for key in values)
                self.store.execute(f'UPDATE auth_roles SET {fields} WHERE id=?', tuple(values.values()) + (role_id,))  # nosec B608 # RoleEdit forbids extra keys; all values are bound parameters.
                for user in self.store.query('SELECT name FROM auth_users WHERE role=?', (role_id,)):
                    self._revoke(user['name'])
                self.ctx.audit(actor['name'], 'role_updated', role_id)
            return self._role(role_id)

        @app.delete('/api/roles/{role_id}')
        async def delete_role(role_id: str, request: Request):
            actor = self.identity(request, 'roles.manage')
            role = self._role(role_id)
            if role['builtin']:
                raise HTTPException(409, 'Standardrollen können nicht entfernt werden')
            self._grant_permissions(actor, role['permissions'])
            self._manage_role(actor, role_id)
            with self.store.transaction():
                if self.store.one('SELECT name FROM auth_users WHERE role=? LIMIT 1', (role_id,)) or role_id in self.directory()['role_groups']:
                    raise HTTPException(409, 'Rolle ist einem Konto oder einer Verzeichnisgruppe zugeordnet')
                self.store.execute('DELETE FROM auth_roles WHERE id=?', (role_id,))
                self.ctx.audit(actor['name'], 'role_deleted', role_id)
            return {'ok': True}

        @app.get('/api/directory')
        async def get_directory(request: Request):
            self.identity(request, 'users.manage')
            return self.directory()

        @app.put('/api/directory')
        async def put_directory(data: DirectoryEdit, request: Request):
            actor = self.identity(request, 'users.manage')
            if '*' not in actor['scope']:
                raise HTTPException(403, 'Verzeichnisverwaltung erfordert den globalen Server-Bereich')
            try:
                config = validate_config(data.model_dump(exclude={'bind_password'}))
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from None
            for role in config['role_groups']:
                self._grant(actor, role, config['scope'])
            previous = self.directory(public=False)
            secret = data.bind_password if data.bind_password is not None else previous['secret']
            if config['enabled'] and not secret:
                raise HTTPException(422, 'Ein Bind-Passwort ist erforderlich')
            with self.store.transaction():
                value = self.ctx.cipher.encrypt(json.dumps({'config': config, 'secret': secret}).encode())
                self.store.execute("UPDATE auth_settings SET value=? WHERE key='directory'", (value,))
                for user in self.store.query('SELECT name FROM auth_users WHERE directory=1'):
                    self._revoke(user['name'])
                self.ctx.audit(actor['name'], 'directory_updated', 'Verzeichniseinstellungen geändert; Verzeichnissitzungen widerrufen')
            return self.directory()

        @app.post('/api/password')
        async def change_password(data: PasswordChange, request: Request):
            actor = self.identity(request)
            row = self._user(actor['name'])
            if row['directory']:
                raise HTTPException(422, 'Passwort des Verzeichniskontos im Verzeichnis ändern')
            self._rate_limit(request, 'password:' + actor['name'])
            if not await self._blocking(verify_password, data.current_password, row['password']):
                raise HTTPException(401, 'Aktuelles Passwort ungültig')
            encoded = await self._blocking(password_hash, data.password)
            with self.store.transaction():
                self.identity(request)
                self.store.execute('UPDATE auth_users SET password=? WHERE name=?', (encoded, actor['name']))
                self._revoke(actor['name'])
                self.ctx.audit(actor['name'], 'password_changed', 'Alle Sitzungen des Kontos widerrufen')
            response = JSONResponse({'ok': True, 'reauthenticate': True})
            response.delete_cookie('session', httponly=True, secure=not self.ctx.config.demo, samesite='strict', path='/')
            return response
