"""Authorization regressions independent of UniFi connectivity and the batch engine."""
import hashlib
import asyncio
import json
import ssl
import time
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app import auth as auth_module
from app import directory as directory_module
from app.auth import AuthService
from app.security import password_hash
from app.storage import Store

ORIGIN = {'Origin': 'http://testserver'}
PASSWORD = 'Valid-password-2026!'


@pytest.fixture
def harness(tmp_path):
    audits = []
    ctx = SimpleNamespace(
        config=SimpleNamespace(demo=True, writes=False, origin='http://testserver', users_file=None, ldap_config_file=None),
        store=Store(tmp_path / 'identity.sqlite'), cipher=Fernet(Fernet.generate_key()),
        audit=lambda actor, action, detail: audits.append((actor, action, detail)),
    )
    service = AuthService(ctx)
    app = FastAPI()
    service.install(app)

    @app.get('/probe/{server}')
    async def probe(server: str, request: Request):
        user = service.identity(request, 'view')
        service.require_scope(user, server)
        return {'ok': True}

    yield SimpleNamespace(ctx=ctx, service=service, app=app, audits=audits)
    ctx.store.close()


def signed(harness, name='admin', password=None):
    client = TestClient(harness.app)
    response = client.post('/api/login', headers=ORIGIN, json={'name': name, 'password': password or ('admin-demo-2026' if name.casefold() == 'admin' else f'demo-{name}-2026')})
    assert response.status_code == 200, response.text
    client.headers.update(ORIGIN | {'X-CSRF-Token': response.json()['csrf']})
    return client


def new_user(admin, name='alice', role='viewer', scope=None):
    return admin.post('/api/users', json={'name': name, 'password': PASSWORD, 'role': role, 'scope': scope or ['*']})


def ldap_settings(**changes):
    return {'enabled': True, 'url': 'ldaps://directory.intern:636', 'base_dn': 'dc=intern', 'bind_dn': 'cn=service,dc=intern',
            'role_groups': {'viewer': 'cn=read,dc=intern'}, 'bind_password': 'service-secret-value', 'scope': ['srv-1']} | changes


def test_password_and_tokens_are_never_public_or_stored_raw(harness):
    admin = signed(harness)
    token = admin.cookies['session']
    sessions = harness.ctx.store.query('SELECT * FROM auth_sessions')
    assert sessions[0]['token_hash'] == hashlib.sha256(token.encode()).hexdigest()
    assert token not in json.dumps(sessions)
    assert new_user(admin).status_code == 200
    public = admin.get('/api/users').json()
    assert all('password' not in row and 'version' not in row for row in public)
    row = harness.ctx.store.one("SELECT password FROM auth_users WHERE name='alice'")
    assert row['password'].startswith('scrypt$') and PASSWORD not in row['password']
    assert 'password' not in harness.service.user('alice')


def test_casefold_reserved_prefix_and_duplicate_identity(harness):
    admin = signed(harness, 'ADMIN')
    assert new_user(admin, 'Alice').json()['name'] == 'alice'
    assert new_user(admin, 'ALICE').status_code == 409
    assert new_user(admin, 'ＡＬＩＣＥ').status_code == 409
    assert new_user(admin, 'AD:alice').status_code == 422
    assert new_user(admin, 'bad/name').status_code == 422
    assert signed(harness, 'ALICE', PASSWORD).get('/api/me').json()['name'] == 'alice'


def test_csrf_origin_and_cookie_policy(harness):
    anon = TestClient(harness.app)
    assert anon.get('/api/me').status_code == 401
    assert anon.post('/api/login', json={'name': 'admin', 'password': 'admin-demo-2026'}).status_code == 403
    admin = signed(harness)
    assert admin.get('/api/me').status_code == 200
    admin.headers['X-CSRF-Token'] = 'invalid'
    assert admin.post('/api/logout').status_code == 403
    admin = signed(harness)
    assert admin.post('/api/logout').status_code == 200
    assert admin.get('/api/me').status_code == 401
    harness.ctx.config.demo = False
    response = anon.post('/api/login', headers=ORIGIN, json={'name': 'admin', 'password': 'admin-demo-2026'})
    cookie = response.headers['set-cookie'].lower()
    assert 'secure' in cookie and 'httponly' in cookie and 'samesite=strict' in cookie


def test_server_scope_and_management_permissions(harness):
    admin = signed(harness)
    assert new_user(admin, scope=['srv-1']).status_code == 200
    user = signed(harness, 'alice', PASSWORD)
    assert user.get('/probe/srv-1').status_code == 200
    assert user.get('/probe/srv-2').status_code == 403
    assert user.get('/api/users').status_code == 403
    assert user.get('/api/roles').status_code == 403
    assert user.get('/api/directory').status_code == 403
    assert new_user(admin, 'bad-scope', scope=['*', 'srv-1']).status_code == 422


def test_disable_and_permissions_changes_revoke_every_session(harness):
    admin = signed(harness)
    new_user(admin, role='operator')
    first, second = signed(harness, 'alice', PASSWORD), signed(harness, 'alice', PASSWORD)
    assert admin.patch('/api/users/alice', json={'enabled': False}).status_code == 200
    assert first.get('/api/me').status_code == second.get('/api/me').status_code == 401
    assert not harness.service.user('alice')['enabled']
    assert admin.patch('/api/users/alice', json={'enabled': True, 'role': 'viewer'}).status_code == 200
    user = signed(harness, 'alice', PASSWORD)
    assert user.get('/api/me').json()['permissions'] == ['view']
    assert admin.patch('/api/users/alice', json={'scope': ['srv-1']}).status_code == 200
    assert user.get('/api/me').status_code == 401


def test_self_disable_and_last_local_admin_guard(harness):
    admin = signed(harness)
    assert admin.patch('/api/users/admin', json={'enabled': False}).status_code == 409
    assert admin.patch('/api/users/admin', json={'role': 'viewer'}).status_code == 409
    assert new_user(admin, 'second-admin', role='admin').status_code == 200
    second = signed(harness, 'second-admin', PASSWORD)
    assert admin.patch('/api/users/admin', json={'role': 'viewer'}).status_code == 200
    assert admin.get('/api/me').status_code == 401
    assert second.patch('/api/users/second-admin', json={'role': 'viewer'}).status_code == 409


def test_custom_roles_revoke_sessions_and_removal_guard(harness):
    admin = signed(harness)
    response = admin.post('/api/roles', json={'id': 'reviewer', 'name': 'Prüfung', 'permissions': ['view', 'approve']})
    assert response.status_code == 200 and not response.json()['builtin']
    new_user(admin, role='reviewer')
    user = signed(harness, 'alice', PASSWORD)
    assert admin.patch('/api/roles/reviewer', json={'permissions': ['view']}).status_code == 200
    assert user.get('/api/me').status_code == 401
    assert harness.service.user('alice')['permissions'] == ['view']
    assert admin.delete('/api/roles/reviewer').status_code == 409
    assert admin.patch('/api/users/alice', json={'role': 'viewer'}).status_code == 200
    assert admin.delete('/api/roles/reviewer').status_code == 200
    assert admin.patch('/api/roles/admin', json={'permissions': ['view']}).status_code == 409
    assert admin.delete('/api/roles/operator').status_code == 409


def test_last_admin_is_checked_by_effective_permissions(harness):
    admin = signed(harness)
    assert admin.post('/api/roles', json={'id': 'recovery', 'name': 'Kontenverwaltung', 'permissions': ['view', 'users.manage', 'roles.manage']}).status_code == 200
    new_user(admin, 'recovery-admin', role='recovery')
    assert admin.patch('/api/users/admin', json={'role': 'viewer'}).status_code == 200
    recovered = signed(harness, 'recovery-admin', PASSWORD)
    assert recovered.patch('/api/roles/recovery', json={'permissions': ['view', 'roles.manage']}).status_code == 409
    assert recovered.patch('/api/users/recovery-admin', json={'role': 'viewer'}).status_code == 409


def test_password_change_revokes_all_sessions_and_requires_old_password(harness):
    admin = signed(harness)
    new_user(admin)
    first, second = signed(harness, 'alice', PASSWORD), signed(harness, 'alice', PASSWORD)
    assert first.post('/api/password', json={'current_password': 'incorrect', 'password': 'New-valid-password-2026'}).status_code == 401
    assert first.post('/api/password', json={'current_password': PASSWORD, 'password': 'New-valid-password-2026'}).json()['reauthenticate']
    assert first.get('/api/me').status_code == second.get('/api/me').status_code == 401
    assert signed(harness, 'alice', 'New-valid-password-2026').get('/api/me').status_code == 200


def test_sessions_survive_restart_hashed_and_expire_absolute_or_idle(harness):
    admin = signed(harness)
    restarted = AuthService(harness.ctx)
    assert restarted.user('admin')['enabled']
    assert restarted.csrf_key == harness.service.csrf_key
    assert admin.get('/api/me').status_code == 200
    harness.ctx.store.execute('UPDATE auth_sessions SET last_seen=?', (time.time()-901,))
    assert admin.get('/api/me').status_code == 401
    admin = signed(harness)
    harness.ctx.store.execute('UPDATE auth_sessions SET expires=0')
    assert admin.get('/api/me').status_code == 401


def test_session_polling_batches_last_seen_writes_without_caching_permissions(harness):
    admin = signed(harness)
    statements = []
    harness.ctx.store.connection.set_trace_callback(statements.append)
    try:
        assert admin.get('/api/me').status_code == 200
        assert admin.get('/api/me').status_code == 200
        assert not any(sql.startswith('UPDATE auth_sessions SET last_seen') for sql in statements)
        harness.ctx.store.execute('UPDATE auth_sessions SET last_seen=?', (time.time()-31,))
        statements.clear()
        assert admin.get('/api/me').status_code == 200
        assert sum(sql.startswith('UPDATE auth_sessions SET last_seen') for sql in statements) == 1
        harness.ctx.store.execute("UPDATE auth_roles SET permissions='[\"view\"]' WHERE id='admin'")
        assert admin.get('/api/me').json()['permissions'] == ['view']
        assert admin.get('/api/users').status_code == 403
    finally:
        harness.ctx.store.connection.set_trace_callback(None)


def test_login_rate_limiting_persists(harness):
    anon = TestClient(harness.app)
    for _ in range(10):
        assert anon.post('/api/login', headers=ORIGIN, json={'name': 'nobody', 'password': 'wrong'}).status_code == 401
    AuthService(harness.ctx)
    response = anon.post('/api/login', headers=ORIGIN, json={'name': 'NOBODY', 'password': 'wrong'})
    assert response.status_code == 429 and response.headers['retry-after'] == '900'


@pytest.mark.parametrize('payload', [
    {'password': 'short'}, {'enabled': 'false'}, {'scope': []}, {'role': 'missing'}, {'unknown': 'x'}, {'role': None}, {},
])
def test_invalid_user_updates_are_rejected(harness, payload):
    admin = signed(harness)
    new_user(admin)
    assert admin.patch('/api/users/alice', json=payload).status_code == 422


def test_bootstrap_import_is_once_and_gui_overrides_file(harness, tmp_path):
    path = tmp_path / 'users.json'
    path.write_text(json.dumps({'Alice': {'role': 'viewer', 'password': password_hash(PASSWORD)}}), encoding='utf-8')
    harness.ctx.config.users_file = str(path)
    AuthService(harness.ctx)
    assert harness.service.user('alice') is None  # An imported database does not reimport files.
    admin = signed(harness)
    new_user(admin)
    assert admin.patch('/api/users/alice', json={'enabled': False}).status_code == 200
    AuthService(harness.ctx)
    assert not harness.service.user('alice')['enabled']


@pytest.mark.parametrize('role,enabled,scope', [
    ('operator', True, ['*']), ('admin', False, ['*']), ('admin', True, ['srv-1']),
])
def test_production_bootstrap_requires_active_global_recovery(harness, tmp_path, role, enabled, scope):
    path = tmp_path / 'bootstrap-users.json'
    path.write_text(json.dumps({'bootstrap': {'role': role, 'password': password_hash(PASSWORD), 'scope': scope, 'enabled': enabled}}), encoding='utf-8')
    store = Store(tmp_path / 'production.sqlite')
    ctx = SimpleNamespace(config=SimpleNamespace(demo=False, writes=False, origin='https://intern.example', users_file=str(path), ldap_config_file=None),
                          store=store, cipher=harness.ctx.cipher, audit=harness.ctx.audit)
    try:
        with pytest.raises(RuntimeError, match='lokale Administration'):
            AuthService(ctx)
        assert store.one("SELECT key FROM auth_settings WHERE key='users_imported'") is None
        path.write_text(json.dumps({'bootstrap': {'role': 'admin', 'password': password_hash(PASSWORD), 'scope': ['*']}}), encoding='utf-8')
        assert AuthService(ctx).user('bootstrap')['enabled']
    finally:
        store.close()


def test_production_restart_checks_existing_recovery_account(harness):
    harness.ctx.config.demo = False
    harness.ctx.store.execute("UPDATE auth_users SET enabled=0 WHERE name='admin'")
    with pytest.raises(RuntimeError, match='lokale Administration'):
        AuthService(harness.ctx)


def test_gui_cannot_remove_last_global_recovery_scope(harness):
    admin = signed(harness)
    assert admin.patch('/api/users/admin', json={'scope': ['srv-1']}).status_code == 409
    new_user(admin, 'scoped-admin', role='admin', scope=['srv-2'])
    assert admin.patch('/api/users/admin', json={'scope': ['srv-1']}).status_code == 409
    new_user(admin, 'global-admin', role='admin')
    assert admin.patch('/api/users/admin', json={'scope': ['srv-1']}).status_code == 200
    global_admin = signed(harness, 'global-admin', PASSWORD)
    assert global_admin.patch('/api/users/global-admin', json={'scope': ['srv-2']}).status_code == 409


def test_directory_secret_is_encrypted_write_only_and_preserved(harness):
    admin = signed(harness)
    response = admin.put('/api/directory', json=ldap_settings())
    assert response.status_code == 200 and response.json()['bind_password_set']
    assert 'service-secret-value' not in response.text
    value = harness.ctx.store.one("SELECT value FROM auth_settings WHERE key='directory'")['value']
    assert b'service-secret-value' not in value
    settings = response.json()
    settings.pop('bind_password_set')
    assert admin.put('/api/directory', json=settings).status_code == 200
    assert harness.service.directory(public=False)['secret'] == 'service-secret-value'
    assert all('service-secret-value' not in str(event) for event in harness.audits)


@pytest.mark.parametrize('changes', [
    {'url': 'ldap://directory.intern'}, {'url': 'ldaps://user:pass@directory.intern'}, {'url': 'ldaps://directory.intern/other'},
    {'role_groups': {'viewer': 'cn=same', 'operator': 'CN=SAME'}}, {'role_groups': {'missing': 'cn=group'}},
    {'user_attribute': 'uid)(objectClass=*'}, {'scope': ['*', 'srv-1']}, {'bind_password': ''},
])
def test_invalid_directory_configuration_is_rejected(harness, changes):
    admin = signed(harness)
    assert admin.put('/api/directory', json=ldap_settings(**changes)).status_code == 422


def test_ad_persistent_account_no_fallback_disable_and_mapping_revocation(harness, monkeypatch):
    admin = signed(harness)
    assert admin.put('/api/directory', json=ldap_settings()).status_code == 200
    seen = []

    def authenticate(config, name, password, secret):
        seen.append((name, secret))
        return 'viewer' if password == PASSWORD else None

    monkeypatch.setattr(auth_module, 'authenticate', authenticate)
    user = signed(harness, 'ad:ALICE', PASSWORD)
    assert seen == [('alice', 'service-secret-value')]
    assert harness.service.user('ad:alice')['directory']
    assert user.get('/probe/srv-1').status_code == 200
    assert user.get('/probe/srv-2').status_code == 403
    assert admin.patch('/api/users/ad:alice', json={'password': PASSWORD}).status_code == 422
    assert admin.patch('/api/users/ad:alice', json={'role': 'operator'}).status_code == 422
    assert admin.patch('/api/users/ad:alice', json={'enabled': False}).status_code == 200
    assert user.get('/api/me').status_code == 401
    assert TestClient(harness.app).post('/api/login', headers=ORIGIN, json={'name': 'ad:alice', 'password': PASSWORD}).status_code == 401
    assert admin.patch('/api/users/ad:alice', json={'enabled': True}).status_code == 200
    user = signed(harness, 'ad:alice', PASSWORD)
    assert admin.put('/api/directory', json=ldap_settings(enabled=False)).status_code == 200
    assert user.get('/api/me').status_code == 401
    assert not harness.service.user('ad:alice')['enabled']


def test_ad_failure_is_generic_and_does_not_create_account(harness, monkeypatch):
    admin = signed(harness)
    admin.put('/api/directory', json=ldap_settings())

    def unavailable(*args):
        raise RuntimeError('Internal bind secret service-secret-value')

    monkeypatch.setattr(auth_module, 'authenticate', unavailable)
    response = TestClient(harness.app).post('/api/login', headers=ORIGIN, json={'name': 'ad:alice', 'password': PASSWORD})
    assert response.status_code == 401 and 'secret' not in response.text
    assert harness.service.user('ad:alice') is None


def test_ldap_transport_and_ambiguous_groups_fail_closed(monkeypatch):
    tls_options, connection_options = [], []

    class Entry:
        entry_dn = 'cn=alice,dc=intern'

        def __getitem__(self, attribute):
            if attribute == 'userAccountControl':
                return SimpleNamespace(value=512)
            if attribute == 'msDS-User-Account-Control-Computed':
                return SimpleNamespace(value=0)
            if attribute == 'accountExpires':
                return SimpleNamespace(value=0)
            return SimpleNamespace(values=['cn=read,dc=intern', 'cn=write,dc=intern'])

    class Connection:
        def __init__(self, server, **kwargs):
            connection_options.append(kwargs)
            self.entries = [Entry()]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def search(self, *args, **kwargs):
            return True

    monkeypatch.setattr(directory_module, 'Tls', lambda **kwargs: tls_options.append(kwargs) or object())
    monkeypatch.setattr(directory_module, 'Server', lambda *args, **kwargs: object())
    monkeypatch.setattr(directory_module, 'Connection', Connection)
    config = ldap_settings(role_groups={'viewer': 'cn=read,dc=intern', 'operator': 'cn=write,dc=intern'})
    config.pop('bind_password')
    assert directory_module.authenticate(config, 'alice', PASSWORD, 'secret') is None
    assert tls_options[0]['validate'] == ssl.CERT_REQUIRED
    assert tls_options[0]['sni'] == 'directory.intern'
    assert len(connection_options) == 1  # Ambiguous memberships never reach user bind.
    assert not connection_options[0]['auto_referrals']
    assert connection_options[0]['read_only'] and connection_options[0]['raise_exceptions']


def test_delegated_admin_cannot_escalate_roles_or_scopes(harness):
    admin = signed(harness)
    assert admin.post('/api/roles', json={'id': 'clerk', 'name': 'Kontenverwaltung', 'permissions': ['view', 'users.manage']}).status_code == 200
    new_user(admin, 'clerk', role='clerk', scope=['srv-1'])
    clerk = signed(harness, 'clerk', PASSWORD)
    assert new_user(clerk, 'global-viewer').status_code == 403
    assert new_user(clerk, 'scoped-viewer', scope=['srv-1']).status_code == 200
    assert new_user(clerk, 'scoped-admin', role='admin', scope=['srv-1']).status_code == 403
    assert clerk.patch('/api/users/admin', json={'password': PASSWORD}).status_code == 403
    assert clerk.put('/api/directory', json=ldap_settings()).status_code == 403
    assert set(row['name'] for row in clerk.get('/api/users').json()) == {'clerk', 'scoped-viewer'}
    assert admin.post('/api/roles', json={'id': 'role-clerk', 'name': 'Rollenverwaltung', 'permissions': ['view', 'roles.manage']}).status_code == 200
    new_user(admin, 'role-clerk', role='role-clerk')
    role_clerk = signed(harness, 'role-clerk', PASSWORD)
    assert role_clerk.post('/api/roles', json={'id': 'escalation', 'name': 'Erhöht', 'permissions': ['view', 'users.manage']}).status_code == 403


def test_scoped_role_manager_cannot_change_globally_assigned_role(harness):
    admin = signed(harness)
    admin.post('/api/roles', json={'id': 'limited', 'name': 'Begrenzt', 'permissions': ['view', 'roles.manage']})
    admin.post('/api/roles', json={'id': 'readonly', 'name': 'Leser', 'permissions': ['view']})
    new_user(admin, 'limited', role='limited', scope=['srv-1'])
    new_user(admin, 'global-reader', role='readonly')
    limited = signed(harness, 'limited', PASSWORD)
    assert limited.patch('/api/roles/readonly', json={'permissions': ['view', 'roles.manage']}).status_code == 403


def test_async_directory_reauthorization_cache_change_and_failure(harness, monkeypatch):
    admin = signed(harness)
    admin.put('/api/directory', json=ldap_settings(role_groups={'viewer': 'cn=read,dc=intern', 'operator': 'cn=write,dc=intern'}))
    monkeypatch.setattr(auth_module, 'authenticate', lambda *args: 'viewer')
    user = signed(harness, 'ad:alice', PASSWORD)
    calls = []

    def role_lookup(*args):
        calls.append(args)
        return 'operator'

    monkeypatch.setattr(auth_module, 'authorize', role_lookup)
    current = asyncio.run(harness.service.reauthorize('ad:alice'))
    assert current['role'] == 'operator' and 'execute' in current['permissions']
    assert user.get('/api/me').status_code == 401
    assert asyncio.run(harness.service.reauthorize('ad:alice'))['role'] == 'operator'
    assert len(calls) == 1
    assert admin.patch('/api/users/ad:alice', json={'scope': ['srv-2']}).status_code == 200
    assert asyncio.run(harness.service.reauthorize('ad:alice'))['scope'] == ['srv-2']
    assert len(calls) == 2
    harness.service.directory_checks.clear()
    monkeypatch.setattr(auth_module, 'authorize', lambda *args: None)
    assert asyncio.run(harness.service.reauthorize('ad:alice')) is None
    assert asyncio.run(harness.service.reauthorize('ad:alice')) is None
    assert harness.audits[-1][1] == 'directory_authorization_denied'


def test_scoped_role_manager_cannot_change_future_global_directory_role(harness):
    admin = signed(harness)
    admin.post('/api/roles', json={'id': 'limited', 'name': 'Begrenzt', 'permissions': ['view', 'roles.manage']})
    admin.post('/api/roles', json={'id': 'directory-reader', 'name': 'Verzeichnisleser', 'permissions': ['view']})
    new_user(admin, 'limited', role='limited', scope=['srv-1'])
    assert admin.put('/api/directory', json=ldap_settings(role_groups={'directory-reader': 'cn=read,dc=intern'}, scope=['*'])).status_code == 200
    limited = signed(harness, 'limited', PASSWORD)
    assert limited.patch('/api/roles/directory-reader', json={'permissions': ['view', 'roles.manage']}).status_code == 403


@pytest.mark.parametrize('control,computed,expires,allowed', [
    (512, 0, 0, True), (514, 0, 0, False), (512, 16, 0, False), (512, 8388608, 0, False),
    (512, 0, 9223372036854775807, True), (512, 0, 11644473601 * 10_000_000, False),
    (None, 0, 0, False), (512, None, 0, False),
])
def test_ad_service_lookup_respects_account_state(monkeypatch, control, computed, expires, allowed):
    class Entry:
        entry_dn = 'cn=alice,dc=intern'

        def __getitem__(self, attribute):
            if attribute == 'memberOf':
                return SimpleNamespace(values=['cn=read,dc=intern'])
            return SimpleNamespace(value={'userAccountControl': control, 'msDS-User-Account-Control-Computed': computed, 'accountExpires': expires}[attribute])

    class Connection:
        entries = [Entry()]

        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def search(self, *args, **kwargs):
            return True

    monkeypatch.setattr(directory_module, 'Connection', Connection)
    config = ldap_settings()
    config.pop('bind_password')
    assert (directory_module.authorize(config, 'alice', 'secret') == 'viewer') is allowed
