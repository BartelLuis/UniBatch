"""Security boundaries for opt-in RADIUS server configuration and routing."""
import pytest
from fastapi import HTTPException

from test_workflow import env, signed


def test_radius_account_secret_preserved_encrypted_and_never_returned(env):
    app, _ = env
    admin = signed(app, 'admin')
    secret = 'radius-local-account-secret-2026'
    response = admin.patch('/api/servers/demo-01', json={
        'radius_legacy_enabled': True, 'radius_auth_mode': 'local_account',
        'radius_username': 'radius-operator', 'radius_password': secret,
    })
    assert response.status_code == 200, response.text
    assert secret not in response.text
    listing = admin.get('/api/servers')
    assert secret not in listing.text
    server = next(server for server in listing.json() if server['id'] == 'demo-01')
    assert server['has_radius_password'] and server['radius_auth_mode'] == 'local_account'
    blob = app.state.ctx.store.one('SELECT blob FROM app_servers WHERE id=?', ('demo-01',))['blob']
    assert secret.encode() not in blob
    assert admin.patch('/api/servers/demo-01', json={'radius_password': '', 'name': 'RADIUS Server'}).status_code == 200
    assert app.state.ctx.server('demo-01')['radius_password'] == secret
    assert admin.patch('/api/servers/demo-01', json={'radius_auth_mode': 'api_key'}).status_code == 200
    config = app.state.ctx.server('demo-01')
    assert 'radius_password' not in config and 'radius_username' not in config
    assert secret not in admin.get('/api/audit/export').text


@pytest.mark.parametrize('fields', [
    {'radius_auth_mode': 'local_account', 'radius_username': 'operator'},
    {'radius_auth_mode': 'local_account', 'radius_username': '   ', 'radius_password': 'secret'},
    {'api_prefix': '/integration/v1'},
    {'radius_auth_mode': 'cloud'},
])
def test_radius_enable_rejects_incomplete_or_incompatible_configuration(env, fields):
    app, _ = env
    admin = signed(app, 'admin')
    before = app.state.ctx.server('demo-01')
    response = admin.patch('/api/servers/demo-01', json={'radius_legacy_enabled': True} | fields)
    assert response.status_code == 422
    assert app.state.ctx.server('demo-01') == before


def test_radius_connection_test_is_read_only_and_requires_server_management(env, monkeypatch):
    app, _ = env
    operator, admin = signed(app), signed(app, 'admin')
    calls = []
    original = app.state.ctx.client.request

    async def capture(server, method, path, payload=None):
        calls.append((method, path))
        return await original(server, method, path, payload)

    monkeypatch.setattr(app.state.ctx.client, 'request', capture)
    assert operator.post('/api/servers/demo-01/radius/test').status_code == 403
    response = admin.post('/api/servers/demo-01/radius/test')
    assert response.status_code == 200, response.text
    assert response.json()['ok'] and response.json()['profile_count'] >= 1
    assert all(method == 'GET' for method, _ in calls)
    assert 'simulation-radius-secret' not in response.text


def test_radius_missing_or_ambiguous_site_reference_fails_closed(env):
    app, _ = env
    ctx = app.state.ctx
    path = '/sites/site-0001/radius/configurations'
    ctx.store.execute('UPDATE app_sites SET internal_reference=NULL WHERE server=? AND site=?', ('demo-01', 'site-0001'))
    with pytest.raises(HTTPException) as error:
        ctx.radius_reference('demo-01', path)
    assert error.value.status_code == 409
    ctx.store.execute('UPDATE app_sites SET internal_reference=? WHERE server=? AND site IN (?,?)',
                      ('same-reference', 'demo-01', 'site-0001', 'site-0002'))
    with pytest.raises(HTTPException) as error:
        ctx.radius_reference('demo-01', path)
    assert error.value.status_code == 409


def test_malformed_radius_reference_response_blocks_delete(env, monkeypatch):
    from app.jobs import references_clear
    import asyncio
    app, _ = env

    async def malformed(*args, **kwargs):
        return {'referenceResources': None}

    monkeypatch.setattr(app.state.ctx, 'request', malformed)
    with pytest.raises(HTTPException) as error:
        asyncio.run(references_clear(app.state.ctx, 'demo-01', '/sites/site-0001/radius/configurations/profile', 'radius'))
    assert error.value.status_code == 502


def test_radius_interim_requires_accounting_in_full_and_partial_configuration():
    from app.contract import create_defaults, validate_patch
    with pytest.raises(ValueError, match='aktiviertes Accounting'):
        validate_patch('radius', {'accountingEnabled': False, 'accountingInterimEnabled': True})
    with pytest.raises(ValueError, match='aktiviertes Accounting'):
        create_defaults('radius', {
            'name': 'Invalid accounting profile',
            'authenticationServers': [{'host': '10.20.0.10', 'port': 1812, 'sharedSecret': 'radius-secret'}],
            'accountingInterimEnabled': True,
        })
