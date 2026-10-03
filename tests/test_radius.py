import asyncio
import base64
import copy
import json

import httpx
import pytest
from fastapi import HTTPException

from app.contract import MASK, create_defaults, default_wifi, redact, validate_patch, write_payload
from app.radius import RadiusClient, legacy_payload, normalize_profile
from app.storage import Store
from app.unifi import DEMO_SERVERS, DemoClient, LocalClient

SERVER = {'id': 'controller-1', 'origin': 'https://10.1.0.10', 'api_prefix': '/proxy/network/integration/v1',
          'key': 'integration-test-key', 'radius_legacy_enabled': True, 'radius_auth_mode': 'api_key'}
ID = '0123456789abcdef01234567'
PATH = '/sites/site-1/radius/configurations'
RAW = {'_id': ID, 'site_id': 'internal-only-site-id', 'name': 'NPS',
       'auth_servers': [{'ip': '10.1.0.20', 'port': 1812, 'x_secret': 'test-shared-secret'}],
       'acct_servers': [], 'use_usg_auth_server': False, 'use_usg_acct_server': False,
       'vlan_enabled': False, 'vlan_wlan_mode': 'optional', 'accounting_enabled': False,
       'interim_update_enabled': True, 'interim_update_interval': '600'}


def ok(data):
    return httpx.Response(200, json={'meta': {'rc': 'ok'}, 'data': data})


def radius(name='NPS'):
    return create_defaults('radius', {'name': name, 'authenticationServers': [
        {'host': '10.1.0.20', 'port': 1812, 'sharedSecret': 'test-shared-secret'}]})


def test_radius_canonical_defaults_and_lossless_legacy_mapping():
    source = RAW | {'accounting_enabled': True, 'acct_servers': [
        {'ip': '10.1.0.21', 'port': 1813, 'x_secret': 'test-acct-shared-secret'}]}
    value = normalize_profile(source)
    assert value['metadata']['origin'] == 'USER_DEFINED'
    assert value['accountingInterimEnabled'] is True and value['accountingInterimIntervalSeconds'] == 600
    assert value['vlanAssignmentMode'] == 'optional'
    expected = copy.deepcopy(source)
    expected.pop('_id')
    expected.pop('site_id')
    expected['interim_update_interval'] = 600
    assert legacy_payload(value) == expected
    defaults = radius()
    assert defaults['vlanAssignmentMode'] == 'disabled' and defaults['accountingServers'] == []
    assert defaults['accountingInterimEnabled'] is False


@pytest.mark.parametrize('patch', [
    {'name': ' '}, {'name': 'bad\nname'}, {'authenticationServers': []},
    {'authenticationServers': [{'host': 'radius.example', 'port': 1812, 'sharedSecret': 'secret'}]},
    {'authenticationServers': [{'host': '::1', 'port': 1812, 'sharedSecret': 'secret'}]},
    {'authenticationServers': [{'host': '10.1.0.20', 'port': 0, 'sharedSecret': 'secret'}]},
    {'authenticationServers': [{'host': '10.1.0.20', 'port': 1812, 'sharedSecret': MASK}]},
    {'authenticationServers': [{'host': '10.1.0.20', 'port': 1812, 'sharedSecret': '********'}]},
    {'authenticationServers': [{'host': '10.1.0.20', 'port': 1812, 'sharedSecret': 'secret\r\n'}]},
    {'authenticationServers': [{'host': '10.1.0.20', 'port': 1812}]},
    {'authenticationServers': [{'host': '10.1.0.20', 'port': 1812, 'sharedSecret': 'secret', 'tls': True}]},
    {'vlanAssignmentMode': 'invalid'}, {'accountingInterimIntervalSeconds': 59},
    {'accountingInterimIntervalSeconds': 86401}, {'accountingEnabled': True, 'accountingServers': []},
    {'tlsEnabled': True}, {'authenticationServers': [
        {'host': '10.1.0.20', 'port': 1812, 'sharedSecret': 'secret'},
        {'host': '10.1.0.20', 'port': 1812, 'sharedSecret': 'another-secret'}]},
])
def test_invalid_radius_configuration_fails_closed(patch):
    with pytest.raises(ValueError):
        validate_patch('radius', patch)


@pytest.mark.parametrize('field,value', [('tls_enabled', True), ('x_ca_crts', ['secret-private-value']),
    ('vlan_enabled', True), ('new_config', 'new-private-value')])
def test_unknown_active_radius_configuration_is_not_silently_discarded(field, value):
    normalized = normalize_profile(RAW | {field: value})
    assert field in normalized['unsupportedConfiguration']
    assert 'private-value' not in json.dumps(normalized)
    with pytest.raises(ValueError):
        write_payload('radius', normalized)


@pytest.mark.parametrize('field,value', [('attr_no_edit', True), ('attr_no_delete', True),
    ('use_usg_auth_server', True), ('use_usg_acct_server', True), ('attr_hidden_id', 'default')])
def test_builtin_radius_profiles_are_marked_system_defined(field, value):
    assert normalize_profile(RAW | {field: value})['metadata']['origin'] == 'SYSTEM_DEFINED'


def test_missing_or_masked_remote_secrets_cannot_be_written_and_private_keys_are_redacted():
    raw = copy.deepcopy(RAW)
    raw['auth_servers'][0].pop('x_secret')
    with pytest.raises(ValueError):
        write_payload('radius', normalize_profile(raw))
    redacted = redact(normalize_profile(RAW) | {'x_client_private_key': 'tls-private-value'})
    assert redacted['authenticationServers'][0]['sharedSecret'] == MASK
    assert redacted['x_client_private_key'] == MASK


def test_radius_api_key_uses_only_classic_local_routes_with_pinned_destination(monkeypatch):
    calls = []
    async def resolve(*args, **kwargs):
        return [(2, 1, 6, '', ('10.1.0.10', 443))]
    def respond(request):
        calls.append(request)
        assert request.url.host == '10.1.0.10'
        assert request.headers['host'] == 'uos.intern.example'
        assert request.extensions['sni_hostname'] == 'uos.intern.example'
        assert request.headers['x-api-key'] == SERVER['key']
        assert request.headers['cookie'] == ''
        assert 'x-csrf-token' not in request.headers
        assert request.url.path.startswith('/proxy/network/api/s/default/rest/radiusprofile')
        if request.method in ('POST', 'PUT'):
            data = json.loads(request.content)
            assert data['auth_servers'][0]['x_secret'] == 'test-shared-secret'
            assert 'sharedSecret' not in data and 'id' not in data
            return ok([RAW])
        return ok([RAW])
    async def run():
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', resolve)
        client = RadiusClient(transport=httpx.MockTransport(respond))
        try:
            server = SERVER | {'origin': 'https://uos.intern.example'}
            assert len(await client.collection(server, PATH, site_reference='default')) == 1
            assert (await client.request(server, 'GET', PATH + '/' + ID, site_reference='default'))['id'] == ID
            assert (await client.request(server, 'POST', PATH, radius(), site_reference='default'))['id'] == ID
            await client.request(server, 'PUT', PATH + '/' + ID, radius(), site_reference='default')
            pool = next(iter(client.local.pools.values()))
            assert not pool.follow_redirects and not pool._trust_env
        finally:
            await client.close()
    asyncio.run(run())
    assert len(calls) == 4


@pytest.mark.parametrize('method,path,reference,server', [
    ('POST', '/sites/site-1/radius/profiles', 'default', SERVER),
    ('GET', 'https://api.ui.com/radius', 'default', SERVER),
    ('GET', PATH, '../default', SERVER), ('GET', PATH, None, SERVER),
    ('GET', PATH + '/not-a-legacy-id', 'default', SERVER),
    ('PUT', PATH, 'default', SERVER), ('GET', PATH + '?limit=201', 'default', SERVER),
    ('GET', PATH, 'default', SERVER | {'radius_legacy_enabled': False}),
    ('GET', PATH, 'default', SERVER | {'origin': 'https://api.ui.com'}),
    ('GET', PATH, 'default', SERVER | {'radius_auth_mode': 'automatic'}),
])
def test_invalid_paths_origins_and_unconfigured_adapter_do_not_reach_transport(method, path, reference, server):
    async def run():
        client = RadiusClient(transport=httpx.MockTransport(lambda request: pytest.fail('Unsafe radius request reached transport')))
        try:
            with pytest.raises(HTTPException):
                await client.request(server, method, path, site_reference=reference)
        finally:
            await client.close()
    asyncio.run(run())


@pytest.mark.parametrize('failure', ['timeout', '401', '429', '503', 'redirect', 'meta-error'])
def test_radius_writes_are_never_retried_and_remote_errors_never_echo_secrets(failure):
    calls = []
    def respond(request):
        calls.append(request)
        if failure == 'timeout':
            raise httpx.ReadTimeout('SECRET-REMOTE-BODY', request=request)
        if failure == 'redirect':
            return httpx.Response(302, headers={'location': 'https://api.ui.com'}, text='SECRET-REMOTE-BODY')
        if failure == 'meta-error':
            return httpx.Response(200, json={'meta': {'rc': 'error', 'msg': 'SECRET-REMOTE-BODY'}, 'data': []})
        return httpx.Response(int(failure), text='SECRET-REMOTE-BODY')
    async def run():
        client = RadiusClient(transport=httpx.MockTransport(respond))
        try:
            with pytest.raises(HTTPException) as error:
                await client.request(SERVER, 'POST', PATH, radius(), site_reference='default')
            assert 'SECRET-REMOTE-BODY' not in error.value.detail
            assert len(calls) == 1
        finally:
            await client.close()
    asyncio.run(run())


def token(csrf):
    encoded = base64.urlsafe_b64encode(json.dumps({'csrfToken': csrf}).encode()).decode().rstrip('=')
    return 'header.' + encoded + '.signature'


def test_local_account_sessions_csrf_401_get_reauthentication_and_credential_rotation():
    calls, logins = [], []
    def respond(request):
        calls.append(request)
        assert 'x-api-key' not in request.headers
        if request.url.path == '/api/auth/login':
            data = json.loads(request.content)
            assert request.headers['cookie'] == ''
            logins.append(data)
            value = token('csrf-' + str(len(logins)))
            return httpx.Response(200, headers={'Set-Cookie': 'TOKEN=' + value + '; Path=/; Secure; HttpOnly'}, json={})
        assert request.headers['x-csrf-token'] == 'csrf-' + str(len(logins))
        assert request.headers['cookie'] == 'TOKEN=' + token('csrf-' + str(len(logins)))
        if len(calls) == 2:
            return httpx.Response(401, text='PRIVATE-LOGIN-ERROR')
        return ok([RAW])
    async def run():
        client = RadiusClient(transport=httpx.MockTransport(respond))
        server = SERVER | {'radius_auth_mode': 'local_account', 'radius_username': 'service', 'radius_password': 'password1'}
        try:
            await client.collection(server, PATH, site_reference='default')
            assert len(logins) == 2
            await client.request(server, 'PUT', PATH + '/' + ID, radius(), site_reference='default')
            assert len(logins) == 2
            await client.collection(server | {'radius_password': 'password2'}, PATH, site_reference='default')
            assert len(logins) == 3 and logins[-1]['password'] == 'password2'
            assert len(client.local.pools) == 2
            assert all(not pool.cookies for pool in client.local.pools.values())
        finally:
            await client.close()
        assert not client.sessions and not client.local.pools
    asyncio.run(run())


def test_reference_scan_includes_wlan_network_port_and_settings_and_fails_on_incomplete_scan():
    paths = []
    def respond(request):
        paths.append(request.url.path)
        if request.url.path.endswith('/rest/radiusprofile/' + ID):
            return ok([RAW])
        if request.url.path.endswith('/rest/wlanconf'):
            return ok([{'_id': 'wlan-id', 'radiusprofile_id': ID}])
        if request.url.path.endswith('/rest/portconf'):
            return ok([{'_id': 'port-id', 'config': {'radius_profile_id': ID}}])
        return ok([])
    async def run():
        client = RadiusClient(transport=httpx.MockTransport(respond))
        try:
            refs = await client.request(SERVER, 'GET', PATH + '/' + ID + '/references', site_reference='default')
            assert sum(item['referenceCount'] for item in refs['referenceResources']) == 2
            assert len(paths) == 6 and paths[-1].endswith('/stat/device')
        finally:
            await client.close()
        bad = RadiusClient(transport=httpx.MockTransport(lambda request: httpx.Response(404)))
        try:
            with pytest.raises(HTTPException):
                await bad.request(SERVER, 'GET', PATH + '/' + ID + '/references', site_reference='default')
        finally:
            await bad.close()
    asyncio.run(run())


def test_real_integration_api_does_not_accept_virtual_radius_configuration_routes():
    async def run():
        client = LocalClient(transport=httpx.MockTransport(lambda request: pytest.fail('Invented integration route was called')))
        try:
            with pytest.raises(HTTPException):
                await client.request(SERVER, 'POST', PATH, radius())
        finally:
            await client.close()
    asyncio.run(run())


def test_unknown_nested_radius_reference_is_conservatively_detected():
    def respond(request):
        if request.url.path.endswith('/rest/radiusprofile/' + ID):
            return ok([RAW])
        if request.url.path.endswith('/stat/device'):
            return ok([{'_id': 'device-id', 'future_config': {'renamedProfileReferences': ['unrelated-id', ID]}}])
        return ok([])
    async def run():
        client = RadiusClient(transport=httpx.MockTransport(respond))
        try:
            refs = await client.request(SERVER, 'GET', PATH + '/' + ID + '/references', site_reference='default')
            assert refs['referenceResources'] == [{'resourceType': 'stat/device', 'referenceCount': 1,
                                                   'references': [{'referenceId': 'device-id'}]}]
        finally:
            await client.close()
    asyncio.run(run())


def test_radius_external_id_alias_reference_is_detected_without_guessing():
    alias = '51b5b943-0000-4000-8000-4579f8a38209'
    def respond(request):
        if request.url.path.endswith('/rest/radiusprofile/' + ID):
            return ok([RAW | {'external_id': alias}])
        if request.url.path.endswith('/rest/wlanconf'):
            return ok([{'_id': 'wlan-id', 'futureProfileRef': alias}])
        return ok([])
    async def run():
        client = RadiusClient(transport=httpx.MockTransport(respond))
        try:
            refs = await client.request(SERVER, 'GET', PATH + '/' + ID + '/references', site_reference='default')
            assert refs['referenceResources'] == [{'resourceType': 'rest/wlanconf', 'referenceCount': 1,
                                                   'references': [{'referenceId': 'wlan-id'}]}]
        finally:
            await client.close()
    asyncio.run(run())


@pytest.mark.parametrize('alias', [0, {}, [], '', 'id\x00invalid'])
def test_invalid_radius_external_id_alias_blocks_reference_scan(alias):
    calls = []
    def respond(request):
        calls.append(request)
        return ok([RAW | {'external_id': alias}])
    async def run():
        client = RadiusClient(transport=httpx.MockTransport(respond))
        try:
            with pytest.raises(HTTPException) as error:
                await client.request(SERVER, 'GET', PATH + '/' + ID + '/references', site_reference='default')
            assert error.value.status_code == 502 and len(calls) == 1
        finally:
            await client.close()
    asyncio.run(run())


def test_local_write_401_does_not_reauthenticate_or_resubmit_and_api_key_never_falls_back():
    logins, writes = [], []
    def respond(request):
        if request.url.path == '/api/auth/login':
            logins.append(request)
            return httpx.Response(200, headers={'Set-Cookie': 'TOKEN=' + token('csrf')}, json={})
        writes.append(request)
        return httpx.Response(401)
    async def run():
        client = RadiusClient(transport=httpx.MockTransport(respond))
        try:
            server = SERVER | {'radius_auth_mode': 'local_account', 'radius_username': 'service', 'radius_password': 'private-password'}
            with pytest.raises(HTTPException):
                await client.request(server, 'POST', PATH, radius(), site_reference='default')
            assert len(logins) == 1 and len(writes) == 1 and not client.sessions
            with pytest.raises(HTTPException):
                await client.collection(SERVER, PATH, site_reference='default')
            assert len(logins) == 1 and len(writes) == 2
        finally:
            await client.close()
    asyncio.run(run())


@pytest.mark.parametrize('bad_token,bad_csrf', [
    ('escaped-control', None), ('escaped-high-byte', None),
    (None, 'csrf\x00token'), (None, 'csrf\x7ftoken'), (None, 'csrf\x80token'),
])
def test_login_tokens_and_csrf_headers_reject_non_printable_and_non_ascii_characters(bad_token, bad_csrf):
    calls = []
    def respond(request):
        calls.append(request)
        assert request.url.path == '/api/auth/login'
        cookie = 'TOKEN=' + token('csrf')
        if bad_token == 'escaped-control':
            cookie = 'TOKEN="bad\\000token"'
        elif bad_token == 'escaped-high-byte':
            cookie = 'TOKEN="bad\\200token"'
        headers = {'Set-Cookie': cookie, 'X-CSRF-Token': bad_csrf or 'csrf'}
        # HTTPX accepts raw Latin-1 response headers so the test models an
        # untrusted controller response instead of failing while building it.
        return httpx.Response(200, headers=[(key.encode(), value.encode('latin-1')) for key, value in headers.items()], json={})
    async def run():
        client = RadiusClient(transport=httpx.MockTransport(respond))
        server = SERVER | {'radius_auth_mode': 'local_account', 'radius_username': 'service', 'radius_password': 'private-password'}
        try:
            with pytest.raises(HTTPException) as error:
                await client.collection(server, PATH, site_reference='default')
            assert error.value.status_code == 502
            assert len(calls) == 1 and not client.sessions
            assert 'bad' not in error.value.detail and 'private-password' not in error.value.detail
        finally:
            await client.close()
    asyncio.run(run())


def test_radius_response_stream_is_bounded_and_closed():
    class TooLarge(httpx.AsyncByteStream):
        chunks = 0
        closed = False
        async def __aiter__(self):
            for _ in range(3):
                self.chunks += 1
                yield b'x' * (9 * 1024 * 1024)
        async def aclose(self):
            self.closed = True
    stream = TooLarge()
    async def run():
        client = RadiusClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=stream)))
        try:
            with pytest.raises(HTTPException):
                await client.collection(SERVER, PATH, site_reference='default')
            assert stream.chunks == 2 and stream.closed
        finally:
            await client.close()
    asyncio.run(run())


def test_demo_radius_crud_references_and_persistent_migration(tmp_path):
    store = Store(tmp_path / 'radius.sqlite')
    async def run():
        client, server, path = DemoClient(store), DEMO_SERVERS[0], '/sites/site-0001/radius/configurations'
        # Simulate an older already-seeded demo: the new independent marker
        # still creates the initial profile once.
        await client.collection(server, '/sites/site-0001/networks')
        profile = (await client.collection(server, path))[0]
        assert profile['name'] == 'Behörden-RADIUS'
        added = await client.request(server, 'POST', path, radius('New profile'))
        overview = await client.collection(server, '/sites/site-0001/radius/profiles')
        assert len(overview) == 2 and all('authenticationServers' not in item for item in overview)
        await client.request(server, 'PUT', path + '/' + added['id'], radius('Renamed'))
        assert (await client.request(server, 'GET', path + '/' + added['id']))['name'] == 'Renamed'
        assert not (await client.request(server, 'GET', path + '/' + added['id'] + '/references'))['referenceResources']
        await client.request(server, 'DELETE', path + '/' + added['id'])
        await client.request(server, 'DELETE', path + '/' + profile['id'])
        assert await DemoClient(store).collection(server, path) == []
        assert await DemoClient(store).collection(server, '/sites/site-0001/radius/profiles') == []
    try:
        asyncio.run(run())
    finally:
        store.close()


def test_demo_personal_wifi_accepts_nullable_optional_radius_configuration(tmp_path):
    store = Store(tmp_path / 'nullable-radius.sqlite')
    async def run():
        client = DemoClient(store)
        value = default_wifi('PSK without RADIUS', passphrase='personal-wifi-secret')
        value['securityConfiguration']['radiusConfiguration'] = None
        result = await client.request(DEMO_SERVERS[0], 'POST', '/sites/site-0001/wifi/broadcasts', value)
        assert result['securityConfiguration']['radiusConfiguration'] is None
        assert not store.one("SELECT id FROM sim_objects WHERE kind='_radius_seed'")
    try:
        asyncio.run(run())
    finally:
        store.close()
