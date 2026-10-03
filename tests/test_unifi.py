import asyncio
import json
from pathlib import Path

import certifi
import httpx
import pytest
from fastapi import HTTPException

from app.contract import create_defaults, default_wifi, write_payload
from app.storage import Store
from app.unifi import DEMO_SERVERS, DemoClient, LocalClient, validate_origin

SERVER = {'id': 'local-1', 'origin': 'https://192.168.8.2',
          'api_prefix': '/proxy/network/integration/v1', 'key': 'private-test-api-key'}


@pytest.mark.parametrize('origin', ['http://10.0.0.1', 'https://api.ui.com', 'https://unifi.ui.com',
    'https://ui.com.', 'https://192.168.8.2@api.ui.com', 'https://8.8.8.8',
    'https://127.0.0.1', 'https://169.254.169.254', 'https://10.0.0.1/api',
    'https://10.0.0.1?x=1', 'https://user:password@10.0.0.1', 'https://10.0.0.1:99999'])
def test_local_origin_validation_rejects_cloud_public_and_unsafe_origins(origin):
    with pytest.raises(HTTPException):
        validate_origin(origin)


def test_valid_origin_and_allowed_hosts():
    assert validate_origin('https://10.90.0.1')[0] == '10.90.0.1'
    assert validate_origin('https://uos-01.intern.example', ['uos-01.intern.example'])[0] == 'uos-01.intern.example'
    with pytest.raises(HTTPException):
        validate_origin('https://uos-02.intern.example', ['uos-01.intern.example'])


def test_extensionless_docker_secret_ca_is_parsed(tmp_path):
    ca_file = tmp_path / 'internal_ca'
    ca_file.write_bytes(Path(certifi.where()).read_bytes())
    async def run():
        client = LocalClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})))
        try:
            assert await client.request(SERVER | {'ca_file': str(ca_file)}, 'GET', '/info') == {}
        finally:
            await client.close()
    asyncio.run(run())


def test_get_transient_retry_pool_tls_and_key_header(monkeypatch):
    calls = []
    async def no_sleep(_):
        pass
    monkeypatch.setattr('app.unifi.asyncio.sleep', no_sleep)
    def response(request):
        calls.append(request)
        if len(calls) < 3:
            return httpx.Response(503, json={'message': 'secret must not escape'})
        return httpx.Response(200, json={'applicationVersion': '10.1.84'})
    async def run():
        client = LocalClient(transport=httpx.MockTransport(response))
        assert await client.request(SERVER, 'GET', '/info') == {'applicationVersion': '10.1.84'}
        await client.request(SERVER, 'GET', '/info')
        assert len(client.pools) == 1
        pool = next(iter(client.pools.values()))
        assert pool.follow_redirects is False and pool._trust_env is False
        assert calls[0].headers['x-api-key'] == SERVER['key']
        assert str(calls[0].url) == 'https://192.168.8.2/proxy/network/integration/v1/info'
        await client.close()
    asyncio.run(run())
    assert len(calls) == 4


@pytest.mark.parametrize('failure', ['timeout', '503', '429', 'redirect'])
def test_writes_are_never_retried_and_errors_never_expose_remote_body(failure):
    calls = []
    def response(request):
        calls.append(request)
        if failure == 'timeout':
            raise httpx.ReadTimeout('REMOTE-SECRET', request=request)
        if failure == 'redirect':
            return httpx.Response(302, headers={'Location': 'https://api.ui.com'}, text='REMOTE-SECRET')
        return httpx.Response(int(failure), text='REMOTE-SECRET')
    async def run():
        client = LocalClient(transport=httpx.MockTransport(response))
        try:
            with pytest.raises(HTTPException) as error:
                await client.request(SERVER, 'POST', '/sites/site-1/wifi/broadcasts', default_wifi('SSID', passphrase='secure-test-phrase'))
            assert 'REMOTE-SECRET' not in error.value.detail
            assert len(calls) == 1
        finally:
            await client.close()
    asyncio.run(run())


def test_remote_response_stream_is_bounded_and_closed():
    class TooLarge(httpx.AsyncByteStream):
        chunks = 0
        closed = False

        async def __aiter__(self):
            for _ in range(10):
                self.chunks += 1
                yield b'x' * (9 * 1024 * 1024)

        async def aclose(self):
            self.closed = True

    stream = TooLarge()
    async def run():
        client = LocalClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=stream)))
        try:
            with pytest.raises(HTTPException) as error:
                await client.request(SERVER, 'GET', '/info')
            assert 'Größenbegrenzung' in error.value.detail
            assert stream.chunks == 2 and stream.closed
        finally:
            await client.close()
    asyncio.run(run())


@pytest.mark.parametrize('method,path', [('GET', 'https://api.ui.com/v1/sites'),
    ('GET', '/sites/../admin'), ('GET', '/sites/site-1/networks/%2e%2e'),
    ('POST', '/sites/site-1/devices/device-1/actions'),
    ('DELETE', '/sites/site-1/networks/object-1?force=true'),
    ('PUT', '/sites/site-1/firewall/policies/object-1'),
    ('GET', '/sites?offset=0&offset=1'), ('GET', '/sites?limit=201')])
def test_arbitrary_controller_operations_and_path_traversal_rejected(method, path):
    def unreachable(request):
        pytest.fail('Invalid request reached UniFi transport')
    async def run():
        client = LocalClient(transport=httpx.MockTransport(unreachable))
        try:
            with pytest.raises(HTTPException):
                await client.request(SERVER, method, path)
        finally:
            await client.close()
    asyncio.run(run())


def test_local_dns_must_resolve_to_internal_addresses(monkeypatch):
    async def resolve(*args, **kwargs):
        return [(2, 1, 6, '', ('8.8.8.8', 443))]
    async def run():
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', resolve)
        client = LocalClient(transport=httpx.MockTransport(lambda request: pytest.fail('External DNS destination reached')))
        try:
            with pytest.raises(HTTPException) as error:
                await client.request(SERVER | {'origin': 'https://uos.intern.example'}, 'GET', '/info')
            assert 'interne' in error.value.detail
        finally:
            await client.close()
    asyncio.run(run())


def test_dns_address_is_pinned_and_tls_hostname_is_preserved(monkeypatch):
    requests = []
    async def resolve(*args, **kwargs):
        return [(2, 1, 6, '', ('10.23.0.10', 443))]
    def respond(request):
        requests.append(request)
        assert request.url.host == '10.23.0.10'
        assert request.headers['host'] == 'uos.intern.example'
        assert request.extensions['sni_hostname'] == 'uos.intern.example'
        return httpx.Response(200, json={'applicationVersion': '10.1.84'})
    async def run():
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', resolve)
        client = LocalClient(transport=httpx.MockTransport(respond))
        try:
            await client.request(SERVER | {'origin': 'https://uos.intern.example'}, 'GET', '/info')
        finally:
            await client.close()
    asyncio.run(run())
    assert len(requests) == 1


def test_pagination_covers_large_collection_and_rejects_inconsistent_pages():
    offsets = []
    def response(request):
        offset = int(request.url.params.get('offset'))
        offsets.append(offset)
        return httpx.Response(200, json={'offset': offset, 'totalCount': 450,
            'data': [{'id': str(index), 'name': f'Site {index}'} for index in range(offset, min(offset + 200, 450))]})
    async def run():
        client = LocalClient(transport=httpx.MockTransport(response))
        try:
            sites = await client.collection(SERVER, '/sites')
            assert len(sites) == 450 and offsets == [0, 200, 400]
        finally:
            await client.close()
    asyncio.run(run())
    async def bad():
        client = LocalClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={'offset': 0, 'data': [], 'totalCount': 10})))
        try:
            with pytest.raises(HTTPException):
                await client.collection(SERVER, '/sites')
        finally:
            await client.close()
    asyncio.run(bad())


def test_demo_1200_sites_persistent_crud_and_local_network_references(tmp_path):
    database = tmp_path / 'sim.sqlite'
    async def run():
        store = Store(database)
        client = DemoClient(store)
        all_sites = [site for server in DEMO_SERVERS for site in await client.collection(server, '/sites')]
        assert len(all_sites) == 1200 and len({site['id'] for site in all_sites}) == 1200
        assert all_sites[0]['name'] == 'Standort 0001' and all_sites[-1]['name'] == 'Standort 1200'
        server, site = DEMO_SERVERS[0], 'site-0001'
        networks = await client.collection(server, f'/sites/{site}/networks')
        assert {network['vlanId'] for network in networks} == {1, 100, 200}
        default = next(network for network in networks if network['default'])
        with pytest.raises(HTTPException):
            await client.request(server, 'DELETE', f'/sites/{site}/networks/{default["id"]}')
        administrative = next(network for network in networks if network['vlanId'] == 100)
        refs = await client.request(server, 'GET', f'/sites/{site}/networks/{administrative["id"]}/references')
        assert refs['referenceResources'][0]['resourceType'] == 'WIFI'
        with pytest.raises(HTTPException):
            await client.request(server, 'DELETE', f'/sites/{site}/networks/{administrative["id"]}')
        created = await client.request(server, 'POST', f'/sites/{site}/networks', create_defaults('network', {'name': 'Testnetz', 'vlanId': 300}))
        wifi = await client.request(server, 'POST', f'/sites/{site}/wifi/broadcasts', default_wifi('Test WLAN', passphrase='secure-test-phrase',
            network={'type': 'SPECIFIC', 'networkId': created['id']}))
        wifi_path = f'/sites/{site}/wifi/broadcasts/{wifi["id"]}'
        updated = await client.request(server, 'PUT', wifi_path, write_payload('wifi', wifi | {'enabled': False}))
        assert updated['enabled'] is False and updated['id'] == wifi['id']
        assert (await client.request(server, 'GET', wifi_path))['securityConfiguration']['passphrase'] == 'secure-test-phrase'
        # Overview responses imitate UniFi and never include secret values.
        assert 'secure-test-phrase' not in json.dumps(await client.collection(server, f'/sites/{site}/wifi/broadcasts'))
        await client.request(server, 'DELETE', wifi_path)
        await client.request(server, 'DELETE', f'/sites/{site}/networks/{created["id"]}')
        guest = next(value for value in await client.collection(server, f'/sites/{site}/wifi/broadcasts') if value['name'] == 'Gast')
        await client.request(server, 'DELETE', f'/sites/{site}/wifi/broadcasts/{guest["id"]}')
        await client.close()
        store.close()
        return guest['id']
    guest_id = asyncio.run(run())
    async def reopened():
        store = Store(database)
        client = DemoClient(store)
        try:
            ids = {item['id'] for item in await client.collection(DEMO_SERVERS[0], '/sites/site-0001/wifi/broadcasts')}
            assert guest_id not in ids
            with pytest.raises(HTTPException):
                await client.request(DEMO_SERVERS[1], 'GET', '/sites/site-0001/networks')
        finally:
            store.close()
    asyncio.run(reopened())
