"""Local-only UniFi API transport and a persistent, scale-sized simulator."""
import asyncio
import copy
import ipaddress
import json
import re
import socket
import ssl
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import NAMESPACE_URL, uuid4, uuid5

import httpx
from fastapi import HTTPException

from app.contract import CONTRACT, default_wifi, write_payload

API_PREFIXES = {'/proxy/network/integration/v1', '/integration/v1'}
_PRIVATE_NETS = tuple(ipaddress.ip_network(value) for value in
                      ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'))
_ID = r'[A-Za-z0-9_-]{1,128}'
_COLLECTION = re.compile(rf'/sites/({_ID})/(wifi/broadcasts|networks|radius/profiles|device-tags|devices)')
_OBJECT = re.compile(rf'/sites/({_ID})/(wifi/broadcasts|networks)/({_ID})')
_REFERENCES = re.compile(rf'/sites/({_ID})/networks/({_ID})/references')


def _internal_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return any(address.version == network.version and address in network for network in _PRIVATE_NETS)


def validate_server(server, allowed_hosts=None):
    """Validate fixed HTTPS origins before creating a pool or sending a key."""
    origin = server.get('origin', '')
    try:
        parsed = urlsplit(origin)
        port = parsed.port or 443
    except ValueError:
        raise ValueError('Ungültiger UniFi-Server-Ursprung') from None
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ('', '/')
            or not 1 <= port <= 65535 or any(char.isspace() for char in origin)):
        raise ValueError('UniFi-Server benötigt einen festen HTTPS-Ursprung')
    host = parsed.hostname.casefold().rstrip('.')
    if host == 'ui.com' or host.endswith('.ui.com') or host == 'ubnt.com' or host.endswith('.ubnt.com'):
        raise ValueError('Cloud-Endpunkte sind nicht zulässig; lokale UniFi-API verwenden')
    if allowed_hosts and host not in {value.casefold().rstrip('.') for value in allowed_hosts}:
        raise ValueError('UniFi-Server steht nicht auf der erlaubten Hostliste')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', host) or '..' in host:
            raise ValueError('Ungültiger UniFi-Hostname') from None
    else:
        if not _internal_ip(host):
            raise ValueError('UniFi-Server muss eine interne RFC1918-/ULA-Adresse verwenden')
    if server.get('api_prefix') not in API_PREFIXES:
        raise ValueError('Nur die dokumentierte lokale Integration-API ist zulässig')
    ca_file = server.get('ca_file')
    if ca_file:
        path = Path(ca_file)
        if not path.is_absolute() or not path.is_file():
            raise ValueError('CA-Datei muss eine vorhandene absolute PEM-Zertifikatsdatei sein')
    return host, port


def validate_origin(origin, allowed_hosts=None):
    """Public configuration validator used by GUI server administration."""
    try:
        return validate_server({'origin': origin, 'api_prefix': '/proxy/network/integration/v1'}, allowed_hosts)
    except ValueError as error:
        raise HTTPException(422, str(error)) from None


def _route(method, path):
    if method not in ('GET', 'POST', 'PUT', 'DELETE') or not isinstance(path, str):
        raise ValueError('Nicht unterstützte lokale UniFi-Anfrage')
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.fragment or '%' in parsed.path or '..' in parsed.path or '\\' in path:
        raise ValueError('Ungültiger lokaler API-Pfad')
    query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True) if parsed.query else {}
    if any(len(value) != 1 for value in query.values()):
        raise ValueError('Doppelte API-Parameter sind nicht erlaubt')
    collection = _COLLECTION.fullmatch(parsed.path)
    obj = _OBJECT.fullmatch(parsed.path)
    references = _REFERENCES.fullmatch(parsed.path)
    if method == 'GET':
        valid = parsed.path in ('/sites', '/info') or collection or obj or references
        allowed = {'offset', 'limit', 'filter'} if parsed.path == '/sites' or collection else set()
    elif method == 'POST':
        valid = collection and collection.group(2) in ('wifi/broadcasts', 'networks')
        allowed = set()
    elif method == 'PUT':
        valid = obj
        allowed = set()
    else:
        valid = obj
        allowed = {'force'} if obj and obj.group(2) == 'networks' else set()
        if 'force' in query and query['force'][0] != 'false':
            raise ValueError('Erzwungenes VLAN-Löschen ist gesperrt')
    if not valid or set(query) - allowed:
        raise ValueError('API-Pfad oder Operation liegt außerhalb WLAN/VLAN')
    for key in ('offset', 'limit'):
        if key in query:
            if not query[key][0].isdigit() or int(query[key][0]) > (200 if key == 'limit' else 200000):
                raise ValueError('Ungültige API-Paginierung')
    if 'filter' in query and len(query['filter'][0]) > 1024:
        raise ValueError('API-Filter ist zu lang')
    return parsed, query, collection, obj, references


class LocalClient:
    """Per-server verified TLS pools. Only transient GETs may be retried."""
    def __init__(self, concurrency=4, timeout=20, transport=None, allowed_hosts=None):
        self.concurrency = max(1, min(int(concurrency), 16))
        self.timeout = timeout
        self.transport = transport
        self.allowed_hosts = allowed_hosts
        self.pools = {}
        self.semaphores = {}
        self.pool_guard = asyncio.Lock()
        self.resolved = {}

    async def _pool(self, server):
        host, port = validate_server(server, self.allowed_hosts)
        key = (server['id'], server['origin'].rstrip('/'), server.get('ca_file'))
        async with self.pool_guard:
            if key not in self.pools:
                try:
                    context = ssl.create_default_context(cafile=server.get('ca_file') or None)
                except (OSError, ssl.SSLError):
                    raise HTTPException(502, 'UniFi-CA-Zertifikat konnte nicht geladen werden') from None
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                self.pools[key] = httpx.AsyncClient(verify=context, timeout=httpx.Timeout(self.timeout),
                    limits=httpx.Limits(max_connections=self.concurrency, max_keepalive_connections=self.concurrency),
                    follow_redirects=False, trust_env=False, transport=self.transport)
            semaphore = self.semaphores.setdefault(server['id'], asyncio.Semaphore(self.concurrency))
        return self.pools[key], semaphore, host, port

    async def _resolve(self, host, port):
        if _internal_ip(host):
            return host
        cached = self.resolved.get((host, port))
        if cached and cached[0] > time.monotonic():
            return cached[1]
        try:
            addresses = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
                host, port, type=socket.SOCK_STREAM), timeout=min(self.timeout, 5))
        except (OSError, TimeoutError):
            raise HTTPException(502, 'Interner UniFi-Hostname konnte nicht aufgelöst werden') from None
        if not addresses or any(not _internal_ip(item[4][0]) for item in addresses):
            raise HTTPException(502, 'UniFi-DNS muss ausschließlich interne RFC1918-/ULA-Adressen liefern')
        address = addresses[0][4][0]
        self.resolved[(host, port)] = (time.monotonic() + 30, address)
        return address

    async def request(self, server, method, path, payload=None):
        try:
            parsed, query, collection, obj, references = _route(method, path)
            if method in ('POST', 'PUT'):
                resource = (collection or obj).group(2)
                payload = write_payload('wifi' if resource == 'wifi/broadcasts' else 'network', payload)
            elif payload is not None:
                raise ValueError('Lesen und Löschen akzeptieren keinen Anfragekörper')
            client, semaphore, host, port = await self._pool(server)
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        key = server.get('key') or server.get('api_key')
        if not isinstance(key, str) or not key or '\r' in key or '\n' in key:
            raise HTTPException(502, 'Lokaler UniFi-API-Schlüssel fehlt oder ist ungültig')
        address = await self._resolve(host, port)
        url = server['origin'].rstrip('/') + server['api_prefix'] + path
        # Connect to the checked address, while keeping the configured hostname
        # for HTTP routing, SNI and certificate verification. A second DNS lookup
        # by the transport could otherwise redirect an API key outside the LAN.
        target = httpx.URL(url).copy_with(host=address)
        host_header = urlsplit(server['origin']).netloc
        async with semaphore:
            attempts = 3 if method == 'GET' else 1
            for attempt in range(attempts):
                try:
                    async with client.stream(method, target, json=payload if payload is not None else None,
                            headers={'X-API-Key': key, 'Accept': 'application/json', 'Host': host_header,
                                     'Accept-Encoding': 'identity'}, extensions={'sni_hostname': host}) as remote:
                        body = bytearray()
                        if 200 <= remote.status_code < 300:
                            async for chunk in remote.aiter_bytes():
                                if len(body) + len(chunk) > 16 * 1024 * 1024:
                                    raise HTTPException(502, 'UniFi-Antwort überschreitet die Größenbegrenzung')
                                body.extend(chunk)
                        response = httpx.Response(remote.status_code, headers=remote.headers,
                                                  content=bytes(body), request=remote.request)
                except (httpx.TimeoutException, httpx.NetworkError):
                    if attempt + 1 < attempts:
                        await asyncio.sleep(0.25 * 2 ** attempt)
                        continue
                    raise HTTPException(502, 'Lokale UniFi-Verbindung fehlgeschlagen; Schreibausgang gegebenenfalls unklar') from None
                if response.status_code == 429 or 500 <= response.status_code <= 599:
                    if attempt + 1 < attempts:
                        await asyncio.sleep(0.25 * 2 ** attempt)
                        continue
                if not 200 <= response.status_code < 300:
                    status = response.status_code if response.status_code in (404, 409, 429) else 502
                    raise HTTPException(status, f'Lokale UniFi-API antwortete mit HTTP {response.status_code}')
                if not response.content or response.status_code == 204:
                    return {}
                try:
                    result = response.json()
                except (ValueError, UnicodeDecodeError):
                    raise HTTPException(502, 'Lokale UniFi-API lieferte ungültiges JSON') from None
                if not isinstance(result, dict):
                    raise HTTPException(502, 'Lokale UniFi-API lieferte ein unerwartetes Antwortformat')
                return result

    async def collection(self, server, path):
        return await _collect(self, server, path)

    async def close(self):
        clients = list(self.pools.values())
        self.pools.clear()
        for client in clients:
            await client.aclose()


UnifiClient = LocalClient


async def _collect(client, server, path):
    parsed, query, collection, obj, refs = _route('GET', path)
    if parsed.path != '/sites' and not collection:
        raise HTTPException(422, 'Keine paginierte UniFi-Sammlung')
    if 'offset' in query:
        raise HTTPException(422, 'Sammlungsabruf startet bei Offset 0')
    query.pop('limit', None)
    base = {key: value[0] for key, value in query.items()}
    result, seen, offset = [], set(), 0
    for _ in range(1000):
        page = await client.request(server, 'GET', parsed.path + '?' + urlencode(base | {'offset': offset, 'limit': 200}))
        data, total = page.get('data'), page.get('totalCount')
        if (not isinstance(data, list) or type(total) is not int or not 0 <= total <= 200000
                or len(data) > 200 or page.get('offset', offset) != offset):
            raise HTTPException(502, 'Ungültige UniFi-Paginierungsantwort')
        for item in data:
            if not isinstance(item, dict) or not isinstance(item.get('id'), str) or item['id'] in seen:
                raise HTTPException(502, 'UniFi-Paginierung enthält ungültige oder doppelte Objekte')
            seen.add(item['id'])
        result.extend(data)
        offset += len(data)
        if offset >= total:
            if offset > total:
                raise HTTPException(502, 'UniFi-Paginierung hat inkonsistente Gesamtanzahl')
            return result
        if not data:
            raise HTTPException(502, 'UniFi-Paginierung endete vor der Gesamtanzahl')
    raise HTTPException(502, 'UniFi-Sammlung überschreitet die Paginierungsbegrenzung')


DEMO_SERVERS = [{'id': f'demo-{index:02}', 'name': f'UniFi OS Server {index:02}',
                 'origin': f'https://10.90.0.{index}', 'api_prefix': '/proxy/network/integration/v1',
                 'key': 'simulation-only-api-key'} for index in range(1, 13)]


class DemoClient:
    """1,200 sites with deterministic IDs; changes survive application restarts."""
    def __init__(self, store):
        self.store = store
        self.store.execute('''CREATE TABLE IF NOT EXISTS sim_objects(
            server_id TEXT NOT NULL,site_id TEXT NOT NULL,kind TEXT NOT NULL,
            id TEXT NOT NULL,payload TEXT NOT NULL,
            PRIMARY KEY(server_id,site_id,kind,id))''')
        self._wifi_template = default_wifi('Demo', passphrase='simulation-passphrase-2026')
        self._site_ids = {server['id']: {site['id'] for site in self._sites(server['id'])} for server in DEMO_SERVERS}

    def _sites(self, server_id):
        if server_id not in {item['id'] for item in DEMO_SERVERS}:
            raise HTTPException(404, 'Simulierter UniFi-Server fehlt')
        start = (int(server_id.rsplit('-', 1)[1]) - 1) * 100 + 1
        return [{'id': f'site-{index:04}', 'name': f'Standort {index:04}',
                 'internalReference': f'standort-{index:04}'} for index in range(start, start + 100)]

    @staticmethod
    def object_id(server_id, site_id, name):
        return str(uuid5(NAMESPACE_URL, f'unifi-batch-demo/{server_id}/{site_id}/{name}'))

    def _save(self, server_id, site_id, kind, value):
        self.store.execute('INSERT OR REPLACE INTO sim_objects(server_id,site_id,kind,id,payload) VALUES(?,?,?,?,?)',
            (server_id, site_id, kind, value['id'], json.dumps(value, ensure_ascii=False, separators=(',', ':'))))

    def _seed(self, server_id, site_id):
        if site_id not in self._site_ids.get(server_id, set()):
            raise HTTPException(404, 'Simulierte Site fehlt auf diesem Server')
        if self.store.one("SELECT id FROM sim_objects WHERE server_id=? AND site_id=? AND kind='_seed'", (server_id, site_id)):
            return
        # One commit per site, rather than six synchronous WAL commits. The
        # validated immutable prototype avoids repeating schema work for each
        # of the 2,400 initial broadcasts.
        with self.store.transaction():
            if self.store.one("SELECT id FROM sim_objects WHERE server_id=? AND site_id=? AND kind='_seed'", (server_id, site_id)):
                return
            for name, vlan_id in (('Default', 1), ('Verwaltungsnetz', 100), ('Gastnetz', 200)):
                value = {'id': self.object_id(server_id, site_id, name), 'name': name,
                         'management': 'UNMANAGED', 'enabled': True, 'vlanId': vlan_id,
                         'default': vlan_id == 1, 'metadata': {'origin': 'SYSTEM_DEFINED' if vlan_id == 1 else 'USER_DEFINED'}}
                self._save(server_id, site_id, 'network', value)
            for name, network in (('Verwaltung', 'Verwaltungsnetz'), ('Gast', 'Gastnetz')):
                value = copy.deepcopy(self._wifi_template)
                value.update({'name': name, 'network': {'type': 'SPECIFIC', 'networkId': self.object_id(server_id, site_id, network)},
                              'id': self.object_id(server_id, site_id, name), 'metadata': {'origin': 'USER_DEFINED'}})
                self._save(server_id, site_id, 'wifi', value)
            self._save(server_id, site_id, '_seed', {'id': '_seed'})

    def _seed_radius(self, server_id, site_id):
        # Existing persistent demos predate configurable profiles. A separate
        # seed marker migrates them once without recreating deleted profiles.
        if self.store.one("SELECT id FROM sim_objects WHERE server_id=? AND site_id=? AND kind='_radius_seed'", (server_id, site_id)):
            return
        with self.store.transaction():
            if self.store.one("SELECT id FROM sim_objects WHERE server_id=? AND site_id=? AND kind='_radius_seed'", (server_id, site_id)):
                return
            value = {'id': self.object_id(server_id, site_id, 'RADIUS'), 'name': 'Behörden-RADIUS',
                'metadata': {'origin': 'USER_DEFINED'},
                'authenticationServers': [{'host': '10.90.20.10', 'port': 1812, 'sharedSecret': 'simulation-radius-secret-2026'}],
                'accountingEnabled': False, 'accountingServers': [], 'accountingInterimEnabled': False,
                'accountingInterimIntervalSeconds': 600, 'vlanAssignmentMode': 'disabled'}
            self._save(server_id, site_id, 'radius', value)
            self._save(server_id, site_id, '_radius_seed', {'id': '_radius_seed'})

    def _radius_references(self, server_id, site_id, object_id):
        self._get(server_id, site_id, 'radius', object_id)
        def uses(value):
            if isinstance(value, dict):
                return any((key == 'profileId' and item == object_id) or uses(item) for key, item in value.items())
            return isinstance(value, list) and any(uses(item) for item in value)
        references = [{'referenceId': value['id']} for value in self._all(server_id, site_id, 'wifi') if uses(value)]
        return {'referenceResources': [{'resourceType': 'WIFI', 'referenceCount': len(references),
                'references': references}] if references else []}

    async def _radius_request(self, server, method, path, payload=None):
        from app.radius import radius_route
        site_id, object_id, references, query = radius_route(method, path)
        server_id = server['id']
        self._seed(server_id, site_id)
        self._seed_radius(server_id, site_id)
        if method in ('GET', 'DELETE') and payload is not None:
            raise HTTPException(422, 'Lesen und Löschen akzeptieren keinen Anfragekörper')
        if references:
            return self._radius_references(server_id, site_id, object_id)
        if method == 'GET':
            if object_id:
                return copy.deepcopy(self._get(server_id, site_id, 'radius', object_id))
            return self._page(copy.deepcopy(self._all(server_id, site_id, 'radius')), query)
        before = self._get(server_id, site_id, 'radius', object_id) if object_id else None
        if before and before.get('metadata', {}).get('origin') != 'USER_DEFINED':
            raise HTTPException(409, 'Systemverwaltete RADIUS-Profile sind geschützt')
        if method == 'DELETE':
            if self._radius_references(server_id, site_id, object_id)['referenceResources']:
                raise HTTPException(409, 'RADIUS-Profil wird noch von WLAN verwendet')
            self.store.execute('DELETE FROM sim_objects WHERE server_id=? AND site_id=? AND kind=? AND id=?',
                (server_id, site_id, 'radius', object_id))
            return {}
        try:
            value = write_payload('radius', payload)
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        if any(existing['id'] != object_id and existing['name'] == value['name'] for existing in self._all(server_id, site_id, 'radius')):
            raise HTTPException(409, 'RADIUS-Profilname ist bereits vorhanden')
        value.update({'id': object_id or str(uuid4()), 'metadata': {'origin': 'USER_DEFINED'}})
        self._save(server_id, site_id, 'radius', value)
        return copy.deepcopy(value)

    def _all(self, server_id, site_id, kind):
        return [json.loads(item['payload']) for item in self.store.query(
            'SELECT payload FROM sim_objects WHERE server_id=? AND site_id=? AND kind=? ORDER BY id',
            (server_id, site_id, kind))]

    def _get(self, server_id, site_id, kind, object_id):
        row = self.store.one('SELECT payload FROM sim_objects WHERE server_id=? AND site_id=? AND kind=? AND id=?',
            (server_id, site_id, kind, object_id))
        if not row:
            raise HTTPException(404, 'Simuliertes UniFi-Objekt fehlt')
        return json.loads(row['payload'])

    def _references(self, server_id, site_id, network_id):
        self._get(server_id, site_id, 'network', network_id)
        references = []
        for wifi in self._all(server_id, site_id, 'wifi'):
            networks = [wifi.get('network', {})] + [item.get('network', {}) for item in wifi.get('securityConfiguration', {}).get('presharedKeys') or []]
            if any(item.get('networkId') == network_id for item in networks if isinstance(item, dict)):
                references.append({'referenceId': wifi['id']})
        return {'referenceResources': [{'resourceType': 'WIFI', 'referenceCount': len(references), 'references': references}] if references else []}

    def _associations(self, server_id, site_id, value):
        networks = [value.get('network', {})] + [item.get('network', {}) for item in value.get('securityConfiguration', {}).get('presharedKeys') or []]
        for reference in networks:
            if isinstance(reference, dict) and reference.get('type') == 'SPECIFIC':
                self._get(server_id, site_id, 'network', reference['networkId'])
        profile = (value.get('securityConfiguration', {}).get('radiusConfiguration') or {}).get('profileId')
        if profile:
            self._seed_radius(server_id, site_id)
            self._get(server_id, site_id, 'radius', profile)

    @staticmethod
    def _page(data, query):
        offset = int(query.get('offset', ['0'])[0])
        limit = int(query.get('limit', ['25'])[0])
        page = data[offset:offset + limit]
        return {'data': page, 'offset': offset, 'limit': limit, 'count': len(page), 'totalCount': len(data)}

    async def request(self, server, method, path, payload=None):
        if isinstance(path, str) and '/radius/configurations' in path:
            return await self._radius_request(server, method, path, payload)
        try:
            parsed, query, collection, obj, references = _route(method, path)
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        server_id = server['id']
        sites = self._sites(server_id)
        if parsed.path == '/info':
            return {'applicationVersion': CONTRACT['version']}
        if parsed.path == '/sites':
            return self._page(sites, query)
        route = collection or obj or references
        site_id = route.group(1)
        self._seed(server_id, site_id)
        if references:
            return self._references(server_id, site_id, references.group(2))
        resource = route.group(2)
        if resource == 'radius/profiles':
            self._seed_radius(server_id, site_id)
            return self._page([{key: value[key] for key in ('id', 'name', 'metadata')}
                              for value in self._all(server_id, site_id, 'radius')], query)
        if resource in ('devices', 'device-tags'):
            return self._page([], query)
        kind = 'wifi' if resource == 'wifi/broadcasts' else 'network'
        object_id = obj.group(3) if obj else None
        if method == 'GET':
            if object_id:
                return copy.deepcopy(self._get(server_id, site_id, kind, object_id))
            values = copy.deepcopy(self._all(server_id, site_id, kind))
            if kind == 'wifi':
                for value in values:
                    security = value['securityConfiguration']
                    value['securityConfiguration'] = {'type': security['type']}
                    if security.get('presharedKeys'):
                        value['securityConfiguration']['presharedKeyNetworkIds'] = [item['network'] for item in security['presharedKeys']]
            return self._page(values, query)
        before = self._get(server_id, site_id, kind, object_id) if object_id else None
        if before and (before.get('default') or before.get('metadata', {}).get('origin') != 'USER_DEFINED'):
            raise HTTPException(409, 'Standardnetz und systemverwaltete Objekte sind geschützt')
        if method == 'DELETE':
            if kind == 'network' and self._references(server_id, site_id, object_id)['referenceResources']:
                raise HTTPException(409, 'VLAN wird noch von WLAN verwendet')
            self.store.execute('DELETE FROM sim_objects WHERE server_id=? AND site_id=? AND kind=? AND id=?',
                (server_id, site_id, kind, object_id))
            return {}
        try:
            value = write_payload(kind, payload)
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        if kind == 'wifi':
            self._associations(server_id, site_id, value)
        for existing in self._all(server_id, site_id, kind):
            if existing['id'] != object_id and (existing['name'] == value['name'] or kind == 'network' and existing['vlanId'] == value['vlanId']):
                raise HTTPException(409, 'WLAN-Name oder VLAN-ID ist bereits vorhanden')
        value.update({'id': object_id or str(uuid4()), 'metadata': {'origin': 'USER_DEFINED'}})
        if kind == 'network':
            value['default'] = False
        self._save(server_id, site_id, kind, value)
        return copy.deepcopy(value)

    async def collection(self, server, path):
        if isinstance(path, str) and '/radius/configurations' in path:
            from app.radius import radius_route
            site_id, object_id, references, query = radius_route('GET', path)
            if object_id or references or query:
                raise HTTPException(422, 'Ungültiger RADIUS-Sammlungspfad')
            self._seed(server['id'], site_id)
            self._seed_radius(server['id'], site_id)
            return copy.deepcopy(self._all(server['id'], site_id, 'radius'))
        return await _collect(self, server, path)

    async def close(self):
        pass
