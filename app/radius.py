"""Opt-in local UniFi OS adapter for the classic, private RADIUS profile API.

The official Integration API exposes RADIUS overviews only. These internal
configuration routes are deliberately separate and never passed to that API.
The classic field mapping follows the SDK implementations documented in README.
"""
import asyncio
import base64
import hashlib
import json
import re
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlsplit

import httpx
from fastapi import HTTPException

from app.contract import MASK, write_payload
from app.unifi import LocalClient

_IDENTITY = r'[A-Za-z0-9_-]{1,128}'
_PATH = re.compile(rf'/sites/({_IDENTITY})/radius/configurations(?:/({_IDENTITY})(/references)?)?')
_LEGACY_ID = re.compile(r'[a-fA-F0-9]{24}')
_REFERENCE_COLLECTIONS = ('rest/wlanconf', 'rest/networkconf', 'rest/portconf', 'get/setting', 'stat/device')


def radius_route(method, path):
    """Validate the app-internal route, never an externally supplied URL."""
    if method not in ('GET', 'POST', 'PUT', 'DELETE') or not isinstance(path, str):
        raise HTTPException(422, 'Ungültige RADIUS-Operation')
    parsed = urlsplit(path)
    route = _PATH.fullmatch(parsed.path)
    if (not route or parsed.scheme or parsed.netloc or parsed.fragment or '%' in parsed.path
            or '..' in parsed.path or '\\' in path):
        raise HTTPException(422, 'Ungültiger interner RADIUS-Pfad')
    try:
        query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True) if parsed.query else {}
    except ValueError:
        raise HTTPException(422, 'Ungültige RADIUS-Parameter') from None
    site_id, object_id, references = route.groups()
    if ((method == 'POST' and object_id) or (method in ('PUT', 'DELETE') and not object_id)
            or references and method != 'GET'):
        raise HTTPException(422, 'RADIUS-Pfad und Operation passen nicht zusammen')
    allowed = {'offset', 'limit'} if method == 'GET' and not object_id else set()
    if set(query) - allowed or any(len(values) != 1 for values in query.values()):
        raise HTTPException(422, 'Ungültige RADIUS-Parameter')
    for key, values in query.items():
        if not values[0].isdigit() or int(values[0]) > (200 if key == 'limit' else 200000):
            raise HTTPException(422, 'Ungültige RADIUS-Paginierung')
    return site_id, object_id, bool(references), query


def _server_rows(value):
    if not isinstance(value, list):
        return value
    result = []
    for server in value:
        if not isinstance(server, dict):
            result.append(server)
            continue
        row = {'host': server.get('ip'), 'port': server.get('port'),
               'sharedSecret': server.get('x_secret', MASK)}
        # The classic controller sometimes serializes numeric fields as strings.
        if isinstance(row['port'], str) and row['port'].isdigit():
            row['port'] = int(row['port'])
        unknown = set(server) - {'ip', 'port', 'x_secret'}
        if unknown:
            row['unsupportedConfiguration'] = sorted(unknown)
        result.append(row)
    return result


def normalize_profile(value):
    if not isinstance(value, dict) or not _LEGACY_ID.fullmatch(str(value.get('_id', ''))):
        raise HTTPException(502, 'UniFi lieferte ein ungültiges RADIUS-Profil')
    protected = any(value.get(key) not in (False, None, '') for key in
        ('attr_no_edit', 'attr_no_delete', 'attr_hidden', 'attr_hidden_id', 'use_usg_auth_server', 'use_usg_acct_server'))
    interval = value.get('interim_update_interval', 600)
    if isinstance(interval, str) and interval.isdigit():
        interval = int(interval)
    result = {'id': value['_id'], 'name': value.get('name'),
        'metadata': {'origin': 'SYSTEM_DEFINED' if protected else 'USER_DEFINED'},
        'authenticationServers': _server_rows(value.get('auth_servers', [])),
        'accountingEnabled': value.get('accounting_enabled', False),
        'accountingServers': _server_rows(value.get('acct_servers', [])),
        'accountingInterimEnabled': value.get('interim_update_enabled', False),
        'accountingInterimIntervalSeconds': interval,
        'vlanAssignmentMode': value.get('vlan_wlan_mode') or 'disabled'}
    known = {'_id', 'site_id', 'external_id', 'name', 'auth_servers', 'acct_servers',
        'accounting_enabled', 'interim_update_enabled', 'interim_update_interval', 'vlan_wlan_mode',
        'vlan_enabled', 'use_usg_auth_server', 'use_usg_acct_server',
        'attr_no_edit', 'attr_no_delete', 'attr_hidden', 'attr_hidden_id'}
    unsupported = set(value) - known
    # Only inert TLS metadata is harmless. Active RadSec and any unfamiliar
    # configuration remain visible as field names and block all writes.
    if value.get('tls_enabled') in (False, None):
        unsupported.discard('tls_enabled')
    if value.get('x_ca_crts') in (None, []):
        unsupported.discard('x_ca_crts')
    if value.get('vlan_enabled') not in (False, None):
        unsupported.add('vlan_enabled')
    if unsupported:
        result['unsupportedConfiguration'] = sorted(unsupported)
    return result


def legacy_payload(value):
    source = write_payload('radius', value)
    rows = lambda servers: [{'ip': server['host'], 'port': server['port'], 'x_secret': server['sharedSecret']}
                            for server in servers]
    return {'name': source['name'], 'auth_servers': rows(source['authenticationServers']),
        'acct_servers': rows(source['accountingServers']), 'accounting_enabled': source['accountingEnabled'],
        'interim_update_enabled': source['accountingInterimEnabled'],
        'interim_update_interval': source['accountingInterimIntervalSeconds'],
        'vlan_wlan_mode': source['vlanAssignmentMode'], 'vlan_enabled': False,
        'use_usg_auth_server': False, 'use_usg_acct_server': False}


class RadiusClient:
    """Isolated local pools; API-key or explicit account auth, no fallback."""
    def __init__(self, concurrency=4, timeout=20, transport=None, allowed_hosts=None):
        self.local = LocalClient(concurrency, timeout, transport, allowed_hosts)
        self.sessions = {}
        self.session_locks = {}

    def _configuration(self, server):
        if server.get('radius_legacy_enabled') is not True:
            raise HTTPException(409, 'RADIUS-Konfiguration muss am UniFi-Server ausdrücklich aktiviert werden')
        mode = server.get('radius_auth_mode', 'api_key')
        if mode not in ('api_key', 'local_account'):
            raise HTTPException(422, 'Ungültige RADIUS-Anmeldemethode')
        names = ('key', 'api_key') if mode == 'api_key' else ('radius_username', 'radius_password')
        credentials = {name: server.get(name) for name in names}
        if mode == 'api_key':
            key = server.get('key') or server.get('api_key')
            if not isinstance(key, str) or not key or any(char in key for char in '\r\n'):
                raise HTTPException(502, 'Lokaler UniFi-API-Schlüssel fehlt oder ist ungültig')
        elif any(not isinstance(credentials[name], str) or not credentials[name] for name in names):
            raise HTTPException(409, 'Lokales UniFi-OS-Konto und Kennwort sind für RADIUS erforderlich')
        fingerprint = hashlib.sha256(json.dumps([server['id'], server['origin'], server.get('ca_file'), mode,
            credentials], sort_keys=True).encode()).hexdigest()
        isolated = server | {'id': 'radius-' + fingerprint}
        return mode, fingerprint, isolated

    async def _wire(self, server, method, path, payload=None, headers=None):
        # This helper is private; every path is produced by the adapter from
        # strict identifiers and a fixed route allowlist below.
        try:
            client, semaphore, host, port = await self.local._pool(server)
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        address = await self.local._resolve(host, port)
        url = httpx.URL(server['origin'].rstrip('/') + path).copy_with(host=address)
        outgoing = {'Accept': 'application/json', 'Accept-Encoding': 'identity',
                    'Host': urlsplit(server['origin']).netloc, 'Cookie': ''} | (headers or {})
        async with semaphore:
            try:
                async with client.stream(method, url, json=payload if payload is not None else None,
                        headers=outgoing, extensions={'sni_hostname': host}) as remote:
                    body = bytearray()
                    if 200 <= remote.status_code < 300:
                        async for chunk in remote.aiter_bytes():
                            if len(body) + len(chunk) > 16 * 1024 * 1024:
                                raise HTTPException(502, 'UniFi-Antwort überschreitet die Größenbegrenzung')
                            body.extend(chunk)
                    response = httpx.Response(remote.status_code, headers=remote.headers,
                                              content=bytes(body), request=remote.request)
            except (httpx.TimeoutException, httpx.NetworkError):
                raise HTTPException(502, 'Lokale RADIUS-Verbindung fehlgeschlagen; Schreibausgang gegebenenfalls unklar') from None
            finally:
                # Authentication state is held explicitly in this adapter's
                # RAM cache. HTTPX's automatic cookie jar never supplies auth.
                client.cookies.clear()
        return response

    async def _session(self, isolated, fingerprint, force=False):
        lock = self.session_locks.setdefault(fingerprint, asyncio.Lock())
        async with lock:
            cached = self.sessions.get(fingerprint)
            if not force and cached and cached['expires'] > time.monotonic():
                return cached
            self.sessions.pop(fingerprint, None)
            response = await self._wire(isolated, 'POST', '/api/auth/login', {
                'username': isolated['radius_username'], 'password': isolated['radius_password'], 'rememberMe': False})
            if response.status_code != 200:
                raise HTTPException(502, f'Lokale UniFi-OS-Anmeldung antwortete mit HTTP {response.status_code}')
            token = None
            for header in response.headers.get_list('set-cookie'):
                if len(header) > 16384:
                    continue
                cookie = SimpleCookie()
                try:
                    cookie.load(header)
                except Exception:
                    continue
                if 'TOKEN' in cookie:
                    token = cookie['TOKEN'].value
            if (not isinstance(token, str) or not 1 <= len(token) <= 8192
                    or any(not 33 <= ord(char) <= 126 or char == ';' for char in token)):
                raise HTTPException(502, 'UniFi-OS-Anmeldung lieferte kein gültiges Sitzungscookie')
            csrf = response.headers.get('x-csrf-token')
            if not csrf:
                try:
                    encoded = token.split('.')[1]
                    claims = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
                    csrf = claims.get('csrfToken')
                except (ValueError, IndexError, UnicodeDecodeError):
                    csrf = None
            if (not isinstance(csrf, str) or not 1 <= len(csrf) <= 1024
                    or any(not 32 <= ord(char) <= 126 for char in csrf)):
                raise HTTPException(502, 'UniFi-OS-Anmeldung lieferte kein gültiges CSRF-Token')
            session = {'token': token, 'csrf': csrf, 'expires': time.monotonic() + 300}
            self.sessions[fingerprint] = session
            return session

    async def _legacy(self, server, method, path, payload=None):
        mode, fingerprint, isolated = self._configuration(server)
        attempts = 2 if mode == 'local_account' and method == 'GET' else 1
        for attempt in range(attempts):
            if mode == 'api_key':
                headers = {'X-API-Key': server.get('key') or server.get('api_key')}
            else:
                session = await self._session(isolated, fingerprint, force=bool(attempt))
                headers = {'Cookie': 'TOKEN=' + session['token'], 'X-CSRF-Token': session['csrf']}
            response = await self._wire(isolated, method, path, payload, headers)
            if response.status_code == 401:
                self.sessions.pop(fingerprint, None)
                if attempt + 1 < attempts:
                    continue
            if not 200 <= response.status_code < 300:
                status = response.status_code if response.status_code in (404, 409, 429) else 502
                raise HTTPException(status, f'Lokale RADIUS-API antwortete mit HTTP {response.status_code}')
            try:
                body = response.json()
            except (ValueError, UnicodeDecodeError):
                raise HTTPException(502, 'Lokale RADIUS-API lieferte ungültiges JSON') from None
            if (not isinstance(body, dict) or not isinstance(body.get('meta'), dict)
                    or body['meta'].get('rc') != 'ok' or not isinstance(body.get('data'), list)
                    or len(body['data']) > 200000):
                raise HTTPException(502, 'Lokale RADIUS-API lieferte ein unerwartetes Antwortformat')
            return body['data']

    @staticmethod
    def _base(site_reference):
        if not isinstance(site_reference, str) or not re.fullmatch(_IDENTITY, site_reference) or '..' in site_reference:
            raise HTTPException(409, 'Die lokale UniFi-Site-Referenz fehlt; Inventar synchronisieren')
        return '/proxy/network/api/s/' + site_reference + '/'

    async def _profiles(self, server, site_reference):
        values = await self._legacy(server, 'GET', self._base(site_reference) + 'rest/radiusprofile')
        profiles = [normalize_profile(value) for value in values]
        if len({profile['id'] for profile in profiles}) != len(profiles):
            raise HTTPException(502, 'UniFi lieferte doppelte RADIUS-Profil-IDs')
        return profiles

    async def _references(self, server, site_reference, object_id):
        base, resources = self._base(site_reference), []
        profiles = await self._legacy(server, 'GET', base + 'rest/radiusprofile/' + object_id)
        if (len(profiles) != 1 or not isinstance(profiles[0], dict)
                or profiles[0].get('_id') != object_id):
            raise HTTPException(404 if not profiles else 502, 'Lokales RADIUS-Profil fehlt oder ist ungültig')
        identifiers = {object_id}
        alias = profiles[0].get('external_id')
        if alias is not None:
            if not isinstance(alias, str) or not 1 <= len(alias) <= 128 or any(ord(char) < 32 or ord(char) == 127 for char in alias):
                raise HTTPException(502, 'UniFi lieferte einen ungültigen RADIUS-Profil-Alias')
            identifiers.add(alias)
        def uses(value):
            if isinstance(value, dict):
                return any(uses(item) for item in value.values())
            if isinstance(value, list):
                return any(uses(item) for item in value)
            # A newly named field or an array reference must not permit a
            # delete merely because its spelling is unfamiliar to this tool.
            return isinstance(value, str) and value in identifiers
        for collection in _REFERENCE_COLLECTIONS:
            values = await self._legacy(server, 'GET', base + collection)
            if any(not isinstance(value, dict) for value in values):
                raise HTTPException(502, 'UniFi lieferte ungültige RADIUS-Verweise')
            references = [{'referenceId': str(value.get('_id') or value.get('key') or index)}
                          for index, value in enumerate(values) if uses(value)]
            if references:
                resources.append({'resourceType': collection, 'referenceCount': len(references), 'references': references})
        return {'referenceResources': resources}

    async def request(self, server, method, path, payload=None, *, site_reference=None):
        _, object_id, references, query = radius_route(method, path)
        self._configuration(server)
        base = self._base(site_reference) + 'rest/radiusprofile'
        if object_id and not _LEGACY_ID.fullmatch(object_id):
            raise HTTPException(422, 'Ungültige lokale RADIUS-Profil-ID')
        if method in ('GET', 'DELETE') and payload is not None:
            raise HTTPException(422, 'Lesen und Löschen akzeptieren keinen Anfragekörper')
        if references:
            return await self._references(server, site_reference, object_id)
        if method == 'GET' and not object_id:
            values = await self._profiles(server, site_reference)
            offset, limit = int(query.get('offset', ['0'])[0]), int(query.get('limit', ['25'])[0])
            page = values[offset:offset + limit]
            return {'data': page, 'offset': offset, 'limit': limit, 'count': len(page), 'totalCount': len(values)}
        if method == 'GET':
            values = await self._legacy(server, 'GET', base + '/' + object_id)
            if len(values) != 1 or not isinstance(values[0], dict) or values[0].get('_id') != object_id:
                raise HTTPException(404 if not values else 502, 'Lokales RADIUS-Profil fehlt oder ist ungültig')
            return normalize_profile(values[0])
        try:
            body = legacy_payload(payload) if method in ('POST', 'PUT') else None
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        values = await self._legacy(server, method, base + ('/' + object_id if object_id else ''), body)
        if method == 'DELETE':
            return {}
        if len(values) != 1 or not isinstance(values[0], dict):
            raise HTTPException(502, 'RADIUS-Schreibantwort lieferte kein eindeutiges Profil; Ausgang unklar')
        result = normalize_profile(values[0])
        if object_id and result['id'] != object_id:
            raise HTTPException(502, 'RADIUS-Schreibantwort lieferte eine andere Profil-ID; Ausgang unklar')
        return result

    async def collection(self, server, path, *, site_reference=None):
        _, object_id, references, query = radius_route('GET', path)
        if object_id or references or query:
            raise HTTPException(422, 'RADIUS-Sammlungsabruf benötigt einen unveränderten Sammlungspfad')
        return await self._profiles(server, site_reference)

    async def close(self):
        self.sessions.clear()
        self.session_locks.clear()
        await self.local.close()
