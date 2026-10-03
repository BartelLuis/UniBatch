"""Fail-closed validation of the pinned, documented local UniFi API contract.

Only WLAN broadcasts, unmanaged VLANs and external RADIUS profiles can be written. Response-only metadata
is removed explicitly; unfamiliar configuration is never silently discarded.
"""
import copy
import ipaddress
import json
import math
import re
from pathlib import Path
from uuid import UUID

CONTRACT = json.loads((Path(__file__).parent / 'unifi-contract.json').read_text(encoding='utf-8'))
SCHEMAS = CONTRACT['schemas']
MASK = '<redacted>'
_READ_ONLY = {'id', 'metadata', 'default'}
_DISCRIMINATORS = {'type', 'management', 'mode', 'action'}
_RADIUS_SERVER_SCHEMA = {'type': 'object', 'required': ['host', 'port', 'sharedSecret'], 'properties': {
    'host': {'type': 'string', 'minLength': 1, 'maxLength': 253},
    'port': {'type': 'integer', 'minimum': 1, 'maximum': 65535},
    'sharedSecret': {'type': 'string', 'minLength': 1, 'maxLength': 128}}}
_RADIUS_SCHEMA = {'type': 'object', 'required': ['name', 'authenticationServers', 'accountingEnabled',
    'accountingServers', 'accountingInterimEnabled', 'accountingInterimIntervalSeconds', 'vlanAssignmentMode'], 'properties': {
    'name': {'type': 'string', 'minLength': 1, 'maxLength': 128},
    'authenticationServers': {'type': 'array', 'minItems': 1, 'maxItems': 8, 'items': _RADIUS_SERVER_SCHEMA},
    'accountingEnabled': {'type': 'boolean'},
    'accountingServers': {'type': 'array', 'maxItems': 8, 'items': _RADIUS_SERVER_SCHEMA},
    'accountingInterimEnabled': {'type': 'boolean'},
    'accountingInterimIntervalSeconds': {'type': 'integer', 'minimum': 60, 'maximum': 86400},
    'vlanAssignmentMode': {'type': 'string', 'enum': ['disabled', 'optional', 'required']}}}


def _kind(kind):
    if kind == 'wifi':
        return 'wifi'
    if kind in ('vlan', 'network'):
        return 'network'
    if kind == 'radius':
        return 'radius'
    raise ValueError('Nur WLAN, VLAN und RADIUS werden unterstützt')


def secret_field(key):
    key = re.sub(r'[^a-z0-9]', '', key.casefold())
    return (any(term in key for term in ('password', 'passphrase', 'secret', 'presharedkey', 'privatekey'))
            or key in {'key', 'apikey', 'token', 'accesstoken', 'refreshtoken', 'bindpassword'})


def redact(value):
    """Return a copy safe for previews, audit events and application responses."""
    if isinstance(value, dict):
        return {key: MASK if secret_field(key) and item is not None else redact(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return copy.deepcopy(value)


def deep_merge(before, patch):
    """Merge objects, replace arrays; changing a subtype replaces its object."""
    if not isinstance(before, dict) or not isinstance(patch, dict):
        return copy.deepcopy(patch)
    if any(key in before and key in patch and before[key] != patch[key]
           for key in _DISCRIMINATORS):
        return copy.deepcopy(patch)
    result = copy.deepcopy(before)
    for key, value in patch.items():
        result[key] = deep_merge(result.get(key), value)
    return result


def effective(schema, value, seen=None, partial=False):
    """Resolve inheritance and discriminator, including recursive base schemas."""
    seen = set() if seen is None else seen.copy()
    if '$ref' in schema:
        name = schema['$ref'].rsplit('/', 1)[-1]
        if name in seen:
            return {}
        if name not in SCHEMAS:
            raise ValueError('Unbekannte UniFi-Vertragsreferenz')
        seen.add(name)
        schema = SCHEMAS[name]
    result = {'properties': {}, 'required': []}
    for sub in schema.get('allOf', []):
        part = effective(sub, value, seen, partial)
        result.update({key: item for key, item in part.items() if key not in ('properties', 'required')})
        result['properties'].update(part.get('properties', {}))
        result['required'].extend(part.get('required', []))
    result.update({key: item for key, item in schema.items()
                   if key not in ('properties', 'required', 'allOf', 'discriminator')})
    result['properties'].update(schema.get('properties', {}))
    result['required'].extend(schema.get('required', []))
    discriminator = schema.get('discriminator')
    if discriminator and isinstance(value, dict):
        key = discriminator['propertyName']
        mapping = discriminator.get('mapping', {})
        if key in value:
            if value[key] not in mapping:
                raise ValueError(f'Unbekannter UniFi-Konfigurationstyp: {key}')
            variants = [mapping[value[key]]]
        elif partial:
            variants = list(mapping.values())
        else:
            raise ValueError(f'Pflichtfeld fehlt: {key}')
        for ref in variants:
            part = effective({'$ref': ref}, value, seen, partial)
            result['properties'].update(part.get('properties', {}))
            if not partial:
                result['required'].extend(part.get('required', []))
    return result


def _error(path, detail):
    raise ValueError(f'{path or "Konfiguration"}: {detail}')


def _masked(value):
    if not isinstance(value, str):
        return False
    return (value.casefold().strip() in {'<redacted>', '[redacted]', 'redacted', '********', '••••••••'}
            or len(value) >= 3 and set(value) in ({'*'}, {'•'}))


def _validate(value, schema, path='', partial=False, nullable=False):
    if value is None:
        if nullable or schema.get('nullable') or 'null' in schema.get('type', []):
            return None
        _error(path, 'darf nicht null sein')
    shape = effective(schema, value, partial=partial)
    expected = shape.get('type')
    if not expected and shape.get('properties'):
        expected = 'object'
    if not expected and not shape.get('properties'):
        _error(path, 'kein schreibbares Schema vorhanden')
    checks = {'object': isinstance(value, dict), 'array': isinstance(value, list),
              'string': isinstance(value, str), 'boolean': type(value) is bool,
              'integer': type(value) is int,
              'number': type(value) in (int, float) and math.isfinite(value)}
    if expected and not checks.get(expected, False):
        _error(path, f'erwartet {expected}')
    if isinstance(value, dict):
        props = shape.get('properties', {})
        unknown = set(value) - set(props)
        if unknown:
            _error(path, 'unbekannte oder nicht schreibbare Felder: ' + ', '.join(sorted(unknown)))
        required = set(shape.get('required', []))
        if not partial and required - set(value):
            _error(path, 'Pflichtfelder fehlen: ' + ', '.join(sorted(required - set(value))))
        result = {}
        for key, item in value.items():
            child_path = f'{path}.{key}' if path else key
            if secret_field(key) and _masked(item):
                _error(child_path, 'maskierte Sicherheitswerte dürfen nicht geschrieben werden')
            result[key] = _validate(item, props[key], child_path, partial, key not in required)
        return result
    if isinstance(value, list):
        if len(value) < shape.get('minItems', 0) or len(value) > min(shape.get('maxItems', 10000), 10000):
            _error(path, 'ungültige Anzahl von Einträgen')
        if shape.get('uniqueItems'):
            encoded = [json.dumps(item, sort_keys=True, separators=(',', ':')) for item in value]
            if len(set(encoded)) != len(encoded):
                _error(path, 'doppelte Einträge sind nicht zulässig')
        return [_validate(item, shape['items'], f'{path}[{index}]', partial=False)
                for index, item in enumerate(value)]
    if 'enum' in shape and value not in shape['enum']:
        # The official contract encodes a few integer enums as strings.
        if not (expected == 'integer' and str(value) in shape['enum']):
            _error(path, 'Wert ist im API-Vertrag nicht vorgesehen')
    if type(value) in (int, float):
        if value < shape.get('minimum', -math.inf) or value > shape.get('maximum', math.inf):
            _error(path, 'Wert liegt außerhalb des zulässigen Bereichs')
    if isinstance(value, str):
        if len(value) < shape.get('minLength', 0) or len(value) > min(shape.get('maxLength', 65536), 65536):
            _error(path, 'ungültige Textlänge')
        if shape.get('format') == 'uuid':
            try:
                UUID(value)
            except (ValueError, AttributeError):
                _error(path, 'gültige UUID erforderlich')
        if shape.get('pattern') and not re.fullmatch(shape['pattern'], value):
            _error(path, 'ungültiges Textformat')
        if path.endswith(('startTime', 'endTime')) and not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d', value):
            _error(path, 'Zeit muss als HH:mm angegeben werden')
        if 'macAddress' in path or 'MacAddress' in path:
            if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
                _error(path, 'MAC-Adresse muss sechs durch Doppelpunkt getrennte Oktette enthalten')
        if path.startswith('dhcpGuarding.trustedDhcpServerIpAddresses'):
            try:
                ipaddress.ip_address(value)
            except ValueError:
                _error(path, 'gültige DHCP-Server-IP-Adresse erforderlich')
    return copy.deepcopy(value)


def _rules(kind, value, complete):
    if 'name' in value:
        name = value['name']
        if not isinstance(name, str) or not name.strip() or any(ord(char) < 32 or ord(char) == 127 for char in name):
            _error('name', 'nicht leer und ohne Steuerzeichen angeben')
        if kind == 'wifi' and len(name.encode('utf-8')) > 32:
            _error('name', 'SSID darf maximal 32 UTF-8-Bytes lang sein')
    if kind == 'radius':
        for field in ('authenticationServers', 'accountingServers'):
            servers = value.get(field, [])
            seen = set()
            for index, server in enumerate(servers):
                path = f'{field}[{index}]'
                try:
                    address = ipaddress.ip_address(server['host'])
                except ValueError:
                    _error(path + '.host', 'gültige IPv4-Adresse erforderlich; Hostnamen werden von diesem UniFi-Vertrag nicht unterstützt')
                if address.version != 4 or address.is_multicast or address.is_unspecified or address.is_loopback:
                    _error(path + '.host', 'gültige RADIUS-IPv4-Adresse erforderlich')
                identity = (server['host'], server['port'])
                if identity in seen:
                    _error(field, 'doppelte RADIUS-Endpunkte sind nicht zulässig')
                seen.add(identity)
                if any(ord(char) < 32 or ord(char) == 127 for char in server['sharedSecret']):
                    _error(path + '.sharedSecret', 'Shared Secret darf keine Steuerzeichen enthalten')
        if (complete or 'accountingServers' in value) and value.get('accountingEnabled') and not value.get('accountingServers'):
            _error('accountingServers', 'Accounting benötigt mindestens einen Server')
        if (complete or 'accountingEnabled' in value) and value.get('accountingInterimEnabled') and not value.get('accountingEnabled'):
            _error('accountingInterimEnabled', 'Accounting-Zwischenupdates setzen aktiviertes Accounting voraus')
        return
    if kind == 'network':
        unknown = set(value) - {'management', 'name', 'enabled', 'vlanId', 'dhcpGuarding'} - _READ_ONLY
        if unknown:
            _error('VLAN', 'nicht unterstützte Felder: ' + ', '.join(sorted(unknown)))
        if value.get('management', 'UNMANAGED') != 'UNMANAGED':
            _error('management', 'nur externe VLANs (UNMANAGED) sind erlaubt')
        if value.get('vlanId') == 1 or value.get('default') is True:
            _error('vlanId', 'das Standardnetz/VLAN 1 ist geschützt')
        return
    security = value.get('securityConfiguration')
    if not isinstance(security, dict):
        return
    security_type = security.get('type', '')
    if complete and security_type.endswith('_PERSONAL'):
        if not security.get('passphrase') and not security.get('presharedKeys'):
            _error('securityConfiguration', 'Passphrase oder persönliche Schlüssel erforderlich; unbekannte Geheimnisse werden nicht überschrieben')
    if complete and security_type.endswith('_ENTERPRISE') and not security.get('radiusConfiguration'):
        _error('securityConfiguration', 'RADIUS-Profil erforderlich')
    for psk in security.get('presharedKeys') or []:
        passphrase = psk.get('passphrase')
        if not isinstance(passphrase, str) or not 8 <= len(passphrase) <= 63 or _masked(passphrase):
            _error('securityConfiguration.presharedKeys', 'Passphrase muss 8 bis 63 Zeichen enthalten')
    if security.get('wpa3FastRoamingEnabled') and (complete or 'fastRoamingEnabled' in security) and not security.get('fastRoamingEnabled'):
        _error('securityConfiguration', 'WPA3 Fast Roaming setzt Fast Roaming voraus')
    if complete and 6 in value.get('broadcastingFrequenciesGHz', []):
        if security_type not in ('WPA3_PERSONAL', 'WPA3_ENTERPRISE'):
            _error('broadcastingFrequenciesGHz', '6 GHz setzt WPA3 voraus')


def _schema(kind):
    if kind == 'radius':
        return _RADIUS_SCHEMA
    return {'$ref': '#/components/schemas/' + ('Wifi broadcast create or update' if kind == 'wifi' else 'Create or update Network')}


def validate_patch(kind, patch, operation='update'):
    kind = _kind(kind)
    if operation not in ('create', 'update', 'delete'):
        raise ValueError('Unbekannte Operation')
    if not isinstance(patch, dict) or (not patch and operation != 'delete'):
        raise ValueError('Eine nicht leere Konfiguration ist erforderlich')
    if operation == 'delete':
        if patch:
            raise ValueError('Löschen akzeptiert keine Konfigurationsänderung')
        return {}
    result = _validate(patch, _schema(kind), partial=True)
    _rules(kind, result, complete=False)
    return result


def write_payload(kind, value):
    kind = _kind(kind)
    if not isinstance(value, dict):
        raise ValueError('Konfiguration muss ein Objekt sein')
    if kind == 'network' and value.get('default') is True:
        _error('default', 'das Standardnetz ist geschützt')
    source = {key: item for key, item in value.items() if key not in _READ_ONLY}
    result = _validate(source, _schema(kind))
    _rules(kind, result, complete=True)
    return result


def create_defaults(kind, patch):
    kind = _kind(kind)
    validate_patch(kind, patch, operation='create')
    if kind == 'network':
        defaults = {'management': 'UNMANAGED', 'enabled': True}
    elif kind == 'radius':
        defaults = {'accountingEnabled': False, 'accountingServers': [], 'accountingInterimEnabled': False,
                    'accountingInterimIntervalSeconds': 600, 'vlanAssignmentMode': 'disabled'}
    else:
        if 'securityConfiguration' not in patch:
            raise ValueError('WLAN-Erstellung benötigt eine ausdrückliche Sicherheitskonfiguration')
        defaults = {'type': patch.get('type', 'STANDARD'), 'enabled': True,
                    'network': {'type': 'NATIVE'}, 'multicastToUnicastConversionEnabled': False,
                    'clientIsolationEnabled': False, 'hideName': False, 'uapsdEnabled': False}
        if defaults['type'] == 'STANDARD':
            defaults.update({'broadcastingFrequenciesGHz': [2.4, 5], 'advertiseDeviceName': False,
                             'arpProxyEnabled': False, 'bssTransitionEnabled': True,
                             'bandSteeringEnabled': False, 'mloEnabled': False})
        security = patch['securityConfiguration']
        if isinstance(security, dict):
            defaults['securityConfiguration'] = {'type': security.get('type', 'WPA2_PERSONAL')}
            if 'WPA3_PERSONAL' in security.get('type', ''):
                defaults['securityConfiguration']['saeConfiguration'] = {'anticloggingThresholdSeconds': 5, 'syncTimeSeconds': 5}
            if security.get('type') == 'WPA2_WPA3_PERSONAL':
                defaults['securityConfiguration'].update({'pmfMode': 'OPTIONAL', 'wpa3FastRoamingEnabled': False})
    return write_payload(kind, deep_merge(defaults, patch))


def default_wifi(name, security_type='WPA2_PERSONAL', passphrase=None, network=None):
    security = {'type': security_type}
    if passphrase is not None:
        security['passphrase'] = passphrase
    return create_defaults('wifi', {'name': name, 'securityConfiguration': security,
                                   **({'network': network} if network else {})})
