"""Read-only directory authentication over verified LDAPS, without local fallback."""
import json
import re
import ssl
import time
from pathlib import Path
from urllib.parse import urlsplit

from ldap3 import AUTO_BIND_NO_TLS, NONE, Connection, Server, Tls
from ldap3.utils.conv import escape_filter_chars

DEFAULT_CONFIG = {
    'enabled': False, 'url': '', 'base_dn': '', 'bind_dn': '', 'ca_file': '',
    'role_groups': {}, 'scope': ['*'], 'user_attribute': 'sAMAccountName',
    'object_class': 'user', 'group_attribute': 'memberOf', 'nested_ad_groups': False,
}


def validate_config(config):
    allowed = set(DEFAULT_CONFIG) | {'bind_password', 'bind_password_file'}
    if set(config) - allowed:
        raise ValueError('Unbekannte Verzeichnis-Einstellung')
    result = DEFAULT_CONFIG | {k: v for k, v in config.items() if k in DEFAULT_CONFIG}
    if type(result['enabled']) is not bool or type(result['nested_ad_groups']) is not bool:
        raise ValueError('Ungültige Verzeichnis-Einstellung')
    for key in ('url', 'base_dn', 'bind_dn', 'ca_file'):
        if not isinstance(result[key], str) or len(result[key]) > 1024 or '\x00' in result[key]:
            raise ValueError('Ungültige Verzeichnis-Einstellung')
    for key in ('user_attribute', 'object_class', 'group_attribute'):
        if not isinstance(result[key], str) or not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9-]{0,63}', result[key]):
            raise ValueError('Ungültiges LDAP-Attribut')
    if result['url']:
        try:
            url = urlsplit(result['url'])
            if url.scheme != 'ldaps' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('', '/') or (url.port is not None and not 1 <= url.port <= 65535):
                raise ValueError
        except ValueError:
            raise ValueError('Es ist eine gültige LDAPS-Adresse erforderlich') from None
    if result['enabled'] and not all(result[k].strip() for k in ('url', 'base_dn', 'bind_dn')):
        raise ValueError('LDAPS-Adresse, Suchbasis und Bind-DN sind erforderlich')
    groups = result['role_groups']
    if not isinstance(groups, dict) or len(groups) > 100:
        raise ValueError('Ungültige Gruppenzuordnung')
    seen = set()
    for role, dn in groups.items():
        if not isinstance(role, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', role) or not isinstance(dn, str) or not 1 <= len(dn) <= 1024 or '\x00' in dn:
            raise ValueError('Ungültige Gruppenzuordnung')
        normalized = dn.strip().casefold()
        if normalized in seen:
            raise ValueError('Eine Gruppe darf nur einer Rolle zugeordnet werden')
        seen.add(normalized)
    if result['enabled'] and not groups:
        raise ValueError('Mindestens eine Gruppenzuordnung ist erforderlich')
    scope = result['scope']
    if not isinstance(scope, list) or not scope or len(scope) > 256 or any(not isinstance(s, str) or (s != '*' and not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}', s)) for s in scope):
        raise ValueError('Ungültiger Server-Berechtigungsbereich')
    if '*' in scope and scope != ['*']:
        raise ValueError('Der globale Bereich darf nicht mit Servern kombiniert werden')
    result['scope'] = sorted(set(scope))
    result['role_groups'] = {role: dn.strip() for role, dn in groups.items()}
    return result


def _settings(config, bind_password):
    if not isinstance(config, dict):
        config = json.loads(Path(config).read_text(encoding='utf-8-sig'))
        if bind_password is None and config.get('bind_password_file'):
            bind_password = Path(config['bind_password_file']).read_text(encoding='utf-8').strip()
        config = {'enabled': True} | config
    return validate_config(config), bind_password


def _connection_settings(config):
    url = urlsplit(config['url'])
    # Default SSL context requires modern TLS and trusted certificates. ldap3
    # verifies the server hostname in addition to this chain verification.
    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=config['ca_file'] or None, sni=url.hostname)
    server = Server(url.hostname, port=url.port or 636, use_ssl=True, tls=tls, connect_timeout=5, get_info=NONE)
    options = dict(auto_bind=AUTO_BIND_NO_TLS, auto_referrals=False, receive_timeout=10,
                   read_only=True, raise_exceptions=True, check_names=False)
    return server, options


def _lookup(config, username, bind_password):
    """Read mapped memberships and account state with the directory service account."""
    server, options = _connection_settings(config)
    attributes = [config['group_attribute']]
    active_directory = config['object_class'].casefold() == 'user'
    if active_directory:
        attributes += ['userAccountControl', 'msDS-User-Account-Control-Computed', 'accountExpires']
    with Connection(server, user=config['bind_dn'], password=bind_password, **options) as service:
        query = f'(&(objectClass={config["object_class"]})({config["user_attribute"]}={escape_filter_chars(username)}))'
        if not service.search(config['base_dn'], query, attributes=attributes, size_limit=2, time_limit=10):
            return None
        if len(service.entries) != 1:
            return None
        entry = service.entries[0]
        dn = entry.entry_dn
        if active_directory:
            # These attributes must be readable by the service account. Missing
            # account state cannot authorize unattended scheduled execution.
            try:
                control = int(entry['userAccountControl'].value)
                computed = int(entry['msDS-User-Account-Control-Computed'].value)
                expires = int(entry['accountExpires'].value)
            except (ValueError, TypeError, KeyError, AttributeError):
                return None
            if control & 2 or computed & (16 | 8388608):
                return None
            if expires not in (0, 9223372036854775807) and expires / 10_000_000 - 11644473600 <= time.time():
                return None
        groups = {str(value).strip().casefold() for value in entry[config['group_attribute']].values}
        if config['nested_ad_groups']:
            group_query = f'(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={escape_filter_chars(dn)}))'
            if not service.search(config['base_dn'], group_query, attributes=['distinguishedName'], size_limit=1000, time_limit=10):
                return None
            groups.update(group.entry_dn.strip().casefold() for group in service.entries)
    roles = [role for role, group in config['role_groups'].items() if group.strip().casefold() in groups]
    return (roles[0], dn) if len(roles) == 1 else None


def authorize(config, username, bind_password=None):
    """Recheck authorization without retaining or reusing a user's password."""
    config, bind_password = _settings(config, bind_password)
    if not config['enabled'] or len(username) > 100 or not bind_password:
        return None
    result = _lookup(config, username, bind_password)
    return result[0] if result else None


def authenticate(config, username, password, bind_password=None):
    """Return exactly one mapped role after a successful user bind; otherwise deny."""
    config, bind_password = _settings(config, bind_password)
    if not config['enabled'] or not password or len(username) > 100 or not bind_password:
        return None
    result = _lookup(config, username, bind_password)
    if not result:
        return None
    role, dn = result
    server, options = _connection_settings(config)
    with Connection(server, user=dn, password=password, **options):
        return role
