"""RADIUS uses the same immutable preview, approval and execution boundary."""
import json

import pytest
from fastapi import HTTPException

from test_workflow import env as env, run, signed, wait_job


TARGETS = [
    {'server': 'demo-01', 'site': 'site-0001'},
    {'server': 'demo-02', 'site': 'site-0101'},
]
DEFAULT_NAME = 'Behörden-RADIUS'


def configuration(name='RADIUS-Test', secret='radius-auth-test-secret-2026'):
    return {
        'name': name,
        'authenticationServers': [
            {'host': '10.20.0.10', 'port': 1812, 'sharedSecret': secret},
            {'host': '10.20.0.11', 'port': 1812, 'sharedSecret': secret + '-backup'},
        ],
        'accountingEnabled': True,
        'accountingServers': [
            {'host': '10.20.0.12', 'port': 1813, 'sharedSecret': 'radius-acct-secret-2026'},
        ],
        'accountingInterimEnabled': True,
        'accountingInterimIntervalSeconds': 600,
        'vlanAssignmentMode': 'optional',
    }


def plan_radius(client, operation='update', patch=None, name=DEFAULT_NAME, targets=None, **options):
    body = {
        'kind': 'radius', 'operation': operation,
        'targets': targets or [TARGETS[0]],
        'patch': patch if patch is not None else {'vlanAssignmentMode': 'required'},
        'selector': {'name': name},
        'reason': 'CHG-RADIUS kontrollierte RADIUS-Konfiguration',
    } | options
    response = client.post('/api/jobs', json=body)
    assert response.status_code == 200, response.text
    return response.json()['id']


def radius_objects(client, target=TARGETS[0]):
    response = client.get(f"/api/servers/{target['server']}/sites/{target['site']}/radius")
    assert response.status_code == 200, response.text
    return response.json()


def radius_detail(client, object_id, target=TARGETS[0]):
    response = client.get(f"/api/servers/{target['server']}/sites/{target['site']}/radius/{object_id}")
    assert response.status_code == 200, response.text
    return response.json()


def mutate_simulated(ctx, object_id, change, kind='radius', target=TARGETS[0]):
    row = ctx.store.one('SELECT payload FROM sim_objects WHERE server_id=? AND site_id=? AND kind=? AND id=?',
        (target['server'], target['site'], kind, object_id))
    assert row, 'Simulator must persist the configuration used in this regression'
    value = json.loads(row['payload'])
    change(value)
    ctx.store.execute('UPDATE sim_objects SET payload=? WHERE server_id=? AND site_id=? AND kind=? AND id=?',
        (json.dumps(value), target['server'], target['site'], kind, object_id))
    return value


def plan_enterprise(client, profile=DEFAULT_NAME, name='RADIUS-EAP-Test', targets=None):
    response = client.post('/api/jobs', json={
        'kind': 'wifi', 'operation': 'create', 'targets': targets or [TARGETS[0]],
        'patch': {'name': name, 'securityConfiguration': {'type': 'WPA2_ENTERPRISE', 'coaEnabled': False}},
        'radius_selector': profile, 'network_selector': 'Verwaltungsnetz',
        'reason': 'CHG-RADIUS Enterprise-WLAN mit lokalem Profil',
    })
    assert response.status_code == 200, response.text
    return response.json()['id']


def test_radius_crud_and_all_inverse_operations(env):
    app, _ = env
    operator, approver = signed(app), signed(app, 'approver')
    original = configuration()
    created = plan_radius(operator, 'create', original)
    result = run(operator, approver, created)
    object_id = result['targets'][0]['object']
    value = radius_detail(operator, object_id)
    assert value['authenticationServers'][0]['host'] == '10.20.0.10'
    assert value['authenticationServers'][0]['sharedSecret'] == '<redacted>'
    assert value['accountingEnabled'] and value['accountingInterimIntervalSeconds'] == 600

    patch = {'authenticationServers': [{'host': '10.20.0.20', 'port': 2812,
        'sharedSecret': 'rotated-radius-secret-2026'}], 'vlanAssignmentMode': 'required',
        'accountingInterimIntervalSeconds': 900}
    updated = plan_radius(operator, patch=patch, name='RADIUS-Test')
    run(operator, approver, updated)
    assert radius_detail(operator, object_id)['authenticationServers'][0]['port'] == 2812
    inverse = operator.post(f'/api/jobs/{updated}/rollback')
    assert inverse.status_code == 200, inverse.text
    run(operator, approver, inverse.json()['id'])
    restored = radius_detail(operator, object_id)
    assert len(restored['authenticationServers']) == 2
    assert restored['authenticationServers'][0]['host'] == '10.20.0.10'
    assert restored['accountingInterimIntervalSeconds'] == 600

    deleted = plan_radius(operator, 'delete', {}, name='RADIUS-Test')
    run(operator, approver, deleted)
    assert not any(v['name'] == 'RADIUS-Test' for v in radius_objects(operator))
    inverse = operator.post(f'/api/jobs/{deleted}/rollback')
    assert inverse.status_code == 200, inverse.text
    run(operator, approver, inverse.json()['id'])
    recreated = next(v for v in radius_objects(operator) if v['name'] == 'RADIUS-Test')
    assert recreated['id'] != object_id

    disposable = plan_radius(operator, 'create', configuration('Disposable RADIUS'))
    run(operator, approver, disposable)
    inverse = operator.post(f'/api/jobs/{disposable}/rollback')
    assert inverse.status_code == 200, inverse.text
    run(operator, approver, inverse.json()['id'])
    assert not any(v['name'] == 'Disposable RADIUS' for v in radius_objects(operator))


def test_radius_template_and_secrets_never_leave_encrypted_records(env):
    app, _ = env
    operator, approver, admin = signed(app), signed(app, 'approver'), signed(app, 'admin')
    patch = configuration('Encrypted Radius Template')
    secrets = [item['sharedSecret'] for key in ('authenticationServers', 'accountingServers') for item in patch[key]]
    response = operator.post('/api/templates', json={
        'name': 'Radius Template', 'kind': 'radius', 'operation': 'create', 'patch': patch})
    assert response.status_code == 200, response.text
    template_id = response.json()['id']
    job = plan_radius(operator, 'create', {}, targets=TARGETS, template_id=template_id)
    result = run(operator, approver, job)
    assert result['counts']['applied'] == 2
    public = [operator.get('/api/templates').text, operator.get(f'/api/jobs/{job}').text,
        operator.get(f'/api/jobs/{job}/export').text, admin.get('/api/audit/export').text]
    public.extend(json.dumps(radius_objects(operator, target)) for target in TARGETS)
    encrypted = [app.state.ctx.store.one('SELECT blob FROM batch_jobs WHERE id=?', (job,))['blob'],
        app.state.ctx.store.one('SELECT blob FROM app_templates WHERE id=?', (template_id,))['blob']]
    for secret in secrets:
        assert all(secret not in response for response in public)
        assert all(secret.encode() not in blob for blob in encrypted)


def test_new_radius_profiles_resolve_per_site_for_enterprise_wlan(env):
    app, _ = env
    operator, approver = signed(app), signed(app, 'approver')
    job = plan_radius(operator, 'create', configuration('Site EAP Radius'), targets=TARGETS)
    run(operator, approver, job)
    ids = [next(v['id'] for v in radius_objects(operator, target) if v['name'] == 'Site EAP Radius')
           for target in TARGETS]
    assert ids[0] != ids[1]
    wifi_job = plan_enterprise(operator, 'Site EAP Radius', targets=TARGETS)
    result = run(operator, approver, wifi_job)
    for target in result['targets']:
        response = operator.get(f"/api/servers/{target['server']}/sites/{target['site']}/wifi/{target['object']}")
        assert response.status_code == 200, response.text
        expected_id = ids[0] if target['server'] == 'demo-01' else ids[1]
        assert response.json()['securityConfiguration']['radiusConfiguration']['profileId'] == expected_id


@pytest.mark.parametrize('security_type', ['WPA2_ENTERPRISE', 'WPA2_PERSONAL'])
def test_radius_deletion_rejects_enterprise_and_mac_radius_references(env, security_type):
    app, _ = env
    operator, approver = signed(app), signed(app, 'approver')
    run(operator, approver, plan_enterprise(operator))
    if security_type == 'WPA2_PERSONAL':
        # MAC authentication may reference RADIUS even on a Personal WLAN.
        wifi = next(v for v in operator.get('/api/servers/demo-01/sites/site-0001/wifi').json()
            if v['name'] == 'RADIUS-EAP-Test')
        def use_mac_radius(value):
            radius = value['securityConfiguration']['radiusConfiguration']
            radius['macAuthenticationConfiguration'] = {'macAddressFormat': 'COLON_SEPARATED', 'passwordSource': 'MAC_ADDRESS'}
            value['securityConfiguration'] = {'type': 'WPA2_PERSONAL', 'passphrase': 'mac-radius-test-key',
                'radiusConfiguration': radius}
        mutate_simulated(app.state.ctx, wifi['id'], use_mac_radius, kind='wifi')
    job = plan_radius(operator, 'delete', {})
    result = wait_job(operator, job, ('planning_failed',))
    assert result['counts']['planning_failed'] == 1
    assert 'verwendet' in result['targets'][0]['error']


def test_radius_references_created_after_approval_block_delete(env, monkeypatch):
    app, _ = env
    operator, approver = signed(app), signed(app, 'approver')
    job = plan_radius(operator, 'delete', {})
    wait_job(operator, job)
    run(operator, approver, plan_enterprise(operator))
    original = app.state.ctx.request
    writes = []
    async def capture(server, method, path, payload=None):
        if method == 'DELETE' and '/radius/configurations/' in path:
            writes.append(path)
        return await original(server, method, path, payload)
    monkeypatch.setattr(app.state.ctx, 'request', capture)
    assert approver.post(f'/api/jobs/{job}/approve').status_code == 200
    assert operator.post(f'/api/jobs/{job}/execute').status_code == 200
    result = wait_job(operator, job, ('stopped',))
    assert result['counts'].get('conflict') == 1 and not writes


def test_radius_reference_added_during_reauthorization_blocks_delete(env, monkeypatch):
    app, _ = env
    operator, approver = signed(app), signed(app, 'approver')
    profile_id = next(v['id'] for v in radius_objects(operator) if v['name'] == DEFAULT_NAME)
    wifi_id = operator.get('/api/servers/demo-01/sites/site-0001/wifi').json()[0]['id']
    job = plan_radius(operator, 'delete', {})
    wait_job(operator, job)
    original_request, original_reauth = app.state.ctx.request, app.state.ctx.auth.reauthorize
    armed, writes = False, []
    async def capture(server, method, path, payload=None):
        nonlocal armed
        result = await original_request(server, method, path, payload)
        if method == 'GET' and '/radius/configurations/' in path:
            armed = True
        if method == 'DELETE':
            writes.append(path)
        return result
    async def add_reference(name):
        result = await original_reauth(name)
        if armed and name == 'operator':
            def attach(value):
                value['securityConfiguration']['radiusConfiguration'] = {
                    'profileId': profile_id, 'nasId': {'type': 'DERIVED', 'source': 'DEVICE_MAC_ADDRESS'}}
            mutate_simulated(app.state.ctx, wifi_id, attach, kind='wifi')
        return result
    monkeypatch.setattr(app.state.ctx, 'request', capture)
    monkeypatch.setattr(app.state.ctx.auth, 'reauthorize', add_reference)
    assert approver.post(f'/api/jobs/{job}/approve').status_code == 200
    assert operator.post(f'/api/jobs/{job}/execute').status_code == 200
    result = wait_job(operator, job, ('stopped',))
    assert not writes and result['counts'].get('conflict') == 1


@pytest.mark.parametrize('origin', ['SYSTEM_DEFINED', 'ORCHESTRATED', None])
@pytest.mark.parametrize('operation', ['update', 'delete'])
def test_builtin_or_unknown_radius_profiles_are_protected(env, origin, operation):
    app, _ = env
    operator = signed(app)
    profile = next(v for v in radius_objects(operator) if v['name'] == DEFAULT_NAME)
    mutate_simulated(app.state.ctx, profile['id'], lambda value: value.update({'metadata': {'origin': origin}}))
    job = plan_radius(operator, operation, {} if operation == 'delete' else {'name': 'Unsafe rename'})
    result = wait_job(operator, job, ('planning_failed',))
    assert result['counts']['planning_failed'] == 1
    assert 'geschützt' in result['targets'][0]['error']


@pytest.mark.parametrize('operation', ['update', 'update_with_fresh_secret', 'delete'])
def test_masked_original_radius_secrets_fail_closed(env, operation):
    app, _ = env
    operator = signed(app)
    profile = next(v for v in radius_objects(operator) if v['name'] == DEFAULT_NAME)
    def mask(value):
        value['authenticationServers'][0]['sharedSecret'] = '********'
    mutate_simulated(app.state.ctx, profile['id'], mask)
    patch = {} if operation == 'delete' else {'vlanAssignmentMode': 'required'}
    if operation == 'update_with_fresh_secret':
        patch['authenticationServers'] = [{'host': '10.20.0.10', 'port': 1812, 'sharedSecret': 'fresh-radius-secret-2026'}]
        operation = 'update'
    job = plan_radius(operator, operation, patch)
    result = wait_job(operator, job, ('planning_failed',))
    assert result['counts']['planning_failed'] == 1
    assert 'maskierte' in result['targets'][0]['error']


def test_unrecognized_radius_configuration_is_never_discarded(env):
    app, _ = env
    operator = signed(app)
    profile = next(v for v in radius_objects(operator) if v['name'] == DEFAULT_NAME)
    mutate_simulated(app.state.ctx, profile['id'], lambda value: value.update({'newRadSecTransport': {'enabled': True}}))
    job = plan_radius(operator)
    result = wait_job(operator, job, ('planning_failed',))
    assert result['counts']['planning_failed'] == 1
    assert 'unbekannte' in result['targets'][0]['error']


def test_radius_scope_and_second_person_approval(env):
    app, _ = env
    admin = signed(app, 'admin')
    response = admin.post('/api/users', json={'name': 'radius-limited', 'password': 'radius-limited-password-2026',
        'role': 'operator', 'scope': ['demo-01']})
    assert response.status_code == 200, response.text
    limited = signed(app, 'radius-limited', 'radius-limited-password-2026')
    assert limited.get('/api/servers/demo-02/sites/site-0101/radius').status_code == 403
    response = limited.post('/api/jobs', json={'kind': 'radius', 'targets': [TARGETS[1]],
        'selector': {'name': DEFAULT_NAME}, 'patch': {'vlanAssignmentMode': 'required'},
        'reason': 'CHG-RADIUS außerhalb des Serverzugriffs'})
    assert response.status_code == 403, response.text
    job = plan_radius(admin)
    wait_job(admin, job)
    assert admin.post(f'/api/jobs/{job}/approve').status_code == 409


def test_radius_drift_and_server_fingerprint_block_writes(env, monkeypatch):
    app, _ = env
    operator, approver, admin = signed(app), signed(app, 'approver'), signed(app, 'admin')
    job = plan_radius(operator)
    preview = wait_job(operator, job)
    mutate_simulated(app.state.ctx, preview['targets'][0]['object'], lambda value: value.update({'name': 'External rename'}))
    original, writes = app.state.ctx.request, []
    async def capture(server, method, path, payload=None):
        if method in ('POST', 'PUT', 'DELETE'):
            writes.append(path)
        return await original(server, method, path, payload)
    monkeypatch.setattr(app.state.ctx, 'request', capture)
    assert approver.post(f'/api/jobs/{job}/approve').status_code == 200
    assert operator.post(f'/api/jobs/{job}/execute').status_code == 200
    assert wait_job(operator, job, ('stopped',))['counts']['conflict'] == 1
    assert not writes

    changed = plan_radius(operator, name='External rename')
    wait_job(operator, changed)
    assert approver.post(f'/api/jobs/{changed}/approve').status_code == 200
    assert admin.patch('/api/servers/demo-01', json={'name': 'Changed radius server'}).status_code == 200
    assert operator.post(f'/api/jobs/{changed}/execute').status_code == 200
    result = wait_job(operator, changed, ('stopped',))
    assert result['counts']['pending'] == 1 and result['error']
    assert not writes


def test_radius_permission_revalidation_blocks_directory_account_revocation(env, monkeypatch):
    app, _ = env
    operator, approver = signed(app), signed(app, 'approver')
    job = plan_radius(operator)
    wait_job(operator, job)
    original, writes = app.state.ctx.request, []
    async def capture(server, method, path, payload=None):
        if method in ('POST', 'PUT', 'DELETE'):
            writes.append(path)
        return await original(server, method, path, payload)
    original_reauth = app.state.ctx.auth.reauthorize
    async def revoked(name):
        # The LDAP authorizer returns no identity after account/group revocation.
        return None if name == 'approver' else await original_reauth(name)
    monkeypatch.setattr(app.state.ctx, 'request', capture)
    monkeypatch.setattr(app.state.ctx.auth, 'reauthorize', revoked)
    assert approver.post(f'/api/jobs/{job}/approve').status_code == 200
    assert operator.post(f'/api/jobs/{job}/execute').status_code == 200
    result = wait_job(operator, job, ('stopped',))
    assert not writes and result['counts']['pending'] == 1


def test_radius_site_reference_change_invalidates_approved_job(env, monkeypatch):
    app, _ = env
    operator, approver = signed(app), signed(app, 'approver')
    job = plan_radius(operator)
    wait_job(operator, job)
    assert approver.post(f'/api/jobs/{job}/approve').status_code == 200
    app.state.ctx.store.execute('UPDATE app_sites SET internal_reference=? WHERE server=? AND site=?',
        ('different-local-site', 'demo-01', 'site-0001'))
    original, writes = app.state.ctx.request, []
    async def capture(server, method, path, payload=None):
        if method in ('POST', 'PUT', 'DELETE'):
            writes.append(path)
        return await original(server, method, path, payload)
    monkeypatch.setattr(app.state.ctx, 'request', capture)
    assert operator.post(f'/api/jobs/{job}/execute').status_code == 200
    result = wait_job(operator, job, ('stopped',))
    assert not writes and result['counts']['pending'] == 1
    assert 'Site-Verweis' in result['error']


@pytest.mark.parametrize('change', ['changed', 'missing', 'ambiguous'])
def test_external_radius_site_mapping_is_verified_before_write(env, monkeypatch, change):
    app, _ = env
    operator, approver = signed(app), signed(app, 'approver')
    job = plan_radius(operator)
    wait_job(operator, job)
    assert approver.post(f'/api/jobs/{job}/approve').status_code == 200
    original_sites = app.state.ctx.client._sites
    def changed_controller_sites(server_id):
        sites = original_sites(server_id)
        if server_id == 'demo-01':
            if change == 'changed':
                sites[0]['internalReference'] = 'new-controller-site'
            elif change == 'missing':
                sites.pop(0)
            else:
                sites[1]['internalReference'] = sites[0]['internalReference']
        return sites
    original_request, writes = app.state.ctx.request, []
    async def capture(server, method, path, payload=None):
        if method in ('POST', 'PUT', 'DELETE'):
            writes.append(path)
        return await original_request(server, method, path, payload)
    monkeypatch.setattr(app.state.ctx.client, '_sites', changed_controller_sites)
    monkeypatch.setattr(app.state.ctx, 'request', capture)
    assert operator.post(f'/api/jobs/{job}/execute').status_code == 200
    result = wait_job(operator, job, ('stopped',))
    assert not writes and result['counts']['pending'] == 1 and result['error']


def test_radius_write_timeout_is_uncertain_and_never_retried(env, monkeypatch):
    app, _ = env
    operator, approver = signed(app), signed(app, 'approver')
    job = plan_radius(operator)
    wait_job(operator, job)
    original, writes = app.state.ctx.request, []
    async def timeout_after_write(server, method, path, payload=None):
        result = await original(server, method, path, payload)
        if method == 'PUT' and '/radius/configurations/' in path:
            writes.append(path)
            raise HTTPException(502, 'Verbindung nach Schreibzugriff unterbrochen')
        return result
    monkeypatch.setattr(app.state.ctx, 'request', timeout_after_write)
    assert approver.post(f'/api/jobs/{job}/approve').status_code == 200
    assert operator.post(f'/api/jobs/{job}/execute').status_code == 200
    result = wait_job(operator, job, ('stopped',))
    assert len(writes) == 1 and result['counts']['uncertain'] == 1
    assert operator.post(f'/api/jobs/{job}/retry').status_code == 409
    assert operator.post(f'/api/jobs/{job}/rollback').status_code == 409
