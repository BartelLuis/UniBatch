"""Exercise RADIUS configuration in a DEMO_MODE GUI without real controllers.

Run with UNIFI_BROWSER_URL=http://localhost:8090 for the Docker demo.
"""
import os
import time
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


url = os.environ.get('UNIFI_BROWSER_URL', 'http://localhost:8080')
run_id = str(time.time_ns())
artifacts = Path('artifacts')
artifacts.mkdir(exist_ok=True)
profile_name = 'RADIUS Browser ' + run_id
secret_auth = 'browser-radius-auth-' + run_id
secret_acct = 'browser-radius-acct-' + run_id


with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page(viewport={'width': 1540, 'height': 1040})
    errors, writes = [], []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.on('request', lambda request: writes.append(request.url)
            if request.method == 'DELETE' else None)

    def native_dialog(dialog):
        errors.append('Unexpected native browser dialog: ' + dialog.type)
        dialog.dismiss()

    page.on('dialog', native_dialog)
    page.goto(url)

    def login(name, password):
        page.locator('#username').fill(name)
        page.locator('#password').fill(password)
        page.locator('#login-form button').click()
        expect(page.locator('#authenticated')).to_be_visible()
        expect(page.locator('#dashboard')).to_have_attribute('aria-busy', 'false')
        assert page.request.get(url + '/api/me').json()['demo'] is True, 'Use the simulator only'

    def logout():
        page.locator('#logout').click()
        expect(page.locator('#login-view')).to_be_visible()

    def show(view):
        page.locator(f'nav [data-view="{view}"]').click()
        expect(page.locator('#' + view)).to_be_visible()
        expect(page.locator('#' + view)).to_have_attribute('aria-busy', 'false')

    def confirm_modal():
        modal = page.locator('dialog.app-dialog[open]')
        expect(modal).to_be_visible()
        modal.locator('.dialog-actions button[type="submit"]').click()
        expect(page.locator('dialog.app-dialog[open]')).to_have_count(0)

    def select_two_sites():
        page.locator('#clear-selection').click()
        for server in ('demo-01', 'demo-02'):
            page.locator('#site-server').select_option(server)
            page.locator('#site-search').fill('')
            page.locator('#site-search-form').get_by_role('button', name='Suchen').click()
            expect(page.locator('#site-pager')).to_contain_text('von 100')
            page.locator('#site-rows input[type="checkbox"]').first.check()
        expect(page.locator('#target-count')).to_have_text('2 ausgewählt')

    def radius_editor(operation):
        show('workspace')
        select_two_sites()
        page.locator('#kind').select_option('radius')
        page.locator('#operation').select_option(operation)
        page.locator('#template-select').select_option('')
        expect(page.locator('#wifi-fields')).to_be_hidden()
        expect(page.locator('#network-fields')).to_be_hidden()
        if operation == 'create':
            page.locator('#config-name').fill(profile_name)
        else:
            page.locator('#object-name').fill(profile_name)
        page.locator('#canary-count').fill('0')

    def create_preview(reason, state='Freigabe ausstehend'):
        page.locator('#reason').fill(reason)
        with page.expect_response(lambda response: response.url.endswith('/api/jobs') and response.request.method == 'POST') as response:
            page.locator('#create-plan').click()
        result = response.value.json()
        assert response.value.status == 200, result
        expect(page.locator('#job-detail .job-header .badge')).to_have_text(state, timeout=60000)
        assert secret_auth not in page.locator('#job-detail').text_content()
        assert secret_acct not in page.locator('#job-detail').text_content()
        return result['id']

    def approve_and_execute(job_id):
        logout()
        login('approver', 'demo-approver-2026')
        show('jobs')
        job_reason = page.request.get(url + '/api/jobs/' + job_id).json()['reason']
        page.locator('#job-rows tr').filter(has_text=job_reason).get_by_role('button', name='Details').click()
        page.locator('#job-detail').get_by_role('button', name='Geprüften Auftrag freigeben').click()
        expect(page.locator('#job-detail .job-header .badge')).to_have_text('Freigegeben')
        logout()
        login('operator', 'demo-operator-2026')
        show('jobs')
        page.locator('#job-rows tr').filter(has_text=job_reason).get_by_role('button', name='Details').click()
        page.locator('#job-detail').get_by_role('button', name='In Simulation ausführen').click()
        confirm_modal()
        expect(page.locator('#job-detail .job-header .badge')).to_have_text('Abgeschlossen', timeout=60000)
        expect(page.locator('#job-detail')).to_contain_text('2 Ziele')

    def profiles():
        values = []
        for server, site in [('demo-01', 'site-0001'), ('demo-02', 'site-0101')]:
            response = page.request.get(url + f'/api/servers/{server}/sites/{site}/radius')
            assert response.status == 200, response.text()
            assert secret_auth not in response.text() and secret_acct not in response.text()
            values.append(response.json())
        return values

    login('admin', 'admin-demo-2026')
    show('servers')
    page.locator('#server-reset').click()
    expect(page.locator('#server-radius-enabled')).to_be_visible()
    page.locator('#server-radius-enabled').check()
    page.locator('#server-radius-auth-mode').select_option('local_account')
    expect(page.locator('#server-radius-username')).to_be_visible()
    expect(page.locator('#server-radius-password')).to_be_visible()
    # This checks the explicit account controls, without storing a fake controller.
    show('workspace')
    radius_editor('create')
    auth_rows = page.locator('#radius-auth-servers .radius-endpoint')
    expect(auth_rows).to_have_count(1)
    auth_rows.first.locator('[data-field="host"]').fill('10.30.0.10')
    auth_rows.first.locator('[data-field="port"]').fill('1812')
    auth_rows.first.locator('[data-field="sharedSecret"]').fill(secret_auth)
    page.locator('#radius-auth-add').click()
    expect(auth_rows).to_have_count(2)
    auth_rows.nth(1).locator('[data-field="host"]').fill('10.30.0.11')
    auth_rows.nth(1).locator('[data-field="port"]').fill('2812')
    auth_rows.nth(1).locator('[data-field="sharedSecret"]').fill(secret_auth + '-backup')
    page.locator('#radius-accounting-enabled').select_option('true')
    acct_rows = page.locator('#radius-acct-servers .radius-endpoint')
    expect(acct_rows).to_have_count(1)
    acct_rows.first.locator('[data-field="host"]').fill('10.30.0.12')
    acct_rows.first.locator('[data-field="port"]').fill('1813')
    acct_rows.first.locator('[data-field="sharedSecret"]').fill(secret_acct)
    page.locator('#radius-interim-enabled').select_option('true')
    page.locator('#radius-accounting-interval').fill('600')
    page.locator('#radius-vlan-assignment').select_option('optional')
    page.screenshot(path=str(artifacts / 'radius-editor.png'), full_page=True)

    page.locator('#save-template').click()
    dialog = page.locator('dialog.app-dialog[open]')
    expect(dialog).to_be_visible()
    dialog.get_by_label('Vorlagenname', exact=True).fill('RADIUS Vorlage ' + run_id)
    dialog.locator('.dialog-actions .primary').click()
    expect(page.locator('#notice')).to_have_text('Vorlage gespeichert.')
    response = page.request.get(url + '/api/templates')
    assert secret_auth not in response.text() and secret_acct not in response.text()
    template_id = next(value['id'] for value in response.json() if value['name'] == 'RADIUS Vorlage ' + run_id)
    page.locator('#template-select').select_option(template_id)
    assert '<redacted>' in page.locator('#patch').input_value()
    assert secret_auth not in page.locator('#patch').input_value()

    created = create_preview('CHG-RADIUS-' + run_id + ' Authentifizierung und Accounting über zwei Sites')
    expect(page.locator('#job-detail')).to_contain_text('authenticationServers')
    expect(page.locator('#job-detail')).to_contain_text('accountingServers')
    page.screenshot(path=str(artifacts / 'radius-preview.png'), full_page=True)
    approve_and_execute(created)
    actual = [next(v for v in values if v['name'] == profile_name) for values in profiles()]
    assert actual[0]['id'] != actual[1]['id']
    assert all(len(v['authenticationServers']) == 2 and v['accountingEnabled'] for v in actual)
    assert all(v['authenticationServers'][0]['sharedSecret'] == '<redacted>' for v in actual)

    radius_editor('update')
    expect(page.locator('#radius-auth-replace')).not_to_be_checked()
    page.locator('#radius-vlan-assignment').select_option('required')
    updated = create_preview('CHG-RADIUS-UPDATE-' + run_id + ' Dynamische VLAN-Zuordnung aktivieren')
    approve_and_execute(updated)
    assert all(next(v for v in values if v['name'] == profile_name)['vlanAssignmentMode'] == 'required' for values in profiles())
    with page.expect_response(lambda response: response.url.endswith('/rollback') and response.request.method == 'POST') as response:
        page.locator('#job-detail').get_by_role('button', name='Rücknahme vorbereiten').click()
    rollback_id = response.value.json()['id']
    expect(page.locator('#job-detail .job-header .badge')).to_have_text('Freigabe ausstehend', timeout=60000)
    approve_and_execute(rollback_id)
    assert all(next(v for v in values if v['name'] == profile_name)['vlanAssignmentMode'] == 'optional' for values in profiles())

    radius_editor('delete')
    deleted = create_preview('CHG-RADIUS-DELETE-' + run_id + ' Unreferenziertes Profil entfernen')
    approve_and_execute(deleted)
    assert all(not any(v['name'] == profile_name for v in values) for values in profiles())
    with page.expect_response(lambda response: response.url.endswith('/rollback') and response.request.method == 'POST') as response:
        page.locator('#job-detail').get_by_role('button', name='Rücknahme vorbereiten').click()
    restore_id = response.value.json()['id']
    expect(page.locator('#job-detail .job-header .badge')).to_have_text('Freigabe ausstehend', timeout=60000)
    approve_and_execute(restore_id)

    show('workspace')
    select_two_sites()
    page.locator('#kind').select_option('wifi')
    page.locator('#operation').select_option('create')
    page.locator('#template-select').select_option('')
    page.locator('#config-name').fill('EAP-' + run_id[-14:])
    page.locator('#wifi-security').select_option('WPA2_ENTERPRISE')
    page.locator('#wifi-radius-name').fill(profile_name)
    page.locator('#wifi-network-name').fill('Verwaltungsnetz')
    page.locator('#canary-count').fill('0')
    enterprise = create_preview('CHG-RADIUS-EAP-' + run_id + ' Enterprise-WLAN mit wiederhergestelltem Profil')
    approve_and_execute(enterprise)
    radius_editor('delete')
    before_writes = len(writes)
    create_preview('CHG-RADIUS-GUARD-' + run_id + ' Verwendetes Profil muss geschützt bleiben', 'Planung fehlgeschlagen')
    expect(page.locator('#job-detail')).to_contain_text('verwendet')
    assert len(writes) == before_writes
    page.screenshot(path=str(artifacts / 'radius-reference-guard.png'), full_page=True)
    assert not errors, errors
    browser.close()
    print('RADIUS browser smoke passed: explicit server authentication controls, two-site profile CRUD, '
          'authentication/accounting endpoints, encrypted templates and masked secrets, second-person approval, '
          'update and deletion rollback, Enterprise WLAN assignment, and reference protection.')
