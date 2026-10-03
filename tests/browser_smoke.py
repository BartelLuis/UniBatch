"""Exercise the local simulator through the real GUI.

Use only a DEMO_MODE server. Run: .venv/Scripts/python tests/browser_smoke.py
Optional: UNIFI_BROWSER_URL=http://localhost:8090 for the Docker demo.
"""
import os
import json
import time
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

url = os.environ.get('UNIFI_BROWSER_URL', 'http://localhost:8080')
run_id = str(int(time.time()))
artifacts = Path('artifacts')
artifacts.mkdir(exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={'width': 1540, 'height': 1040}, reduced_motion='reduce')
    errors = []
    requests = []
    template_writes = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.on('request', lambda request: requests.append(request.url))
    page.on('request', lambda request: template_writes.append(request.post_data)
            if request.method == 'POST' and request.url.endswith('/api/templates') else None)

    def reject_native_dialog(dialog):
        errors.append('Unexpected native browser dialog: ' + dialog.type)
        dialog.dismiss()

    page.on('dialog', reject_native_dialog)
    page.goto(url)

    def capture(name):
        page.evaluate('window.scrollTo(0, 0)')
        page.screenshot(path=str(artifacts / name), full_page=True, animations='disabled')

    def login(name, password):
        page.locator('#username').fill(name)
        page.locator('#password').fill(password)
        page.locator('#login-form button').click()
        expect(page.locator('#authenticated')).to_be_visible()
        expect(page.locator('#dashboard')).to_be_visible()

    def logout():
        page.locator('#logout').click()
        expect(page.locator('#login-view')).to_be_visible()

    def show(name):
        page.locator(f'nav [data-view="{name}"]').click()
        expect(page.locator(f'#{name}')).to_be_visible()
        expect(page.locator(f'#{name}')).to_have_attribute('aria-busy', 'false')
        expect(page.locator(f'nav [data-view="{name}"]')).to_have_attribute('aria-current', 'page')
        expect(page.locator('nav [aria-current="page"]')).to_have_count(1)

    def confirm_modal():
        modal = page.locator('dialog.app-dialog[open]')
        expect(modal).to_be_visible()
        modal.locator('.dialog-actions button[type="submit"]').click()
        expect(page.locator('dialog.app-dialog[open]')).to_have_count(0)

    def cancel_job():
        page.locator('#job-detail').get_by_role('button', name='Auftrag abbrechen').click()
        confirm_modal()
        expect(page.locator('#job-detail .job-header .badge')).to_have_text('Abgebrochen')

    login('admin', 'admin-demo-2026')
    expect(page.locator('#mode')).to_contain_text('SIMULATION')
    expect(page.locator('#metric-servers')).to_have_text('12')
    expect(page.locator('#metric-sites')).to_have_text('1.200')
    expect(page.locator('#metric-servers-note')).to_have_text('12 verbunden · 12 aktiv')
    expect(page.locator('#connection-summary')).to_have_text('12 / 12 Server verbunden')
    expect(page.locator('nav [data-view="dashboard"]')).to_have_attribute('aria-current', 'page')
    capture('desktop.png')

    show('workspace')
    expect(page.locator('#site-rows tr')).to_have_count(50)
    before = len(requests)
    page.locator('#select-matching').click()
    expect(page.locator('#target-count')).to_have_text('1.200 ausgewählt')
    bulk_requests = requests[before:]
    assert len([r for r in bulk_requests if '/api/inventory?' in r]) == 12
    assert not any('/sites/' in r for r in bulk_requests), bulk_requests
    assert page.locator('#site-rows tr').count() == 50
    page.locator('#clear-selection').click()
    page.locator('#site-rows input[type="checkbox"]').first.check()
    page.locator('#site-pager').get_by_role('button', name='Weiter').click()
    expect(page.locator('#site-pager')).to_contain_text('51–100')
    page.locator('#site-rows input[type="checkbox"]').first.check()
    expect(page.locator('#target-count')).to_have_text('2 ausgewählt')
    page.locator('#site-rows input[type="checkbox"]').first.uncheck()
    page.locator('#site-server').select_option('demo-12')
    page.locator('#site-search-form').get_by_role('button', name='Suchen').click()
    expect(page.locator('#site-pager')).to_contain_text('von 100')
    expect(page.locator('#target-count')).to_have_text('1 ausgewählt')
    page.locator('#site-rows input[type="checkbox"]').first.check()
    expect(page.locator('#target-count')).to_have_text('2 ausgewählt')
    page.locator('#site-rows').get_by_role('button', name='Ansehen').first.click()
    expect(page.locator('#site-inspector')).to_contain_text('Verwaltung')
    page.locator('#object-name').fill('Verwaltung')
    wlan = page.locator('#site-inspector details').filter(has=page.locator('summary', has_text='Verwaltung')).first
    hidden = 'false' if '"hideName": true' in wlan.text_content() else 'true'
    page.locator('#wifi-hidden').select_option(hidden)
    page.locator('#wifi-passphrase').fill('browser-rollout-' + run_id)
    page.locator('#canary-count').fill('1')
    page.locator('#reason').fill('CHG-BROWSER-' + run_id + ' WLAN über zwei Sites ausrollen')
    page.locator('#create-plan').click()
    expect(page.locator('#jobs')).to_be_visible()
    expect(page.locator('#job-detail .job-header .badge')).to_have_text('Freigabe ausstehend', timeout=60000)
    page.locator('#job-detail summary').first.click()
    expect(page.locator('#job-detail')).to_contain_text('hideName')
    capture('jobs.png')

    show('workspace')
    page.locator('#wifi-passphrase').fill('browser-wlan-secret-2026')
    before_templates = len(template_writes)
    page.locator('#save-template').click()
    dialog = page.locator('dialog.app-dialog[open]')
    expect(dialog).to_be_visible()
    title_id = dialog.get_attribute('aria-labelledby')
    description_id = dialog.get_attribute('aria-describedby')
    assert title_id and description_id, 'Dialog has no accessible title or description'
    expect(page.locator('#' + title_id)).to_be_visible()
    expect(page.locator('#' + description_id)).to_be_visible()
    dialog.get_by_label('Vorlagenname', exact=True).fill('Escape-Vorlage-' + run_id)
    page.keyboard.press('Escape')
    expect(page.locator('dialog.app-dialog[open]')).to_have_count(0)
    expect(page.locator('#save-template')).to_be_enabled()
    expect(page.locator('#save-template')).to_be_focused()
    assert len(template_writes) == before_templates

    page.locator('#save-template').click()
    dialog = page.locator('dialog.app-dialog[open]')
    expect(dialog).to_be_visible()
    dialog.get_by_label('Vorlagenname', exact=True).fill('Abbruch-Vorlage-' + run_id)
    dialog.get_by_role('button', name='Abbrechen', exact=True).click()
    expect(page.locator('dialog.app-dialog[open]')).to_have_count(0)
    expect(page.locator('#save-template')).to_be_focused()
    assert len(template_writes) == before_templates

    template_name = 'Browser-Vorlage-' + run_id + ' <b>Team</b>'
    page.locator('#save-template').click()
    dialog = page.locator('dialog.app-dialog[open]')
    expect(dialog).to_be_visible()
    dialog.get_by_label('Vorlagenname', exact=True).fill(template_name)
    dialog.locator('.dialog-actions .primary').click()
    expect(page.locator('#notice')).to_have_text('Vorlage gespeichert.')
    assert len(template_writes) == before_templates + 1
    show('templates')
    template_card = page.locator('#template-list article').filter(has=page.locator('h2', has_text=template_name))
    expect(template_card.locator('h2')).to_have_text(template_name)
    assert template_card.locator('h2 b').count() == 0, 'Template name was interpreted as HTML'
    show('workspace')
    page.locator('#template-select').select_option(label=template_name + ' · WLAN')
    assert 'browser-wlan-secret-2026' not in page.locator('#patch').input_value()
    assert '<redacted>' in page.locator('#patch').input_value()
    page.locator('#wifi-network-name').fill('Verwaltungsnetz')
    page.locator('#reason').fill('CHG-TEMPLATE-' + run_id + ' Vorlage mit sitebezogener VLAN-Zuordnung')
    with page.expect_request(lambda request: request.url.endswith('/api/jobs') and request.method == 'POST') as planned:
        page.locator('#create-plan').click()
    body = json.loads(planned.value.post_data)
    assert body['template_id'] and body['patch'] == {}, body
    assert body['network_selector'] == 'Verwaltungsnetz', body
    expect(page.locator('#job-detail .job-header .badge')).to_have_text('Freigabe ausstehend', timeout=60000)
    cancel_job()

    for security in ['WPA2_ENTERPRISE', 'WPA2_WPA3_ENTERPRISE', 'WPA3_ENTERPRISE']:
        show('workspace')
        page.locator('#kind').select_option('wifi')
        page.locator('#operation').select_option('create')
        page.locator('#config-name').fill('EAP-' + run_id)
        page.locator('#wifi-security').select_option(security)
        expect(page.locator('#wifi-passphrase-label')).to_be_hidden()
        page.locator('#wifi-radius-name').fill('Behörden-RADIUS')
        page.locator('#wifi-network-name').fill('Verwaltungsnetz')
        page.locator('#reason').fill('CHG-EAP-' + run_id + ' ' + security + ' mit lokalem RADIUS-Profil')
        page.locator('#create-plan').click()
        expect(page.locator('#job-detail .job-header .badge')).to_have_text('Freigabe ausstehend', timeout=60000)
        expect(page.locator('#job-detail')).to_contain_text('DEVICE_MAC_ADDRESS')
        expect(page.locator('#job-detail')).to_contain_text(security)
        cancel_job()

    show('workspace')
    page.locator('#kind').select_option('network')
    page.locator('#operation').select_option('create')
    page.locator('#config-name').fill('Browser-VLAN-' + run_id)
    page.locator('#vlan-id').fill('310')
    page.locator('#reason').fill('CHG-VLAN-' + run_id + ' VLAN ohne Gateway-Konfiguration erstellen')
    page.locator('#create-plan').click()
    expect(page.locator('#job-detail .job-header .badge')).to_have_text('Freigabe ausstehend', timeout=60000)
    expect(page.locator('#job-detail')).to_contain_text('vlanId')
    expect(page.locator('#job-detail')).to_contain_text('UNMANAGED')
    cancel_job()

    show('identity')
    expect(page.locator('#role-form')).to_be_hidden()
    expect(page.locator('#user-form')).to_be_hidden()
    page.locator('#role-reset').click()
    page.locator('#role-id').fill('browser-' + run_id)
    page.locator('#role-name').fill('Browser Leserechte')
    page.locator('#role-permissions input[value="view"]').check()
    page.locator('#role-form').get_by_role('button', name='Rolle speichern').click()
    expect(page.locator('#notice')).to_have_text('Rolle gespeichert.')
    page.locator('#user-reset').click()
    page.locator('#user-name').fill('browser-' + run_id)
    page.locator('#user-password').fill('browser-test-password-2026')
    page.locator('#user-role').select_option('browser-' + run_id)
    page.locator('#user-scope-all').uncheck()
    page.locator('#user-scope input[value="demo-12"]').check()
    page.locator('#user-form').get_by_role('button', name='Konto speichern').click()
    expect(page.locator('#notice')).to_have_text('Benutzerkonto gespeichert.')
    expect(page.locator('#user-rows')).to_contain_text('browser-' + run_id)
    capture('users.png')
    show('directory')
    assert page.locator('#directory-groups input').count() >= 5
    show('servers')
    expect(page.locator('#server-list .server-card')).to_have_count(12)
    capture('servers.png')
    logout()

    login('browser-' + run_id, 'browser-test-password-2026')
    expect(page.locator('#metric-servers')).to_have_text('1')
    expect(page.locator('#metric-servers-note')).to_have_text('1 verbunden · 1 aktiv')
    expect(page.locator('#connection-summary')).to_have_text('1 / 1 Server verbunden')
    expect(page.locator('nav [data-view="identity"]')).to_be_hidden()
    show('workspace')
    expect(page.locator('#create-plan')).to_be_hidden()
    expect(page.locator('#site-pager')).to_contain_text('von 100')
    logout()

    login('approver', 'demo-approver-2026')
    show('jobs')
    page.locator('#job-rows tr').filter(has_text='CHG-BROWSER-' + run_id).get_by_role('button', name='Details').click()
    page.locator('#job-detail').get_by_role('button', name='Geprüften Auftrag freigeben').click()
    expect(page.locator('#job-detail .job-header .badge')).to_have_text('Freigegeben')
    logout()

    login('operator', 'demo-operator-2026')
    show('jobs')
    page.locator('#job-rows tr').filter(has_text='CHG-BROWSER-' + run_id).get_by_role('button', name='Details').click()
    page.locator('#job-detail').get_by_role('button', name='In Simulation ausführen').click()
    confirm_modal()
    expect(page.locator('#job-detail .job-header .badge')).to_have_text('Canary-Prüfung', timeout=60000)
    page.locator('#job-detail').get_by_role('button', name='Rollout fortsetzen').click()
    expect(page.locator('#job-detail .job-header .badge')).to_have_text('Abgeschlossen', timeout=60000)
    expect(page.locator('#job-detail')).to_contain_text('2 Ziele')
    expect(page.locator('#job-detail')).to_contain_text('Angewendet:')
    page.locator('#job-detail').get_by_role('button', name='Rücknahme vorbereiten').click()
    expect(page.locator('#job-detail .job-header .badge')).to_have_text('Freigabe ausstehend', timeout=60000)
    expect(page.locator('#notice')).to_contain_text('Erneute Freigabe')
    logout()
    login('admin', 'admin-demo-2026')
    show('audit')
    expect(page.locator('#audit-rows tr').first).to_be_visible()
    page.set_viewport_size({'width': 390, 'height': 844})
    page.locator('#mobile-menu-toggle').click()
    expect(page.locator('#mobile-menu-toggle')).to_have_attribute('aria-expanded', 'true')
    expect(page.locator('#app-sidebar')).to_be_visible()
    page.locator('nav [data-view="account"]').focus()
    page.keyboard.press('Tab')
    expect(page.locator('#app-sidebar a.brand')).to_be_focused()
    page.keyboard.press('Shift+Tab')
    expect(page.locator('nav [data-view="account"]')).to_be_focused()
    capture('mobile-navigation.png')
    show('dashboard')
    expect(page.locator('#mobile-menu-toggle')).to_have_attribute('aria-expanded', 'false')
    capture('mobile.png')
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), 'Mobile viewport overflows'
    page.locator('#mobile-menu-toggle').click()
    show('workspace')
    expect(page.locator('#site-rows tr')).to_have_count(50)
    assert page.locator('#site-rows').evaluate('node => node.closest("table").getBoundingClientRect().width >= 520')
    capture('mobile-workspace.png')
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), 'Mobile site table overflows the page'
    assert not errors, errors
    browser.close()
    print('Browser smoke passed: 12 servers / 1200 sites, bounded rendering, persistent selection, WLAN/VLAN and WPA2/WPA3 Enterprise previews, secret-safe templates and per-site VLAN/RADIUS mapping, accessible dialogs, cancellation and focus restore, escaped template labels, custom roles, scoped users, LDAP GUI, second-person approval, canary/resume rollout, rollback preview, audit, mobile drawer and navigation state.')
