import time

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.settings import Settings

ORIGIN = {'Origin':'http://testserver'}


@pytest.fixture
def env(tmp_path):
    app=create_app(Settings(demo=True,origin='http://testserver',data_dir=tmp_path))
    with TestClient(app) as lifecycle:
        yield app, lifecycle


def signed(app,name='operator',password=None):
    client=TestClient(app)
    response=client.post('/api/login',headers=ORIGIN,json={'name':name,'password':password or ('admin-demo-2026' if name=='admin' else f'demo-{name}-2026')})
    assert response.status_code==200,response.text
    client.headers.update(ORIGIN|{'X-CSRF-Token':response.json()['csrf']})
    return client


def wait_job(client,job_id,states=('planned',),timeout=30):
    started=time.monotonic()
    while time.monotonic()-started<timeout:
        response=client.get('/api/jobs/'+job_id)
        assert response.status_code==200,response.text
        result=response.json()
        if result['state'] in states:
            return result
        if result['state'] in ('planning_failed','stopped','interrupted','cancelled') and result['state'] not in states:
            pytest.fail(str(result))
        time.sleep(.02)
    pytest.fail(f'Timed out waiting for {job_id}: state={result["state"]}, counts={result["counts"]}')


def plan(client,kind='wifi',operation='update',targets=None,patch=None,**options):
    body={'kind':kind,'operation':operation,'targets':targets or [{'server':'demo-01','site':'site-0001'}],
          'patch':patch if patch is not None else {'hideName':True},'reason':'CHG-12345 kontrollierter Test',
          'selector':{'name':'Verwaltung' if kind=='wifi' else 'Verwaltungsnetz'}}|options
    response=client.post('/api/jobs',json=body)
    assert response.status_code==200,response.text
    return response.json()['id']


def run(operator,approver,job):
    wait_job(operator,job)
    response=approver.post(f'/api/jobs/{job}/approve')
    assert response.status_code==200,response.text
    response=operator.post(f'/api/jobs/{job}/execute',json={})
    assert response.status_code==200,response.text
    return wait_job(operator,job,('completed',))


def test_inventory_search_pagination_and_tags(env):
    app,_=env;client=signed(app)
    assert client.get('/api/stats').json()['sites']==1200
    response=client.get('/api/inventory?limit=25&offset=100').json()
    assert response['total']==1200 and len(response['items'])==25
    assert response['items'][0]['site']=='site-0101'
    assert client.get('/api/inventory?search=Standort%200001').json()['total']==1
    assert client.get('/api/inventory?server=demo-01').json()['total']==100
    assert client.patch('/api/inventory/demo-01/site-0001',json={'tags':['Pilot','Berlin']}).status_code==200
    assert client.get('/api/inventory?tag=Pilot').json()['total']==1


def test_four_eyes_immutable_job_and_repeat_protection(env):
    app,_=env;operator=signed(app);approver=signed(app,'approver');admin=signed(app,'admin')
    job=plan(operator)
    wait_job(operator,job)
    assert operator.post(f'/api/jobs/{job}/approve').status_code==403
    assert operator.post(f'/api/jobs/{job}/execute').status_code==409
    assert admin.post(f'/api/jobs/{job}/approve').status_code==200
    assert approver.post(f'/api/jobs/{job}/execute').status_code==403
    assert operator.post(f'/api/jobs/{job}/execute').status_code==200
    result=wait_job(operator,job,('completed',))
    assert result['counts']['applied']==1
    assert operator.post(f'/api/jobs/{job}/execute').status_code==409
    own=plan(admin,patch={'hideName':False})
    wait_job(admin,own)
    assert admin.post(f'/api/jobs/{own}/approve').status_code==409


def test_1200_site_batch_canary_and_resume(env):
    app,_=env;operator=signed(app);approver=signed(app,'approver')
    targets=[]
    for offset in range(0,1200,200):
        targets.extend({k:site[k] for k in ('server','site')} for site in operator.get('/api/inventory?limit=200&offset='+str(offset)).json()['items'])
    started=time.monotonic()
    job=plan(operator,targets=targets,canary_count=3,concurrency=6)
    preview=wait_job(operator,job,timeout=45)
    assert preview['total_targets']==1200 and len(preview['targets'])==100
    assert preview['counts']['pending']==1200
    approver.post(f'/api/jobs/{job}/approve')
    operator.post(f'/api/jobs/{job}/execute')
    pilot=wait_job(operator,job,('paused',),timeout=45)
    assert pilot['counts']['applied']==3
    assert operator.post(f'/api/jobs/{job}/resume').status_code==200
    # Verify completion of durable writes; the deadline is not a performance SLA.
    # Windows disk contention during builds can exceed the former 45s window.
    result=wait_job(operator,job,('completed',),timeout=90)
    assert result['counts']['applied']==1200
    assert operator.get(f'/api/jobs/{job}?offset=1100&limit=100').json()['targets'][0]['idx']==1100
    elapsed=time.monotonic()-started
    print(f'1200-site simulated plan + pilot + rollout: {elapsed:.2f}s')


def test_vlan_create_update_delete_and_rollback(env):
    app,_=env;op=signed(app);approval=signed(app,'approver')
    created=plan(op,'network','create',patch={'name':'Test-VLAN','vlanId':220})
    result=run(op,approval,created)
    object_id=result['targets'][0]['object']
    updated=plan(op,'network',patch={'vlanId':221},selector={'name':'Test-VLAN'})
    run(op,approval,updated)
    restored=op.post(f'/api/jobs/{updated}/rollback')
    assert restored.status_code==200,restored.text
    run(op,approval,restored.json()['id'])
    objects=op.get('/api/servers/demo-01/sites/site-0001/network').json()
    assert next(v for v in objects if v['id']==object_id)['vlanId']==220
    deleted=plan(op,'network','delete',patch={},selector={'name':'Test-VLAN'})
    run(op,approval,deleted)
    assert not any(v['name']=='Test-VLAN' for v in op.get('/api/servers/demo-01/sites/site-0001/network').json())
    restore_delete=op.post(f'/api/jobs/{deleted}/rollback').json()['id']
    run(op,approval,restore_delete)
    assert any(v['name']=='Test-VLAN' for v in op.get('/api/servers/demo-01/sites/site-0001/network').json())


def test_wifi_template_secrets_and_per_site_vlan_resolution(env):
    app,_=env;op=signed(app);approval=signed(app,'approver')
    secret='Very-secret-wifi-password-2026'
    data={'name':'WLAN Vorlage','kind':'wifi','operation':'create','patch':{'name':'Test-SSID','securityConfiguration':{'type':'WPA2_PERSONAL','passphrase':secret}}}
    template=op.post('/api/templates',json=data)
    assert template.status_code==200,template.text
    template_id=template.json()['id']
    assert secret not in op.get('/api/templates').text
    targets=[{'server':'demo-01','site':'site-0001'},{'server':'demo-02','site':'site-0101'}]
    job=plan(op,operation='create',patch={},template_id=template_id,targets=targets,network_selector='Verwaltungsnetz')
    result=run(op,approval,job)
    assert result['counts']['applied']==2
    assert secret not in op.get(f'/api/jobs/{job}/export').text
    network_ids=[]
    for target in targets:
        values=op.get(f"/api/servers/{target['server']}/sites/{target['site']}/wifi").json()
        wifi=next(v for v in values if v['name']=='Test-SSID')
        assert secret not in str(wifi)
        network_ids.append(wifi['network']['networkId'])
    assert network_ids[0]!=network_ids[1]
    assert secret.encode() not in app.state.ctx.store.one('SELECT blob FROM batch_jobs WHERE id=?',(job,))['blob']


def test_vlan_reference_and_default_protection(env):
    app,_=env;op=signed(app)
    job=plan(op,'network','delete',patch={})
    result=wait_job(op,job,('planning_failed',))
    assert 'verwendet' in result['targets'][0]['error']
    job=plan(op,'network','update',patch={'vlanId':240},selector={'name':'Default'})
    assert wait_job(op,job,('planning_failed',))['counts']['planning_failed']==1


def test_drift_conflict_and_rollback_conflict(env):
    app,_=env;op=signed(app);approval=signed(app,'approver')
    job=plan(op);preview=wait_job(op,job)
    target=preview['targets'][0]
    app.state.ctx.store.execute('UPDATE sim_objects SET payload=json_set(payload,?,?) WHERE server_id=? AND site_id=? AND id=?',('$.name','Extern geändert',target['server'],target['site'],target['object']))
    approval.post(f'/api/jobs/{job}/approve');op.post(f'/api/jobs/{job}/execute')
    stopped=wait_job(op,job,('stopped',))
    assert stopped['counts']['conflict']==1


def test_timeout_not_retried_and_uncertain_excluded(env,monkeypatch):
    app,_=env;ctx=app.state.ctx;op=signed(app);approval=signed(app,'approver')
    job=plan(op);wait_job(op,job)
    original=ctx.client.request;calls=[]
    async def timeout(server,method,path,payload=None):
        calls.append(method)
        if method=='PUT':
            await original(server,method,path,payload)
            raise HTTPException(502,'Zeitüberschreitung')
        return await original(server,method,path,payload)
    from fastapi import HTTPException
    monkeypatch.setattr(ctx.client,'request',timeout)
    approval.post(f'/api/jobs/{job}/approve');op.post(f'/api/jobs/{job}/execute')
    stopped=wait_job(op,job,('stopped',))
    assert stopped['counts']['uncertain']==1 and calls.count('PUT')==1
    assert op.post(f'/api/jobs/{job}/retry').status_code==409
    assert op.post(f'/api/jobs/{job}/rollback').status_code==409


def test_server_reconfiguration_invalidates_approval(env):
    app,_=env;op=signed(app);admin=signed(app,'admin');approval=signed(app,'approver')
    job=plan(op);wait_job(op,job);approval.post(f'/api/jobs/{job}/approve')
    assert admin.patch('/api/servers/demo-01',json={'name':'Geänderter Server'}).status_code==200
    op.post(f'/api/jobs/{job}/execute')
    result=wait_job(op,job,('stopped',))
    assert result['counts']['conflict']==1


def test_scheduling_cancel_and_preview_expiry(env):
    app,_=env;op=signed(app);approval=signed(app,'approver')
    job=plan(op);wait_job(op,job);approval.post(f'/api/jobs/{job}/approve')
    assert op.post(f'/api/jobs/{job}/execute',json={'run_after':time.time()+60}).status_code==200
    assert op.get(f'/api/jobs/{job}').json()['state']=='queued'
    assert op.post(f'/api/jobs/{job}/cancel').status_code==200
    assert op.get(f'/api/jobs/{job}').json()['state']=='cancelled'
    expired=plan(op);wait_job(op,expired)
    app.state.ctx.store.execute('UPDATE batch_jobs SET ready_at=? WHERE id=?',(time.time()-90000,expired))
    assert approval.post(f'/api/jobs/{expired}/approve').status_code==409


def test_scope_prevents_cross_server_visibility(env):
    app,_=env;admin=signed(app,'admin')
    assert admin.post('/api/users',json={'name':'limited','password':'limited-pass-2026','role':'operator','scope':['demo-01']}).status_code==200
    limited=signed(app,'limited','limited-pass-2026')
    assert len(limited.get('/api/servers').json())==1
    assert limited.get('/api/inventory').json()['total']==100
    assert limited.get('/api/servers/demo-02/sites').status_code==403
    response=limited.post('/api/jobs',json={'kind':'wifi','targets':[{'server':'demo-02','site':'site-0101'}],'selector':{'name':'Verwaltung'},'patch':{'hideName':True},'reason':'CHG-12345 Test'})
    assert response.status_code==403


def test_immediate_revocation_blocks_queued_job(env):
    app,_=env;admin=signed(app,'admin');op=signed(app);approval=signed(app,'approver')
    job=plan(op);wait_job(op,job);approval.post(f'/api/jobs/{job}/approve')
    op.post(f'/api/jobs/{job}/execute',json={'run_after':time.time()+60})
    assert admin.patch('/api/users/operator',json={'enabled':False}).status_code==200
    assert op.get('/api/me').status_code==401
    app.state.ctx.store.execute('UPDATE batch_jobs SET run_after=? WHERE id=?',(time.time()-1,job))
    result=wait_job(admin,job,('stopped',))
    assert result['counts']['pending']==1


def test_audit_verification_export_and_tampering(env):
    app,_=env;admin=signed(app,'admin');op=signed(app)
    assert op.get('/api/audit').status_code==403
    assert admin.get('/api/audit/verify').json()['valid'] is True
    result=admin.get('/api/audit/export').json()
    assert result['items'] and result['next']>0
    app.state.ctx.store.execute("UPDATE app_audit SET detail='tampered' WHERE seq=1")
    assert admin.get('/api/audit/verify').json()['valid'] is False


def test_origin_csrf_body_bounds_and_cloud_rejection(env):
    app,anon=env
    assert anon.get('/api/servers').status_code==401
    assert anon.post('/api/login',json={'name':'x','password':'x'}).status_code==403
    admin=signed(app,'admin')
    response=admin.post('/api/servers',json={'id':'cloud','name':'Cloud','origin':'https://api.ui.com','key':'secret'})
    assert response.status_code==422
    assert admin.post('/api/jobs',content='x'*(2*1024*1024+1)).status_code==413
    admin.headers['X-CSRF-Token']='wrong'
    assert admin.post('/api/logout').status_code==403
    assert "frame-ancestors 'none'" in anon.get('/').headers['content-security-policy']


def test_restart_preserves_inventory_accounts_and_marks_running_interrupted(tmp_path):
    settings=Settings(demo=True,origin='http://testserver',data_dir=tmp_path)
    app=create_app(settings)
    with TestClient(app):
        admin=signed(app,'admin');op=signed(app)
        admin.post('/api/users',json={'name':'persistent','password':'persistent-2026-pass','role':'viewer'})
        job=plan(op);wait_job(op,job)
        app.state.ctx.store.execute("UPDATE batch_jobs SET state='running' WHERE id=?",(job,))
    other=create_app(settings)
    with TestClient(other):
        persisted=signed(other,'persistent','persistent-2026-pass')
        assert persisted.get('/api/stats').json()['sites']==1200
        admin=signed(other,'admin')
        assert admin.get(f'/api/jobs/{job}').json()['state']=='interrupted'


def test_cancel_during_preflight_prevents_write(env,monkeypatch):
    app,_=env;ctx=app.state.ctx;op=signed(app);approval=signed(app,'approver')
    job=plan(op);wait_job(op,job)
    original=ctx.client.request;writes=[]
    async def cancel_after_read(server,method,path,payload=None):
        result=await original(server,method,path,payload)
        if method=='GET' and '/wifi/broadcasts/' in path:
            ctx.store.execute('UPDATE batch_jobs SET cancel_requested=1 WHERE id=?',(job,))
        if method=='PUT':
            writes.append(path)
        return result
    monkeypatch.setattr(ctx.client,'request',cancel_after_read)
    approval.post(f'/api/jobs/{job}/approve');op.post(f'/api/jobs/{job}/execute')
    result=wait_job(op,job,('cancelled',))
    assert not writes and result['counts']['pending']==1


def test_exact_optional_field_restore_and_paused_parent_cannot_resume(env):
    app,_=env;op=signed(app);approval=signed(app,'approver')
    job=plan(op,targets=[{'server':'demo-01','site':'site-0001'},{'server':'demo-02','site':'site-0101'}],patch={'mdnsProxyConfiguration':{'mode':'AUTO'}},canary_count=1)
    wait_job(op,job);approval.post(f'/api/jobs/{job}/approve');op.post(f'/api/jobs/{job}/execute')
    pilot=wait_job(op,job,('paused',))
    assert pilot['counts']['applied']==1
    restore=op.post(f'/api/jobs/{job}/rollback')
    assert restore.status_code==200,restore.text
    preview=wait_job(op,restore.json()['id'])
    assert preview['targets'][0]['diff']['mdnsProxyConfiguration']['after'] is None
    assert op.post(f'/api/jobs/{job}/resume').status_code==409
    run(op,approval,restore.json()['id'])
    target=preview['targets'][0]
    detail=op.get(f"/api/servers/{target['server']}/sites/{target['site']}/wifi/{target['object']}").json()
    assert 'mdnsProxyConfiguration' not in detail


def test_cross_server_parallelism_and_one_write_per_server(env,monkeypatch):
    import asyncio
    app,_=env;ctx=app.state.ctx;op=signed(app);approval=signed(app,'approver')
    job=plan(op,targets=[{'server':'demo-01','site':'site-0001'},{'server':'demo-01','site':'site-0002'},{'server':'demo-02','site':'site-0101'}],concurrency=6)
    wait_job(op,job);original=ctx.client.request;active={};max_per_server={};max_total=0
    async def measured(server,method,path,payload=None):
        nonlocal max_total
        if method!='PUT':
            return await original(server,method,path,payload)
        name=server['id'];active[name]=active.get(name,0)+1
        max_per_server[name]=max(max_per_server.get(name,0),active[name]);max_total=max(max_total,sum(active.values()))
        await asyncio.sleep(.03)
        try:
            return await original(server,method,path,payload)
        finally:
            active[name]-=1
    monkeypatch.setattr(ctx.client,'request',measured)
    run(op,approval,job)
    assert max_total>=2 and all(n==1 for n in max_per_server.values())


def test_enterprise_profile_resolved_per_site(env):
    app,_=env;op=signed(app);approval=signed(app,'approver')
    targets=[{'server':'demo-01','site':'site-0001'},{'server':'demo-02','site':'site-0101'}]
    job=plan(op,operation='create',targets=targets,patch={'name':'EAP-Test','securityConfiguration':{'type':'WPA2_ENTERPRISE','coaEnabled':False}},radius_selector='Behörden-RADIUS',network_selector='Verwaltungsnetz')
    run(op,approval,job)
    profiles=[]
    for target in targets:
        objects=op.get(f"/api/servers/{target['server']}/sites/{target['site']}/wifi").json()
        object_id=next(v['id'] for v in objects if v['name']=='EAP-Test')
        value=op.get(f"/api/servers/{target['server']}/sites/{target['site']}/wifi/{object_id}").json()
        profiles.append(value['securityConfiguration']['radiusConfiguration']['profileId'])
    assert profiles[0]!=profiles[1]


def test_planner_only_role_can_delegate_execution(env):
    app,_=env;admin=signed(app,'admin');approval=signed(app,'approver');op=signed(app)
    assert admin.post('/api/roles',json={'id':'planner','name':'Planung','permissions':['view','plan']}).status_code==200
    assert admin.post('/api/users',json={'name':'planner-user','password':'planner-password-2026','role':'planner'}).status_code==200
    planner=signed(app,'planner-user','planner-password-2026')
    job=plan(planner)
    run(op,approval,job)


def test_single_instance_and_demo_data_cannot_be_production(tmp_path):
    from cryptography.fernet import Fernet
    config=Settings(demo=True,origin='http://testserver',data_dir=tmp_path)
    app=create_app(config)
    with TestClient(app):
        with pytest.raises(RuntimeError,match='andere Instanz'):
            create_app(config)
    key=tmp_path/'production.key';key.write_bytes(Fernet.generate_key())
    with pytest.raises(RuntimeError,match='Demo- und Produktivdaten'):
        create_app(Settings(demo=False,origin='https://testserver',data_dir=tmp_path,encryption_key_file=str(key)))


def test_validation_responses_never_echo_credentials(env):
    app,_=env;admin=signed(app,'admin');secret='do-not-echo-api-secret'
    response=admin.post('/api/servers',json={'id':'x','name':'Test','origin':'https://uos.intern.example','key':secret,'unexpected':secret})
    assert response.status_code==422 and secret not in response.text


def test_duplicate_vlan_id_rejected_before_write(env):
    app,_=env;op=signed(app)
    job=plan(op,'network','create',patch={'name':'Duplicate-ID','vlanId':100})
    result=wait_job(op,job,('planning_failed',))
    assert result['targets'][0]['error']=='VLAN-ID ist auf dieser Site bereits vorhanden'


def test_system_managed_wlan_update_is_protected(env):
    app,_=env;op=signed(app)
    obj=op.get('/api/servers/demo-01/sites/site-0001/wifi').json()[0]
    app.state.ctx.store.execute('UPDATE sim_objects SET payload=json_set(payload,?,?) WHERE server_id=? AND site_id=? AND id=?',('$.metadata.origin','ORCHESTRATED','demo-01','site-0001',obj['id']))
    job=plan(op,targets=[{'server':'demo-01','site':'site-0001','object':obj['id']}])
    result=wait_job(op,job,('planning_failed',))
    assert 'herkunft' in result['targets'][0]['error'].casefold()


def test_retained_optional_setting_makes_restore_uncertain(env,monkeypatch):
    app,_=env;ctx=app.state.ctx;op=signed(app);approval=signed(app,'approver')
    job=plan(op,patch={'mdnsProxyConfiguration':{'mode':'AUTO'}})
    run(op,approval,job)
    restore=op.post(f'/api/jobs/{job}/rollback').json()['id'];wait_job(op,restore)
    original=ctx.client.request
    async def retained(server,method,path,payload=None):
        result=await original(server,method,path,payload)
        if method=='PUT':
            ctx.store.execute('UPDATE sim_objects SET payload=json_set(payload,?,json(?)) WHERE server_id=? AND id=?',('$.mdnsProxyConfiguration','{"mode":"AUTO"}',server['id'],result['id']))
        return result
    monkeypatch.setattr(ctx.client,'request',retained)
    approval.post(f'/api/jobs/{restore}/approve');op.post(f'/api/jobs/{restore}/execute')
    result=wait_job(op,restore,('stopped',))
    assert result['counts']['uncertain']==1


def test_local_revocation_after_last_directory_await_blocks_write(env,monkeypatch):
    app,_=env;ctx=app.state.ctx;op=signed(app);approval=signed(app,'approver');admin=signed(app,'admin')
    job=plan(op);wait_job(op,job)
    original_request=ctx.client.request;original_reauth=ctx.auth.reauthorize;armed=False;writes=[]
    async def request(server,method,path,payload=None):
        nonlocal armed
        result=await original_request(server,method,path,payload)
        if method=='GET' and '/wifi/broadcasts/' in path:
            armed=True
        if method=='PUT':
            writes.append(path)
        return result
    async def reauth(name):
        result=await original_reauth(name)
        if armed and name=='admin':
            ctx.store.execute("UPDATE auth_users SET enabled=0,version=version+1 WHERE name='operator'")
        return result
    monkeypatch.setattr(ctx.client,'request',request);monkeypatch.setattr(ctx.auth,'reauthorize',reauth)
    approval.post(f'/api/jobs/{job}/approve');admin.post(f'/api/jobs/{job}/execute')
    result=wait_job(admin,job,('stopped',))
    assert not writes and result['counts']['failed']==1
