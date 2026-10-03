"""Durable, approval-gated WLAN/VLAN/RADIUS planning and bounded rollout execution."""
import asyncio
import hashlib
import re
import secrets
import time

from fastapi import HTTPException
from app.contract import create_defaults, deep_merge, redact, write_payload

RESOURCES = {'wifi': 'wifi/broadcasts', 'network': 'networks', 'radius': 'radius/configurations'}
ACTIVE = ('planning', 'planned', 'approved', 'queued', 'running', 'paused')


def segment(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}', value):
        raise HTTPException(422, 'Ungültige Objekt-ID')
    return value


def resource_path(site, kind, object_id=None):
    if kind not in RESOURCES:
        raise HTTPException(422, 'Nur WLANs, VLANs und RADIUS-Profile werden unterstützt')
    path = f'/sites/{segment(site)}/{RESOURCES[kind]}'
    return path + '/' + segment(object_id) if object_id else path


def job_row(ctx, job_id):
    row = ctx.store.one('SELECT * FROM batch_jobs WHERE id=?', (job_id,))
    if not row:
        raise HTTPException(404, 'Auftrag unbekannt')
    return row


def check_scope(ctx, user, row):
    recipe = ctx.decrypt(row['blob'])
    for server in {t['server'] for t in recipe['targets']}:
        ctx.auth.require_scope(user, server)
    return recipe


def cancelled(ctx,job_id):
    row=ctx.store.one('SELECT cancel_requested FROM batch_jobs WHERE id=?',(job_id,))
    return not row or bool(row['cancel_requested'])


def current_user(ctx, name, permission):
    user = ctx.auth.user(name)
    if not user or not user.get('enabled') or permission not in user['permissions']:
        raise HTTPException(403, 'Berechtigung des beteiligten Kontos ist nicht mehr gültig')
    return user


def summary(ctx, row):
    recipe = ctx.decrypt(row['blob'])
    counts = {r['status']: r['n'] for r in ctx.store.query('SELECT status,COUNT(*) n FROM batch_targets WHERE job=? GROUP BY status', (row['id'],))}
    return {k: row[k] for k in ('id','creator','approver','state','created','ready_at','approved_at','run_after','kind','operation','reason','parent','error')} | {
        'counts': counts, 'total_targets': sum(counts.values()), 'input_targets': len(recipe['targets']),
        'concurrency': recipe.get('concurrency', 4), 'stop_on_error': recipe.get('stop_on_error', True),
        'canary_count': recipe.get('canary_count', 0), 'cancel_requested': bool(row['cancel_requested'])}


def detail(ctx, row, offset=0, limit=100):
    result = summary(ctx, row)
    values = ctx.store.query('SELECT * FROM batch_targets WHERE job=? ORDER BY idx LIMIT ? OFFSET ?', (row['id'], limit, offset))
    result['targets'] = []
    for target in values:
        payload = ctx.decrypt(target['blob'])
        result['targets'].append({k: target[k] for k in ('idx','server','site','object','operation','status')} | {
            'name': payload.get('name'), 'diff': redact(payload.get('diff', {})), 'error': payload.get('error')})
    return result | {'offset': offset, 'limit': limit}


def create_job(ctx, user, recipe, kind, operation, reason, parent=None):
    if kind not in RESOURCES or operation not in ('create','update','delete','restore'):
        raise HTTPException(422, 'Unbekannte Änderung')
    for target in recipe['targets']:
        segment(target['server'])
        segment(target['site'])
        if target.get('object'):
            segment(target['object'])
        ctx.auth.require_scope(user, target['server'])
        ctx.server(target['server'])
    recipe['server_versions'] = {server: hashlib.sha256(ctx.store.one('SELECT blob FROM app_servers WHERE id=?',(server,))['blob']).hexdigest()
                                 for server in {t['server'] for t in recipe['targets']}}
    if kind == 'radius':
        recipe['radius_site_references'] = {f"{target['server']}:{target['site']}": ctx.radius_reference(target['server'], resource_path(target['site'], kind))
                                            for target in recipe['targets']}
    job_id = secrets.token_hex(12)
    with ctx.store.transaction():
        ctx.store.execute('INSERT INTO batch_jobs(id,creator,state,created,kind,operation,reason,blob,parent) VALUES(?,?,?,?,?,?,?,?,?)',
                          (job_id,user['name'],'planning',time.time(),kind,operation,reason,ctx.encrypt(recipe),parent))
        for server in {t['server'] for t in recipe['targets']}:
            ctx.store.execute('INSERT INTO batch_scope VALUES(?,?)',(job_id,server))
        ctx.audit(user['name'],'plan_created',f'{job_id}:{kind}:{operation}:{len(recipe["targets"])} Ziele')
    return summary(ctx, job_row(ctx, job_id))


def protected(kind, before, operation, patch):
    if (before.get('metadata') or {}).get('origin')!='USER_DEFINED':
        raise HTTPException(422,'Systemverwaltete oder unbekannte Konfigurationsherkunft ist geschützt')
    if kind == 'network':
        if before.get('management') != 'UNMANAGED':
            raise HTTPException(422, 'Nur VLANs ohne UniFi-Routing (UNMANAGED) sind erlaubt')
        if before.get('default') or before.get('vlanId') == 1:
            if operation == 'delete' or 'vlanId' in patch:
                raise HTTPException(422, 'Das Standardnetz ist geschützt')


async def references_clear(ctx, server, path, kind='network'):
    references = await ctx.request(server, 'GET', path + '/references')
    if not isinstance(references, dict) or not isinstance(references.get('referenceResources'), list):
        raise HTTPException(502, ('RADIUS' if kind == 'radius' else 'VLAN')+'-Referenzen konnten nicht zuverlässig geprüft werden')
    if references['referenceResources']:
        raise HTTPException(409, ('RADIUS-Profil' if kind == 'radius' else 'VLAN')+' wird noch verwendet und darf nicht gelöscht werden')


async def plan_job(ctx, job_id):
    row = job_row(ctx, job_id)
    recipe = ctx.decrypt(row['blob'])
    user = current_user(ctx, row['creator'], 'plan')
    check_scope(ctx, user, row)
    # Safe to restart a read-only planning phase. Execution is never restarted automatically.
    ctx.store.execute('DELETE FROM batch_targets WHERE job=?', (job_id,))
    index = 0
    failures = False
    gate = asyncio.Semaphore(6)
    pending_inserts=[]
    def flush():
        with ctx.store.transaction():
            for values in pending_inserts:
                ctx.store.execute('INSERT INTO batch_targets VALUES(?,?,?,?,?,?,?,?)',values)
        pending_inserts.clear()
    def insert(source, operation, object_id, payload, status):
        nonlocal index, failures
        if status == 'planning_failed':
            failures = True
        pending_inserts.append((job_id,index,source['server'],source['site'],object_id,operation,status,ctx.encrypt(payload)))
        index += 1
        if len(pending_inserts)>=50:
            flush()
    async def one(source):
        nonlocal failures
        async with gate:
            if cancelled(ctx,job_id):
                return
            operation = source.get('operation', row['operation'])
            kind = row['kind']
            patch = source.get('desired', recipe.get('patch', {}))
            path = resource_path(source['site'], kind)
            try:
                ensure_server_version(ctx,recipe,source['server'],source['site'])
                matches = []
                if operation == 'create':
                    create_patch=patch
                    if recipe.get('radius_selector') and kind=='wifi':
                        profiles=await ctx.collection(source['server'],f"/sites/{segment(source['site'])}/radius/profiles")
                        selected=[p for p in profiles if p.get('name')==recipe['radius_selector']]
                        if len(selected)!=1:
                            raise HTTPException(409,'RADIUS-Profil fehlt auf dieser Site oder ist nicht eindeutig')
                        create_patch=deep_merge(patch,{'securityConfiguration':{'radiusConfiguration':{'profileId':selected[0]['id'],'nasId':{'type':'DERIVED','source':'DEVICE_MAC_ADDRESS'}}}})
                    desired = create_defaults(kind, create_patch)
                    existing = await ctx.collection(source['server'], path)
                    if any(v.get('name') == desired['name'] for v in existing):
                        raise HTTPException(409, 'Eine Konfiguration mit diesem Namen existiert bereits')
                    if kind=='network' and any(v.get('vlanId')==desired['vlanId'] for v in existing):
                        raise HTTPException(409,'VLAN-ID ist auf dieser Site bereits vorhanden')
                    matches = [None]
                elif source.get('object'):
                    matches = [await ctx.request(source['server'],'GET',path+'/'+segment(source['object']))]
                else:
                    selector = recipe.get('selector') or {}
                    values = await ctx.collection(source['server'], path)
                    if kind == 'network':
                        values = [v for v in values if v.get('management') == 'UNMANAGED' and not v.get('default') and v.get('vlanId') != 1]
                    matches = values if selector.get('all') else [v for v in values if v.get('name') == selector.get('name')]
                    if not matches:
                        raise HTTPException(404, 'Keine Konfiguration passend zur Auswahl vorhanden')
                    if not selector.get('all') and len(matches) != 1:
                        raise HTTPException(409, 'Der Konfigurationsname ist nicht eindeutig')
                    matches = [await ctx.request(source['server'],'GET',path+'/'+segment(v['id'])) for v in matches]
                for before in matches:
                    if index >= 20000:
                        raise HTTPException(422, 'Mehr als 20.000 Zielobjekte; Auftrag aufteilen')
                    object_id = before['id'] if before else None
                    target_path = path + '/' + segment(object_id) if object_id else path
                    if before:
                        protected(kind,before,operation,patch)
                        if source.get('expected') is not None and write_payload(kind,before) != write_payload(kind,source['expected']):
                            raise HTTPException(409, 'Konfiguration hat sich seit der ursprünglichen Ausführung geändert')
                    if operation == 'delete':
                        write_payload(kind,before)
                        if kind in ('network', 'radius'):
                            await references_clear(ctx,source['server'],target_path,kind)
                        after = None
                        diff = {'delete': {'before': before, 'after': None}}
                    else:
                        after = patch if source.get('desired') is not None else deep_merge(before,patch) if before else desired
                        if recipe.get('radius_selector') and kind=='wifi' and operation!='create':
                            profiles=await ctx.collection(source['server'],f"/sites/{segment(source['site'])}/radius/profiles")
                            selected=[p for p in profiles if p.get('name')==recipe['radius_selector']]
                            if len(selected)!=1:
                                raise HTTPException(409,'RADIUS-Profil fehlt auf dieser Site oder ist nicht eindeutig')
                            radius=(after.get('securityConfiguration') or {}).get('radiusConfiguration') or {'nasId':{'type':'DERIVED','source':'DEVICE_MAC_ADDRESS'}}
                            radius['profileId']=selected[0]['id']
                            after['securityConfiguration']['radiusConfiguration']=radius
                        if recipe.get('network_selector') and kind == 'wifi':
                            networks = await ctx.collection(source['server'], resource_path(source['site'],'network'))
                            selected = [v for v in networks if v.get('name') == recipe['network_selector'] and v.get('management') == 'UNMANAGED']
                            if len(selected) != 1:
                                raise HTTPException(409, 'Der gewählte VLAN-Name fehlt oder ist nicht eindeutig')
                            after['network'] = {'type':'SPECIFIC','networkId':selected[0]['id']}
                        if kind == 'wifi' and (after.get('network') or {}).get('type') == 'SPECIFIC':
                            networks = await ctx.collection(source['server'], resource_path(source['site'],'network'))
                            if not any(v['id'] == after['network']['networkId'] for v in networks):
                                raise HTTPException(422, 'WLAN-VLAN-Zuordnung existiert auf dieser Site nicht')
                        after = write_payload(kind,after)
                        if before:
                            comparable = write_payload(kind,before)
                            diff = {k:{'before':comparable.get(k),'after':after.get(k)} for k in set(comparable)|set(after) if comparable.get(k)!=after.get(k)}
                        else:
                            diff = {'create': {'before': None, 'after': after}}
                    insert(source,operation,object_id,{'path':target_path,'name':(before or after or {}).get('name'),
                           'before':before,'after':after,'diff':diff},'pending' if diff else 'unchanged')
            except (HTTPException,ValueError) as error:
                message = error.detail if isinstance(error,HTTPException) and isinstance(error.detail,str) else str(error)
                insert(source,operation,source.get('object'),{'name':recipe.get('selector',{}).get('name'), 'error':message,'diff':{}},'planning_failed')
            except Exception:
                insert(source,operation,source.get('object'),{'error':'Vorschau fehlgeschlagen; Serverzugriff und API-Vertrag prüfen','diff':{}},'planning_failed')
    await asyncio.gather(*(one(target) for target in recipe['targets']))
    flush()
    state = 'cancelled' if job_row(ctx,job_id)['cancel_requested'] else 'planning_failed' if failures or not index else 'planned'
    ctx.store.execute('UPDATE batch_jobs SET state=?,ready_at=? WHERE id=?', (state,time.time(),job_id))
    ctx.audit(row['creator'],'planning_finished',f'{job_id}:{state}:{index} Ziele')


def save_target(ctx, job, idx, status, payload, object_id=None):
    if object_id:
        ctx.store.execute('UPDATE batch_targets SET status=?,blob=?,object=? WHERE job=? AND idx=?', (status,ctx.encrypt(payload),object_id,job,idx))
    else:
        ctx.store.execute('UPDATE batch_targets SET status=?,blob=? WHERE job=? AND idx=?', (status,ctx.encrypt(payload),job,idx))


def same_fields(actual, expected):
    if isinstance(expected,dict):
        return isinstance(actual,dict) and all(k in actual and same_fields(actual[k],v) for k,v in expected.items())
    return actual == expected


def ensure_server_version(ctx,recipe,server_id,site_id=None):
    row=ctx.store.one('SELECT blob FROM app_servers WHERE id=?',(server_id,))
    actual=hashlib.sha256(row['blob']).hexdigest() if row else None
    if actual != recipe.get('server_versions',{}).get(server_id):
        raise HTTPException(409,'Serverkonfiguration wurde seit der Planung verändert; neue Vorschau erforderlich')
    if recipe.get('radius_site_references') is not None and site_id is not None:
        reference = ctx.radius_reference(server_id, resource_path(site_id,'radius'))
        if reference != recipe['radius_site_references'].get(f'{server_id}:{site_id}'):
            raise HTTPException(409,'Der lokale Site-Verweis wurde seit der Planung verändert; neue Vorschau erforderlich')


async def verify_radius_site_bindings(ctx, recipe):
    """Refresh only the official site overview, once per affected controller.

    A stale inventory must not bind a planned UUID to a newly reused classic
    site name. Target processing also verifies the locally pinned binding.
    """
    expected = recipe.get('radius_site_references')
    if expected is None:
        raise HTTPException(409, 'RADIUS-Auftrag ohne Site-Zuordnung; neue Vorschau erforderlich')
    by_server = {}
    for target in recipe['targets']:
        by_server.setdefault(target['server'], set()).add(target['site'])
    gate = asyncio.Semaphore(4)

    async def verify(server_id, site_ids):
        async with gate:
            ensure_server_version(ctx, recipe, server_id)
            sites = await ctx.collection(server_id, '/sites')
            if not isinstance(sites, list) or any(not isinstance(site, dict) for site in sites):
                raise HTTPException(502, 'RADIUS-Site-Zuordnung konnte nicht zuverlässig geprüft werden')
            mapping, references = {}, set()
            for site in sites:
                site_id, reference = site.get('id'), site.get('internalReference')
                if not isinstance(site_id, str) or site_id in mapping:
                    raise HTTPException(502, 'UniFi liefert ungültige oder mehrdeutige Site-IDs')
                if reference is not None:
                    if (not isinstance(reference, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', reference)
                            or reference in references):
                        raise HTTPException(502, 'UniFi liefert ungültige oder mehrdeutige lokale Site-Verweise')
                    references.add(reference)
                mapping[site_id] = reference
            for site_id in site_ids:
                ensure_server_version(ctx, recipe, server_id, site_id)
                if not mapping.get(site_id) or mapping[site_id] != expected.get(f'{server_id}:{site_id}'):
                    raise HTTPException(409, 'Die lokale UniFi-Site-Zuordnung wurde verändert; neue Vorschau erforderlich')

    await asyncio.gather(*(verify(server_id, site_ids) for server_id, site_ids in by_server.items()))


async def apply_target(ctx,row,target,stop,recipe):
    job_id = row['id']
    payload = ctx.decrypt(target['blob'])
    kind,operation = row['kind'],target['operation']
    controller_lock = ctx.controller_locks.setdefault(target['server'],asyncio.Lock())
    async with controller_lock:
        if stop.is_set() or cancelled(ctx,job_id):
            return
        try:
            # Revalidate accounts/scopes at each target, including long scheduled rollouts.
            creator = current_user(ctx,row['creator'],'plan')
            approver = current_user(ctx,row['approver'],'approve')
            ctx.auth.require_scope(creator,target['server'])
            ctx.auth.require_scope(approver,target['server'])
            ensure_server_version(ctx,recipe,target['server'],target['site'])
            if operation == 'create':
                current = await ctx.collection(target['server'],payload['path'])
                if any(v.get('name') == payload['after']['name'] for v in current):
                    raise HTTPException(409,'Zielname ist inzwischen vorhanden')
                if kind=='network' and any(v.get('vlanId')==payload['after']['vlanId'] for v in current):
                    raise HTTPException(409,'VLAN-ID ist inzwischen vorhanden')
            else:
                current = await ctx.request(target['server'],'GET',payload['path'])
                if current != payload['before']:
                    raise HTTPException(409,'Konfiguration wurde nach der Vorschau verändert')
                protected(kind,current,operation,payload.get('after') or {})
                if operation == 'delete' and kind == 'network':
                    await references_clear(ctx,target['server'],payload['path'])
            if stop.is_set() or cancelled(ctx,job_id):
                return
            for name,permission in ((row['creator'],'plan'),(row['approver'],'approve'),(recipe.get('executor',row['creator']),'execute')):
                user=await ctx.auth.reauthorize(name)
                if not user or not user.get('enabled') or permission not in user['permissions']:
                    raise HTTPException(403,'Berechtigung vor dem Schreibzugriff widerrufen')
                ctx.auth.require_scope(user,target['server'])
            if kind == 'radius' and operation == 'create':
                current = await ctx.collection(target['server'],payload['path'])
                if any(v.get('name') == payload['after']['name'] for v in current):
                    raise HTTPException(409,'RADIUS-Zielname ist inzwischen vorhanden')
            elif kind == 'radius':
                # LDAP checks may take time. Repeat drift/reference reads last,
                # then check local authorization again immediately before write.
                current = await ctx.request(target['server'],'GET',payload['path'])
                if current != payload['before']:
                    raise HTTPException(409,'RADIUS-Profil wurde nach der Vorschau verändert')
                protected(kind,current,operation,payload.get('after') or {})
                if operation == 'delete':
                    await references_clear(ctx,target['server'],payload['path'],kind)
            if stop.is_set() or cancelled(ctx,job_id):
                return
            ensure_server_version(ctx,recipe,target['server'],target['site'])
            for name,permission in ((row['creator'],'plan'),(row['approver'],'approve'),(recipe.get('executor',row['creator']),'execute')):
                final_user=current_user(ctx,name,permission)
                ctx.auth.require_scope(final_user,target['server'])
            save_target(ctx,job_id,target['idx'],'uncertain',payload)
            method = {'create':'POST','update':'PUT','delete':'DELETE'}[operation]
            result = await ctx.request(target['server'],method,payload['path'],payload['after'])
            if operation == 'delete':
                try:
                    await ctx.request(target['server'],'GET',payload['path'])
                except HTTPException as error:
                    if error.status_code != 404:
                        raise
                else:
                    raise HTTPException(502,'Gelöschtes Objekt ist noch vorhanden')
                payload['actual'] = None
            else:
                if operation == 'create':
                    object_id = segment(result['id'])
                    payload['path'] += '/' + object_id
                    save_target(ctx,job_id,target['idx'],'uncertain',payload,object_id)
                actual = await ctx.request(target['server'],'GET',payload['path'])
                actual_write=write_payload(kind,actual)
                previous_write=write_payload(kind,payload['before']) if payload['before'] else {}
                removed=set(previous_write)-set(payload['after'])
                if not same_fields(actual_write,payload['after']) or any(actual_write.get(key) is not None for key in removed):
                    raise HTTPException(502,'Nachprüfung meldet abweichende Konfiguration')
                payload['actual'] = actual
            with ctx.store.transaction():
                save_target(ctx,job_id,target['idx'],'applied',payload)
                ctx.audit(row['creator'],'target_applied',f"{job_id}:{target['idx']}:{target['server']}:{target['site']}:{operation}")
        except Exception as error:
            state = ctx.store.one('SELECT status FROM batch_targets WHERE job=? AND idx=?',(job_id,target['idx']))['status']
            payload['error'] = error.detail if isinstance(error,HTTPException) and isinstance(error.detail,str) else 'Ziel konnte nicht abgeschlossen werden; Ergebnis am Controller prüfen'
            status = 'uncertain' if state == 'uncertain' else 'conflict' if isinstance(error,HTTPException) and error.status_code == 409 else 'failed'
            with ctx.store.transaction():
                save_target(ctx,job_id,target['idx'],status,payload)
                ctx.audit(row['creator'],'target_failed',f"{job_id}:{target['idx']}:{status}")
            if recipe.get('stop_on_error',True):
                stop.set()


async def execute_job(ctx,job_id):
    row = job_row(ctx,job_id)
    if row['state'] != 'queued':
        return
    recipe = ctx.decrypt(row['blob'])
    try:
        if not ctx.config.writes:
            raise HTTPException(403,'Schreibzugriffe sind vom Betreiber gesperrt')
        creator = current_user(ctx,row['creator'],'plan')
        approver = current_user(ctx,row['approver'],'approve')
        for name,permission in ((row['creator'],'plan'),(row['approver'],'approve'),(recipe.get('executor',row['creator']),'execute')):
            user=await ctx.auth.reauthorize(name)
            if not user or not user.get('enabled') or permission not in user['permissions']:
                raise HTTPException(403,'Berechtigung für geplante Ausführung widerrufen')
            check_scope(ctx,user,row)
        if creator['name'] == approver['name']:
            raise HTTPException(403,'Vier-Augen-Freigabe ungültig')
        check_scope(ctx,creator,row)
        check_scope(ctx,approver,row)
        if not row['ready_at'] or time.time()-row['ready_at'] > ctx.config.preview_ttl:
            raise HTTPException(409,'Vorschau abgelaufen; neue Vorschau erstellen')
        if row['kind'] == 'radius':
            await verify_radius_site_bindings(ctx, recipe)
    except HTTPException as error:
        ctx.store.execute("UPDATE batch_jobs SET state='stopped',error=? WHERE id=?",(error.detail,job_id))
        return
    ctx.store.execute("UPDATE batch_jobs SET state='running' WHERE id=?",(job_id,))
    ctx.audit(row['creator'],'execution_started',job_id)
    pending = ctx.store.query("SELECT * FROM batch_targets WHERE job=? AND status='pending' ORDER BY idx",(job_id,))
    canary = recipe.get('canary_count',0)
    applied = ctx.store.one("SELECT COUNT(*) n FROM batch_targets WHERE job=? AND status='applied'",(job_id,))['n']
    canary_phase = bool(canary and applied < canary and len(pending) > canary-applied)
    if canary_phase:
        pending = pending[:canary-applied]
    by_server={}
    for target in pending:
        by_server.setdefault(target['server'],[]).append(target)
    stop = asyncio.Event()
    global_gate=asyncio.Semaphore(recipe.get('concurrency',4))
    async def server_worker(targets):
        for target in targets:
            if stop.is_set() or cancelled(ctx,job_id):
                return
            async with global_gate:
                await apply_target(ctx,row,target,stop,recipe)
    await asyncio.gather(*(server_worker(targets) for targets in by_server.values()))
    counts = summary(ctx,job_row(ctx,job_id))['counts']
    failure = any(counts.get(key,0) for key in ('failed','uncertain','conflict'))
    state = 'cancelled' if job_row(ctx,job_id)['cancel_requested'] else 'stopped' if failure else 'paused' if canary_phase else 'completed'
    ctx.store.execute('UPDATE batch_jobs SET state=? WHERE id=?',(state,job_id))
    ctx.audit(row['creator'],'execution_finished',f'{job_id}:{state}')


def inverse_job(ctx,user,row):
    check_scope(ctx,user,row)
    if row['state'] not in ('completed','stopped','cancelled','interrupted','paused'):
        raise HTTPException(409,'Wiederherstellung erfordert einen abgeschlossenen oder gestoppten Auftrag')
    recipe = ctx.decrypt(row['blob'])
    targets = []
    for target in ctx.store.query("SELECT * FROM batch_targets WHERE job=? AND status='applied' ORDER BY idx",(row['id'],)):
        payload = ctx.decrypt(target['blob'])
        source = {'server':target['server'],'site':target['site']}
        if target['operation'] == 'create':
            source |= {'operation':'delete','object':target['object'],'expected':payload['actual']}
        elif target['operation'] == 'update':
            source |= {'operation':'update','object':target['object'],'desired':write_payload(row['kind'],payload['before']),'expected':payload['actual']}
        else:
            source |= {'operation':'create','desired':write_payload(row['kind'],payload['before'])}
        targets.append(source)
    if not targets:
        raise HTTPException(409,'Keine bestätigten Änderungen zur Wiederherstellung vorhanden')
    if row['state']=='paused':
        ctx.store.execute("UPDATE batch_jobs SET state='cancelled',cancel_requested=1 WHERE id=?",(row['id'],))
        ctx.audit(user['name'],'pilot_cancelled_for_restore',row['id'])
    inverse = {'targets':targets,'patch':{},'selector':{},'concurrency':recipe.get('concurrency',4),'stop_on_error':True,'canary_count':0}
    return create_job(ctx,user,inverse,row['kind'],'restore','Wiederherstellung von '+row['id'],row['id'])
