import json
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from app.settings import Settings
from app.service import Service
from app.jobs import ACTIVE, check_scope, create_job, detail, inverse_job, job_row, resource_path, segment, summary
from app.contract import redact, validate_patch

ROOT = Path(__file__).parent


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid')


class ServerInput(Input):
    id: str = Field(max_length=80)
    name: str = Field(min_length=1,max_length=128)
    origin: str = Field(max_length=255)
    api_prefix: str = '/proxy/network/integration/v1'
    key: str = Field(min_length=1,max_length=8192)
    ca_file: str | None = None
    radius_legacy_enabled: bool = False
    radius_auth_mode: Literal['api_key', 'local_account'] = 'api_key'
    radius_username: str | None = Field(default=None, max_length=128)
    radius_password: str | None = Field(default=None, max_length=8192)


class ServerUpdate(Input):
    name: str | None = Field(default=None,min_length=1,max_length=128)
    origin: str | None = Field(default=None,max_length=255)
    api_prefix: str | None = None
    key: str | None = Field(default=None,max_length=8192)
    ca_file: str | None = None
    enabled: bool | None = None
    radius_legacy_enabled: bool | None = None
    radius_auth_mode: Literal['api_key', 'local_account'] | None = None
    radius_username: str | None = Field(default=None, max_length=128)
    radius_password: str | None = Field(default=None, max_length=8192)


class SyncInput(Input):
    servers: list[str] | None = None


class TagsInput(Input):
    tags: list[str] = Field(max_length=20)


class Target(Input):
    server: str
    site: str
    object: str | None = None


class Selector(Input):
    name: str | None = Field(default=None,max_length=128)
    all: bool = False


class Plan(Input):
    kind: str
    operation: str = 'update'
    targets: list[Target] = Field(min_length=1,max_length=20000)
    selector: Selector = Field(default_factory=Selector)
    patch: dict = Field(default_factory=dict)
    template_id: str | None = None
    network_selector: str | None = Field(default=None,max_length=128)
    radius_selector: str | None = Field(default=None,max_length=128)
    reason: str = Field(min_length=10,max_length=1000)
    concurrency: int = Field(default=4,ge=1,le=6)
    stop_on_error: bool = True
    canary_count: int = Field(default=0,ge=0,le=50)


class TemplateInput(Input):
    name: str = Field(min_length=1,max_length=128)
    kind: str
    operation: str = 'update'
    patch: dict


class Schedule(Input):
    run_after: float | None = None


def create_app(config=None):
    ctx = Service(config or Settings())
    from app.auth import AuthService
    try:
        ctx.auth = AuthService(ctx)
    except Exception:
        ctx.store.close();ctx.process_lock.close()
        raise
    @asynccontextmanager
    async def lifespan(app):
        await ctx.start()
        try:
            yield
        finally:
            await ctx.close()
    app = FastAPI(docs_url=None,redoc_url=None,openapi_url=None,lifespan=lifespan)
    app.state.ctx = ctx
    ctx.auth.install(app)
    @app.exception_handler(RequestValidationError)
    async def validation_error(request,error):
        return JSONResponse({'detail':'Ungültige Eingabefelder','errors':[{'loc':e['loc'],'type':e['type']} for e in error.errors()]},status_code=422)
    app.mount('/static', StaticFiles(directory=ROOT/'static'),name='static')

    @app.middleware('http')
    async def protection(request,call_next):
        if request.method not in ('GET','HEAD'):
            if request.headers.get('origin') != ctx.config.origin:
                return JSONResponse({'detail':'Ungültiger Ursprung'},status_code=403)
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 2 * 1024 * 1024:
                    return JSONResponse({'detail':'Anfrage größer als 2 MiB'},status_code=413)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers.update({
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Cache-Control':'no-store',
            'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
        })
        if not ctx.config.demo:
            response.headers['Strict-Transport-Security']='max-age=31536000'
        return response

    @app.get('/')
    async def index():
        return FileResponse(ROOT/'static/index.html')

    @app.get('/health')
    async def health():
        ctx.store.one('SELECT 1')
        return {'status':'ok'}

    @app.get('/api/stats')
    async def stats(request:Request):
        user = ctx.auth.identity(request,'view')
        servers = ctx.servers(user)
        where,args=job_where(user)
        states={r['state']:r['n'] for r in ctx.store.query('SELECT state,COUNT(*) n FROM batch_jobs'+where+' GROUP BY state',args)}  # nosec B608 # job_where supplies fixed SQL and placeholders; scope values are bound.
        return {'servers':len(servers),'sites':sum(s['site_count'] for s in servers),'jobs':sum(states.values()),
                'states':states,'writes':ctx.config.writes,'demo':ctx.config.demo,'online_servers':sum(s['status']=='online' for s in servers)}

    @app.get('/api/servers')
    async def servers(request:Request):
        return ctx.servers(ctx.auth.identity(request,'view'))

    @app.post('/api/servers')
    async def add_server(data:ServerInput,request:Request):
        user=ctx.auth.identity(request,'servers.manage')
        segment(data.id)
        ctx.auth.require_scope(user,data.id)
        if ctx.store.one('SELECT id FROM app_servers WHERE id=?',(data.id,)):
            raise HTTPException(409,'Server-ID ist bereits vorhanden')
        value = ctx.validate_server(data.model_dump(exclude={'id','name'}) | {'origin':data.origin.rstrip('/')})
        ctx.store.execute('INSERT INTO app_servers(id,name,blob) VALUES(?,?,?)',(data.id,data.name,ctx.encrypt(value)))
        ctx.audit(user['name'],'server_created',data.id)
        return ctx.public_server(ctx.store.one('SELECT * FROM app_servers WHERE id=?',(data.id,)))

    @app.patch('/api/servers/{server_id}')
    async def update_server(server_id:str,data:ServerUpdate,request:Request):
        user=ctx.auth.identity(request,'servers.manage')
        ctx.auth.require_scope(user,server_id)
        row=ctx.store.one('SELECT * FROM app_servers WHERE id=?',(server_id,))
        if not row:
            raise HTTPException(404,'Server unbekannt')
        changes=data.model_dump(exclude_unset=True)
        if any(server_id in {t['server'] for t in ctx.decrypt(j['blob'])['targets']} for j in ctx.store.query("SELECT blob FROM batch_jobs WHERE state='running'")):
            raise HTTPException(409,'Server wird gerade in einem Rollout verwendet')
        value=ctx.decrypt(row['blob']) | {k:v for k,v in changes.items() if k not in ('name','enabled') and (k not in ('key','radius_password') or v)}
        if value.get('radius_auth_mode', 'api_key') == 'api_key':
            value.pop('radius_password', None)
            value.pop('radius_username', None)
        ctx.validate_server(value)
        ctx.store.execute('UPDATE app_servers SET name=?,enabled=?,blob=? WHERE id=?',
                          (changes.get('name') or row['name'],row['enabled'] if changes.get('enabled') is None else int(changes['enabled']),ctx.encrypt(value),server_id))
        ctx.audit(user['name'],'server_updated',server_id)
        return ctx.public_server(ctx.store.one('SELECT * FROM app_servers WHERE id=?',(server_id,)))

    @app.delete('/api/servers/{server_id}')
    async def delete_server(server_id:str,request:Request):
        user=ctx.auth.identity(request,'servers.manage')
        ctx.auth.require_scope(user,server_id)
        ctx.server(server_id,enabled=False)
        for row in ctx.store.query('SELECT blob FROM batch_jobs WHERE state IN ('+','.join('?' for _ in ACTIVE)+')',ACTIVE):  # nosec B608 # Only placeholder count is generated; ACTIVE values are bound.
            if server_id in {t['server'] for t in ctx.decrypt(row['blob'])['targets']}:
                raise HTTPException(409,'Server ist noch in einem offenen Auftrag enthalten')
        with ctx.store.transaction():
            ctx.store.execute('DELETE FROM app_sites WHERE server=?',(server_id,))
            ctx.store.execute('DELETE FROM app_servers WHERE id=?',(server_id,))
        ctx.audit(user['name'],'server_deleted',server_id)
        return {'ok':True}

    @app.post('/api/servers/{server_id}/test')
    async def test_server(server_id:str,request:Request):
        user=ctx.auth.identity(request,'servers.manage')
        ctx.auth.require_scope(user,server_id)
        values=await ctx.collection(server_id,'/sites')
        return {'ok':True,'site_count':len(values)}

    @app.post('/api/servers/{server_id}/radius/test')
    async def test_radius(server_id:str,request:Request):
        user=ctx.auth.identity(request,'servers.manage')
        ctx.auth.require_scope(user,server_id)
        ctx.server(server_id)
        sites=ctx.store.query('SELECT site FROM app_sites WHERE server=? AND internal_reference IS NOT NULL ORDER BY site LIMIT 1',(server_id,))
        if not sites:
            raise HTTPException(409,'Für den RADIUS-Verbindungstest zuerst das Inventar synchronisieren')
        profiles=await ctx.collection(server_id,resource_path(sites[0]['site'],'radius'))
        return {'ok':True,'profile_count':len(profiles),'site':sites[0]['site'],'adapter':'classic-local-api'}

    @app.post('/api/inventory/sync')
    async def sync(data:SyncInput,request:Request):
        user=ctx.auth.identity(request,'view')
        ids=data.servers if data.servers is not None else [s['id'] for s in ctx.servers(user) if s['enabled']]
        if len(ids)>100 or len(set(ids))!=len(ids):
            raise HTTPException(422,'Serverauswahl ist ungültig')
        for server_id in ids:
            ctx.auth.require_scope(user,server_id)
            ctx.server(server_id)
        if ctx.sync_task and not ctx.sync_task.done():
            raise HTTPException(409,'Eine Synchronisierung läuft bereits')
        sync_id=secrets.token_hex(12)
        ctx.syncs[sync_id]={'id':sync_id,'state':'queued','completed':0,'total':len(ids),'errors':[],'scope':ids}
        ctx.sync_task=ctx.spawn(ctx.sync_inventory(ids,sync_id))
        ctx.audit(user['name'],'inventory_sync',str(len(ids))+' Server')
        return {'id':sync_id,'state':'queued'}

    @app.get('/api/inventory/sync/{sync_id}')
    async def sync_status(sync_id:str,request:Request):
        user=ctx.auth.identity(request,'view')
        result=ctx.syncs.get(sync_id)
        if not result:
            raise HTTPException(404,'Synchronisierung unbekannt')
        for server_id in result.get('scope',[]):
            ctx.auth.require_scope(user,server_id)
        return {k:v for k,v in result.items() if k!='scope'}

    @app.get('/api/inventory')
    async def inventory(request:Request,search:str='',server:str='',tag:str='',offset:int=Query(0,ge=0),limit:int=Query(100,ge=1,le=200)):
        user=ctx.auth.identity(request,'view')
        terms=[];args=[]
        if '*' not in user['scope']:
            if not user['scope']:
                return {'items':[],'total':0,'offset':offset,'limit':limit}
            terms.append('server IN ('+','.join('?' for _ in user['scope'])+')');args.extend(user['scope'])
        if server:
            ctx.auth.require_scope(user,server)
            terms.append('server=?');args.append(server)
        if search:
            if len(search)>128:
                raise HTTPException(422,'Suchbegriff zu lang')
            terms.append("(name LIKE ? ESCAPE '\\' OR site LIKE ? ESCAPE '\\')")
            escaped=search.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
            args.extend(['%'+escaped+'%']*2)
        if tag:
            terms.append('EXISTS (SELECT 1 FROM json_each(app_sites.tags) WHERE json_each.value=?)');args.append(tag)
        where=' WHERE '+' AND '.join(terms) if terms else ''
        total=ctx.store.one('SELECT COUNT(*) n FROM app_sites'+where,args)['n']  # nosec B608 # Filter clauses are fixed SQL; all request values are bound.
        rows=ctx.store.query('SELECT * FROM app_sites'+where+' ORDER BY name,server,site LIMIT ? OFFSET ?',args+[limit,offset])  # nosec B608 # Filter clauses are fixed SQL; request values and pagination are bound.
        return {'items':[r|{'tags':json.loads(r['tags'])} for r in rows],'total':total,'offset':offset,'limit':limit}

    @app.patch('/api/inventory/{server_id}/{site_id}')
    async def tags(server_id:str,site_id:str,data:TagsInput,request:Request):
        user=ctx.auth.identity(request,'plan');ctx.auth.require_scope(user,server_id)
        values=sorted(set(t.strip() for t in data.tags))
        if any(not v or len(v)>64 for v in values):
            raise HTTPException(422,'Tags müssen 1–64 Zeichen enthalten')
        if not ctx.store.one('SELECT site FROM app_sites WHERE server=? AND site=?',(server_id,site_id)):
            raise HTTPException(404,'Site nicht im Katalog')
        ctx.store.execute('UPDATE app_sites SET tags=? WHERE server=? AND site=?',(json.dumps(values),server_id,site_id))
        ctx.audit(user['name'],'site_tags_changed',server_id+':'+site_id)
        return {'tags':values}

    @app.get('/api/servers/{server_id}/sites')
    async def server_sites(server_id:str,request:Request):
        user=ctx.auth.identity(request,'view');ctx.auth.require_scope(user,server_id)
        values=await ctx.collection(server_id,'/sites')
        return [{'id':v['id'],'name':v.get('name',v['id'])} for v in values]

    @app.get('/api/servers/{server_id}/sites/{site_id}/{kind}')
    async def objects(server_id:str,site_id:str,kind:str,request:Request):
        user=ctx.auth.identity(request,'view');ctx.auth.require_scope(user,server_id)
        if kind=='radius-profiles':
            values=await ctx.collection(server_id,f'/sites/{segment(site_id)}/radius/profiles')
            return [{'id':v['id'],'name':v.get('name',v['id'])} for v in values]
        values=await ctx.collection(server_id,resource_path(site_id,kind))
        if kind=='network':
            values=[v for v in values if v.get('management')=='UNMANAGED']
        return redact(values)

    @app.get('/api/servers/{server_id}/sites/{site_id}/{kind}/{object_id}')
    async def object_detail(server_id:str,site_id:str,kind:str,object_id:str,request:Request):
        user=ctx.auth.identity(request,'view');ctx.auth.require_scope(user,server_id)
        value=await ctx.request(server_id,'GET',resource_path(site_id,kind,object_id))
        if kind=='network' and value.get('management')!='UNMANAGED':
            raise HTTPException(422,'Nur VLANs ohne UniFi-Routing unterstützt')
        return redact(value)

    @app.get('/api/templates')
    async def templates(request:Request):
        ctx.auth.identity(request,'view')
        return [{k:r[k] for k in ('id','name','kind','operation','creator','created')} | {'patch':redact(ctx.decrypt(r['blob']))} for r in ctx.store.query('SELECT * FROM app_templates ORDER BY name')]

    @app.post('/api/templates')
    async def add_template(data:TemplateInput,request:Request):
        user=ctx.auth.identity(request,'plan')
        try:
            validate_patch(data.kind,data.patch,data.operation)
        except ValueError:
            raise HTTPException(422,'Vorlage enthält ungültige Felder oder Werte') from None
        template_id=secrets.token_hex(12)
        ctx.store.execute('INSERT INTO app_templates VALUES(?,?,?,?,?,?,?)',(template_id,data.name,data.kind,data.operation,user['name'],time.time(),ctx.encrypt(data.patch)))
        ctx.audit(user['name'],'template_created',template_id)
        return {'id':template_id,'name':data.name}

    @app.delete('/api/templates/{template_id}')
    async def delete_template(template_id:str,request:Request):
        user=ctx.auth.identity(request,'plan')
        ctx.store.execute('DELETE FROM app_templates WHERE id=?',(template_id,))
        ctx.audit(user['name'],'template_deleted',template_id)
        return {'ok':True}

    def job_where(user):
        if '*' in user['scope']:
            return '',[]
        if not user['scope']:
            return ' WHERE 0',[]
        return ' WHERE NOT EXISTS (SELECT 1 FROM batch_scope s WHERE s.job=batch_jobs.id AND s.server NOT IN ('+','.join('?' for _ in user['scope'])+'))',user['scope']  # nosec B608 # Only placeholder count is generated; scope values are bound by callers.

    @app.post('/api/jobs')
    async def plan(data:Plan,request:Request):
        user=ctx.auth.identity(request,'plan')
        patch=data.patch
        if data.template_id:
            template=ctx.store.one('SELECT * FROM app_templates WHERE id=?',(data.template_id,))
            if not template or template['kind']!=data.kind or template['operation']!=data.operation:
                raise HTTPException(422,'Vorlage passt nicht zur Änderung')
            from app.contract import deep_merge
            patch=deep_merge(ctx.decrypt(template['blob']),patch)
        if data.operation not in ('create','update','delete'):
            raise HTTPException(422,'Unbekannte Operation')
        try:
            validation_patch=patch
            if data.radius_selector and data.kind=='wifi' and isinstance(patch.get('securityConfiguration'),dict):
                from app.contract import deep_merge
                validation_patch=deep_merge(patch,{'securityConfiguration':{'radiusConfiguration':{'profileId':'00000000-0000-0000-0000-000000000001','nasId':{'type':'DERIVED','source':'DEVICE_MAC_ADDRESS'}}}})
            validate_patch(data.kind,validation_patch,data.operation)
        except ValueError:
            raise HTTPException(422,'Änderung enthält ungültige Felder oder Werte') from None
        if data.operation!='create' and any(not t.object for t in data.targets) and not (data.selector.name or data.selector.all):
            raise HTTPException(422,'Konfigurationsname oder ausdrückliche Auswahl aller Objekte erforderlich')
        keys={(t.server,t.site,t.object) for t in data.targets}
        if len(keys)!=len(data.targets):
            raise HTTPException(422,'Doppelte Ziele')
        recipe=data.model_dump(exclude={'kind','operation','reason','template_id'}) | {'patch':patch}
        return create_job(ctx,user,recipe,data.kind,data.operation,data.reason)

    @app.get('/api/jobs')
    async def jobs(request:Request,offset:int=Query(0,ge=0),limit:int=Query(25,ge=1,le=100)):
        user=ctx.auth.identity(request,'view')
        where,args=job_where(user)
        total=ctx.store.one('SELECT COUNT(*) n FROM batch_jobs'+where,args)['n']  # nosec B608 # job_where supplies fixed SQL and placeholders; scope values are bound.
        rows=ctx.store.query('SELECT * FROM batch_jobs'+where+' ORDER BY created DESC LIMIT ? OFFSET ?',args+[limit,offset])  # nosec B608 # Fixed SQL and placeholders; scope values and pagination are bound.
        return {'items':[summary(ctx,r) for r in rows],'total':total,'offset':offset,'limit':limit}

    @app.get('/api/jobs/{job_id}')
    async def job(job_id:str,request:Request,offset:int=Query(0,ge=0),limit:int=Query(100,ge=1,le=200)):
        user=ctx.auth.identity(request,'view');row=job_row(ctx,job_id);check_scope(ctx,user,row)
        return detail(ctx,row,offset,limit)

    @app.post('/api/jobs/{job_id}/approve')
    async def approve(job_id:str,request:Request):
        user=ctx.auth.identity(request,'approve');row=job_row(ctx,job_id);check_scope(ctx,user,row)
        if row['state']!='planned' or row['creator']==user['name'] or not row['ready_at'] or time.time()-row['ready_at']>ctx.config.preview_ttl:
            raise HTTPException(409,'Auftrag muss aktuell geplant sein und durch eine andere Person freigegeben werden')
        ctx.store.execute("UPDATE batch_jobs SET state='approved',approver=?,approved_at=? WHERE id=?",(user['name'],time.time(),job_id))
        ctx.audit(user['name'],'plan_approved',job_id)
        return {'ok':True}

    @app.post('/api/jobs/{job_id}/execute')
    async def execute(job_id:str,request:Request,data:Schedule|None=None):
        user=ctx.auth.identity(request,'execute');row=job_row(ctx,job_id);check_scope(ctx,user,row)
        if not ctx.config.writes:
            raise HTTPException(403,'Schreibzugriffe sind vom Betreiber gesperrt')
        if row['state']!='approved':
            raise HTTPException(409,'Auftrag ist nicht freigegeben')
        from app.jobs import current_user
        current_user(ctx,row['creator'],'plan')
        run_after=data.run_after if data else None
        if run_after is not None and (run_after<time.time()-60 or run_after>row['ready_at']+ctx.config.preview_ttl):
            raise HTTPException(422,'Wartungsfenster muss innerhalb der Gültigkeit der Vorschau liegen')
        recipe=ctx.decrypt(row['blob']);recipe['executor']=user['name']
        ctx.store.execute("UPDATE batch_jobs SET state='queued',run_after=?,blob=? WHERE id=?",(run_after,ctx.encrypt(recipe),job_id))
        ctx.audit(user['name'],'execution_queued',job_id)
        return summary(ctx,job_row(ctx,job_id))

    @app.post('/api/jobs/{job_id}/resume')
    async def resume(job_id:str,request:Request):
        user=ctx.auth.identity(request,'execute');row=job_row(ctx,job_id);check_scope(ctx,user,row)
        if row['state']!='paused':
            raise HTTPException(409,'Nur ein nach Pilotzielen pausierter Auftrag kann fortgesetzt werden')
        recipe=ctx.decrypt(row['blob']);recipe['executor']=user['name']
        ctx.store.execute("UPDATE batch_jobs SET state='queued',run_after=NULL,blob=? WHERE id=?",(ctx.encrypt(recipe),job_id))
        ctx.audit(user['name'],'execution_resumed',job_id)
        return {'ok':True}

    @app.post('/api/jobs/{job_id}/cancel')
    async def cancel(job_id:str,request:Request):
        user=ctx.auth.identity(request,'plan');row=job_row(ctx,job_id);check_scope(ctx,user,row)
        if row['state'] not in ACTIVE:
            raise HTTPException(409,'Auftrag ist bereits beendet')
        ctx.store.execute("UPDATE batch_jobs SET cancel_requested=1,state=CASE WHEN state IN ('running','planning') THEN state ELSE 'cancelled' END WHERE id=?",(job_id,))
        ctx.audit(user['name'],'job_cancelled',job_id)
        return {'ok':True}

    @app.post('/api/jobs/{job_id}/rollback')
    async def rollback(job_id:str,request:Request):
        user=ctx.auth.identity(request,'plan');row=job_row(ctx,job_id)
        return inverse_job(ctx,user,row)

    @app.post('/api/jobs/{job_id}/retry')
    async def retry(job_id:str,request:Request):
        user=ctx.auth.identity(request,'plan');row=job_row(ctx,job_id);recipe=check_scope(ctx,user,row)
        if row['state'] not in ('stopped','cancelled','interrupted','planning_failed') or row['operation']=='restore':
            raise HTTPException(409,'Dieser Auftrag kann nicht erneut geplant werden')
        targets=[]
        for target in ctx.store.query("SELECT * FROM batch_targets WHERE job=? AND status IN ('pending','failed','conflict','planning_failed') ORDER BY idx",(job_id,)):
            targets.append({'server':target['server'],'site':target['site'],'object':target['object']})
        if not targets:
            raise HTTPException(409,'Keine sicher erneut planbaren Ziele; unklare Ergebnisse müssen am Controller geprüft werden')
        recipe['targets']=list({(t['server'],t['site'],t['object']):t for t in targets}.values())
        return create_job(ctx,user,recipe,row['kind'],row['operation'],'Erneute Planung von '+job_id,row['id'])

    @app.get('/api/jobs/{job_id}/export')
    async def export_job(job_id:str,request:Request):
        user=ctx.auth.identity(request,'view');row=job_row(ctx,job_id);check_scope(ctx,user,row)
        result=detail(ctx,row,0,20000)
        ctx.audit(user['name'],'job_exported',job_id)
        return JSONResponse(result,headers={'Content-Disposition':f'attachment; filename="job-{job_id}.json"'})

    @app.get('/api/audit')
    async def audit(request:Request,offset:int=Query(0,ge=0),limit:int=Query(100,ge=1,le=200)):
        user=ctx.auth.identity(request,'audit.export')
        if '*' not in user['scope']:
            raise HTTPException(403,'Das zentrale Audit-Protokoll erfordert einen globalen Berechtigungsbereich')
        return {'items':ctx.store.query('SELECT * FROM app_audit ORDER BY seq DESC LIMIT ? OFFSET ?',(limit,offset)),
                'total':ctx.store.one('SELECT COUNT(*) n FROM app_audit')['n'],'offset':offset,'limit':limit}

    @app.get('/api/audit/verify')
    async def verify_audit(request:Request):
        user=ctx.auth.identity(request,'audit.export')
        if '*' not in user['scope']:
            raise HTTPException(403,'Das zentrale Audit-Protokoll erfordert einen globalen Berechtigungsbereich')
        import hashlib
        import hmac
        previous='0'*64;count=0
        for row in ctx.store.query('SELECT * FROM app_audit ORDER BY seq'):
            encoded=json.dumps([row['timestamp'],row['actor'],row['action'],row['detail'],previous],separators=(',',':')).encode()
            digest=hashlib.sha256(encoded).hexdigest()
            sig=hmac.new(ctx.audit_key,digest.encode(),hashlib.sha256).hexdigest()
            if row['previous']!=previous or not hmac.compare_digest(row['hash'],digest) or not hmac.compare_digest(row['signature'],sig):
                return {'valid':False,'seq':row['seq'],'checked':count}
            count+=1;previous=digest
        return {'valid':True,'checked':count,'head':previous}

    @app.get('/api/audit/export')
    async def export_audit(request:Request,after:int=Query(0,ge=0),limit:int=Query(10000,ge=1,le=50000)):
        user=ctx.auth.identity(request,'audit.export')
        if '*' not in user['scope']:
            raise HTTPException(403,'Das zentrale Audit-Protokoll erfordert einen globalen Berechtigungsbereich')
        ctx.audit(user['name'],'audit_exported',str(after))
        rows=ctx.store.query('SELECT * FROM app_audit WHERE seq>? ORDER BY seq LIMIT ?',(after,limit))
        return JSONResponse({'items':rows,'next':rows[-1]['seq'] if rows else after},headers={'Content-Disposition':'attachment; filename="audit.json"'})

    return app


def app_factory():
    return create_app()
