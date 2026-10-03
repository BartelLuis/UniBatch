'use strict';
const $ = id => document.getElementById(id);
const labels = {dashboard:'Übersicht',workspace:'Sites & Änderungen',jobs:'Aufträge & Freigaben',templates:'Vorlagen',servers:'UniFi OS Server',identity:'Benutzer & Rollen',directory:'LDAP / Active Directory',audit:'Audit-Protokoll',account:'Mein Konto'};
const states = {planning:'Vorschau wird erstellt',planned:'Freigabe ausstehend',planning_failed:'Planung fehlgeschlagen',approved:'Freigegeben',queued:'In Warteschlange',running:'Wird ausgeführt',paused:'Canary-Prüfung',completed:'Abgeschlossen',stopped:'Gestoppt',cancelled:'Abgebrochen',interrupted:'Unterbrochen',pending:'Ausstehend',unchanged:'Unverändert',applied:'Angewendet',conflict:'Konflikt',failed:'Fehlgeschlagen',uncertain:'Ergebnis unklar',online:'Verbunden',offline:'Nicht erreichbar',unknown:'Nicht geprüft',disabled:'Deaktiviert'};
const permissions = {'view':'Konfigurationen ansehen','plan':'Änderungen planen','approve':'Aufträge freigeben','execute':'Aufträge ausführen','users.manage':'Benutzer und Verzeichnis verwalten','roles.manage':'Rollen verwalten','servers.manage':'Server und Inventar verwalten','audit.export':'Audit exportieren'};
const activeStates = new Set(['planning','running','queued']);
const kindLabels = {wifi:'WLAN',network:'VLAN',radius:'RADIUS-Profil'};
function kindLabel(kind){return kindLabels[kind]||kind;}
function kindIcon(kind){return {wifi:'wifi',network:'network',radius:'radius'}[kind]||'folder';}
const roleLabels = {admin:'Administrator',operator:'Operator',approver:'Freigabeberechtigt',viewer:'Leseberechtigt'};
const events = {login:'Anmeldung',logout:'Abmeldung',login_failed:'Anmeldung abgewiesen',user_created:'Benutzer angelegt',user_updated:'Benutzer geändert',role_created:'Rolle angelegt',role_updated:'Rolle geändert',role_deleted:'Rolle gelöscht',password_changed:'Passwort geändert',directory_updated:'Verzeichnisanbindung geändert',directory_authorization_denied:'Verzeichniszugriff entzogen',directory_role_changed:'Verzeichnisrolle geändert',server_created:'Server hinzugefügt',server_updated:'Server geändert',server_deleted:'Server entfernt',inventory_sync:'Inventar synchronisiert',site_tags_changed:'Site-Tags geändert',template_created:'Vorlage gespeichert',template_deleted:'Vorlage gelöscht',plan_created:'Änderung geplant',planning_finished:'Vorschau erstellt',plan_approved:'Auftrag freigegeben',execution_queued:'Ausführung eingeplant',execution_started:'Ausführung gestartet',execution_resumed:'Rollout fortgesetzt',execution_finished:'Ausführung beendet',target_applied:'Änderung angewendet',target_failed:'Ziel fehlgeschlagen',job_cancelled:'Auftrag abgebrochen',job_exported:'Auftrag exportiert',audit_exported:'Audit exportiert',pilot_cancelled_for_restore:'Pilotlauf für Rücknahme beendet'};
const iconPaths = {
  server:['M4 3h16v7H4z','M4 14h16v7H4z','M7 6.5h.01','M7 17.5h.01','M11 6.5h6','M11 17.5h6'],
  wifi:['M2 8.8a17 17 0 0 1 20 0','M5 12a12 12 0 0 1 14 0','M8.5 15.5a6 6 0 0 1 7 0','M12 19h.01'],
  network:['M9 3h6v5H9z','M2 16h6v5H2z','M16 16h6v5h-6z','M12 8v4','M5 16v-4h14v4'],
  radius:['M7 12V7a5 5 0 0 1 10 0v5','M5 12h14v9H5z','M12 16v2'],
  activity:['M3 12h4l3-8 4 16 3-8h4'],
  arrow:['M5 12h14','m13 6 6 6-6 6'],
  check:['m5 12 4 4L19 6'],
  close:['m6 6 12 12','M18 6 6 18'],
  refresh:['M20 7v5h-5','M4 17v-5h5','M6 7a7 7 0 0 1 11-2l3 3','M18 17a7 7 0 0 1-11 2l-3-3'],
  edit:['m15 4 5 5','M4 20h4L21 7a2.1 2.1 0 0 0-4-4L4 16z'],
  trash:['M3 6h18','M9 6V3h6v3','m5 6 1 15h12l1-15','M10 10v7','M14 10v7'],
  download:['M12 3v12','m7 10 5 5 5-5','M5 16v5h14v-5'],
  shield:['m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6z','m8 12 3 3 5-6'],
  warning:['M12 3 2 21h20z','M12 9v5','M12 17h.01'],
  info:['M12 8h.01','M12 11v6','M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0'],
  folder:['M3 5h6l2 3h10v12H3z'],
  user:['M16 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0','M4 21v-2a8 8 0 0 1 16 0v2'],
  tag:['M3 3h8l10 10-8 8L3 11z','M7 7h.01'],
  calendar:['M4 5h16v16H4z','M4 10h16','M8 3v4','M16 3v4'],
  eye:['M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12','M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0'],
  more:['M5 12h.01','M12 12h.01','M19 12h.01'],
};
const selection = new Map();
let me=null, currentView='dashboard', servers=[], templates=[], roles=[], sitePage=[], siteOffset=0, siteTotal=0, jobOffset=0, auditOffset=0;
let editorMode='guided', selectedTemplate=null, selectedJob=null, targetOffset=0, pollTimer=null, editingServer=null, editingUser=null, editingDirectoryUser=false, editingRole=null, syncTimer=null;
let serverRadiusPasswordSet=false,serverRadiusUsername='';
const pageSize=50, targetPageSize=25;
const compactNavigation=window.matchMedia('(max-width: 900px)');
function el(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);if(cls)n.className=cls;return n;}
function option(value,label){const n=el('option',label);n.value=value;return n;}
function icon(name,cls='icon'){
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 24 24');svg.setAttribute('fill','none');svg.setAttribute('stroke','currentColor');svg.setAttribute('stroke-width','1.7');svg.setAttribute('stroke-linecap','round');svg.setAttribute('stroke-linejoin','round');svg.setAttribute('aria-hidden','true');svg.setAttribute('class',cls);
  for(const data of iconPaths[name]||iconPaths.info){const path=document.createElementNS(svg.namespaceURI,'path');path.setAttribute('d',data);svg.append(path);}return svg;
}
function empty(node,text,title='Keine Einträge vorhanden',kind='folder',action=null){
  const state=el('div',undefined,'empty-state');state.append(icon(kind,'icon empty-icon'),el('strong',title,'empty-title'),el('p',text,'empty-description'));if(action)state.append(action);node.replaceChildren(state);
}
function decorateButton(b,name){if(b.querySelector('svg')||!name)return;const label=el('span',b.textContent,'button-label');b.replaceChildren(icon(name,'icon button-icon'),label);}
function actionIcon(text){if(/entfernen|löschen/i.test(text))return 'trash';if(/bearbeiten/i.test(text))return 'edit';if(/synchronisieren|aktualisieren/i.test(text))return 'refresh';if(/export/i.test(text))return 'download';if(/freigeben|prüfen|speichern/i.test(text))return 'check';if(/abbrechen|schließen/i.test(text))return 'close';if(/ansehen|details/i.test(text))return 'eye';if(/tags|taggen/i.test(text))return 'tag';if(/fortsetzen|ausführen|öffnen|verwenden/i.test(text))return 'arrow';return null;}
function button(text,action,cls){const b=el('button',text,cls);b.type='button';decorateButton(b,actionIcon(text));b.addEventListener('click',()=>perform(b,action));return b;}
function time(value){if(!value)return '—';const d=new Date(typeof value==='number'?value*1000:value);return Number.isNaN(d.getTime())?'—':d.toLocaleString('de-DE');}
function serverName(id){return servers.find(s=>s.id===id)?.name||id;}
function key(site){return site.server+'\u0000'+(site.site||site.id);}
function can(permission){return Boolean(me?.permissions?.includes(permission));}
function badge(state){return el('span',states[state]||state||'Unbekannt','badge '+(['failed','planning_failed','uncertain','conflict','interrupted','offline'].includes(state)?'error':['paused','stopped','planned'].includes(state)?'warning':['planning','running','queued','approved'].includes(state)?'info':['pending','cancelled','unknown','disabled','unchanged'].includes(state)?'neutral':'success'));}
function notice(message,error=false){const node=$('notice'),dismiss=el('button',undefined,'notice-dismiss');dismiss.type='button';dismiss.setAttribute('aria-label','Hinweis schließen');dismiss.append(icon('close'));dismiss.onclick=()=>node.replaceChildren();node.replaceChildren(icon(error?'warning':'check','icon notice-icon'),el('span',message,'notice-content'),dismiss);node.classList.toggle('error',error);}
async function api(path,options={}){
  const response=await fetch('/api'+path,{...options,credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':me?.csrf||'',...options.headers}});
  let data;
  if(response.status===204)data={};else try{data=await response.json();}catch{throw Error('Die Serverantwort konnte nicht gelesen werden.');}
  if(!response.ok){if(response.status===401)showLogin();const detail=typeof data.detail==='string'?data.detail:Array.isArray(data.detail)?data.detail.map(x=>x.msg).join('; '):data.message;throw Error(detail||'Anfrage fehlgeschlagen (HTTP '+response.status+').');}
  return data;
}
const send=(path,method,body)=>api(path,{method,body:body===undefined?undefined:JSON.stringify(body)});
function items(data){return Array.isArray(data)?data:data.items||[];}
async function perform(control,action){const wasDisabled=control?.disabled;if(control){control.disabled=true;control.setAttribute('aria-busy','true');}try{return await action();}catch(error){notice(error.message,true);}finally{if(control?.isConnected){control.disabled=wasDisabled||false;control.setAttribute('aria-busy','false');if(!control.disabled&&document.activeElement===document.body)control.focus({preventScroll:true});}}}
function bindForm(id,action){$(id).addEventListener('submit',event=>{event.preventDefault();perform(event.submitter,action);});}
function applyPermissions(){document.querySelectorAll('[data-permission]').forEach(n=>{n.hidden=!n.dataset.permission.split(',').some(can)||n.hasAttribute('data-global')&&!me.scope?.includes('*');});document.querySelectorAll('.nav-group').forEach(group=>group.hidden=!Array.from(group.querySelectorAll('[data-view]')).some(button=>!button.hidden));}
function setNavigation(open){
  const wasOpen=document.body.classList.contains('sidebar-open');open=Boolean(open&&me&&compactNavigation.matches);document.body.classList.toggle('sidebar-open',open);$('mobile-menu-toggle')?.setAttribute('aria-expanded',String(open));if($('sidebar-backdrop'))$('sidebar-backdrop').hidden=!open;$('content').inert=open;if($('app-sidebar'))$('app-sidebar').inert=!me||(compactNavigation.matches&&!open);
  if(open)$('sidebar-close')?.focus({preventScroll:true});else if(wasOpen&&compactNavigation.matches)$('mobile-menu-toggle')?.focus({preventScroll:true});
}
function showLogin(){me=null;clearTimeout(pollTimer);clearTimeout(syncTimer);document.body.classList.remove('is-authenticated');setNavigation(false);$('authenticated').hidden=true;$('login-view').hidden=false;$('logout').hidden=true;$('user').textContent='';selection.clear();selectedJob=null;resetTemplate();resetGuided();$('patch').value='{}';document.querySelectorAll('input[type="password"]').forEach(i=>i.value='');}
async function showApp(){
  me=await api('/me');$('login-view').hidden=true;$('authenticated').hidden=false;$('logout').hidden=false;
  document.body.classList.add('is-authenticated');$('user').textContent=me.name;if($('user-avatar'))$('user-avatar').textContent=me.name.replace(/^ad:/,'').slice(0,2).toUpperCase();if($('header-user-role'))$('header-user-role').textContent=roleLabels[me.role]||me.role;$('demo-login').hidden=!me.demo;
  const mode=$('mode'),detail=el('div',undefined,'mode-copy');mode.dataset.mode=me.demo?'demo':me.writes?'production':'preview';detail.append(el('strong',me.demo?'SIMULATION':me.writes?'Produktivbetrieb':'Vorschau-Modus','mode-title'),el('span',me.demo?'12 Server · 1.200 Sites · Änderungen wirken ausschließlich auf den Simulator.':me.writes?'Lokale UniFi API · Vier-Augen-Freigabe und Driftprüfung aktiv.':'Schreibzugriffe sind in der Betriebskonfiguration gesperrt.','mode-description'));mode.replaceChildren(icon(me.demo?'info':'shield','icon mode-icon'),detail,el('span',me.demo?'Demo-Umgebung':me.writes?'Ausführung aktiv':'Nur Vorschau','mode-pill'));
  applyPermissions();await Promise.all([loadServers(),loadTemplates()]);await view('dashboard');
}
async function view(name){
  if(!me||!labels[name])return;
  currentView=name;setNavigation(false);document.querySelectorAll('.action-menu[open]').forEach(menu=>menu.open=false);clearTimeout(pollTimer);document.querySelectorAll('.view').forEach(v=>v.hidden=v.id!==name);document.querySelectorAll('nav [data-view]').forEach(b=>{b.classList.toggle('active',b.dataset.view===name);if(b.dataset.view===name)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');});$('breadcrumb').textContent=labels[name];document.title=labels[name]+' · UniFi Batch';
  const section=$(name);section.inert=true;section.setAttribute('aria-busy','true');
  try{
    if(name==='dashboard')await loadDashboard();if(name==='workspace')await loadSites();if(name==='jobs')await loadJobs();if(name==='templates')await loadTemplates();if(name==='servers')await loadServers();if(name==='identity')await loadIdentity();if(name==='directory')await loadDirectory();if(name==='audit')await loadAudit();
    if(name==='account'){$('account-info').textContent=me.name+' · Rolle '+me.role+' · Serverzugriff: '+(me.scope?.includes('*')?'alle Server':(me.scope||[]).map(serverName).join(', '));$('password-form').hidden=me.name.startsWith('ad:');}
  }finally{section.inert=false;section.setAttribute('aria-busy','false');}
}
document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>perform(b,()=>view(b.dataset.view))));
document.querySelectorAll('[data-go]').forEach(b=>b.addEventListener('click',()=>perform(b,()=>view(b.dataset.go))));
$('mobile-menu-toggle')?.addEventListener('click',()=>setNavigation(!document.body.classList.contains('sidebar-open')));
$('sidebar-close')?.addEventListener('click',()=>setNavigation(false));$('sidebar-backdrop')?.addEventListener('click',()=>setNavigation(false));
compactNavigation.addEventListener('change',()=>setNavigation(false));
document.addEventListener('keydown',event=>{
  if(event.key==='Escape'&&!document.querySelector('dialog.app-dialog[open]')){setNavigation(false);document.querySelectorAll('.action-menu[open]').forEach(menu=>{menu.open=false;menu.querySelector('summary')?.focus();});}
  if(event.key==='Tab'&&document.body.classList.contains('sidebar-open')){const focusable=Array.from($('app-sidebar').querySelectorAll('a[href],button:not([disabled])')).filter(node=>node.getClientRects().length&& !node.closest('[hidden]'));const first=focusable[0],last=focusable[focusable.length-1];if(event.shiftKey&&document.activeElement===first){event.preventDefault();last?.focus();}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first?.focus();}}
});
document.addEventListener('click',event=>document.querySelectorAll('.action-menu[open]').forEach(menu=>{if(!menu.contains(event.target))menu.open=false;}));
document.querySelectorAll('thead th').forEach(th=>th.setAttribute('scope','col'));
document.querySelectorAll('.view .title-row button,.view .form-actions button,#logout').forEach(b=>decorateButton(b,actionIcon(b.textContent)));
bindForm('login-form',async()=>{await send('/login','POST',{name:$('username').value.trim(),password:$('password').value});$('password').value='';$('notice').replaceChildren();await showApp();});
$('logout').addEventListener('click',()=>perform($('logout'),async()=>{await send('/logout','POST');showLogin();notice('Abgemeldet.');}));
function pager(node,offset,total,size,load){
  const label=el('span',total?((offset+1)+'–'+Math.min(offset+size,total)+' von '+total.toLocaleString('de-DE')):'0 Einträge');
  const controls=el('div'),prev=button('Zurück',()=>load(Math.max(0,offset-size))),next=button('Weiter',()=>load(offset+size));prev.disabled=offset===0;next.disabled=offset+size>=total;controls.append(prev,next);node.replaceChildren(label,controls);
}
function connectionOverview(){
  const enabled=servers.filter(s=>s.enabled!==false),online=enabled.filter(s=>s.status==='online').length,offline=enabled.filter(s=>s.status==='offline').length,unknown=enabled.length-online-offline;
  if($('connection-summary'))$('connection-summary').textContent=enabled.length?online+' / '+enabled.length+' Server verbunden':'Keine aktiven Server';
  if($('connection-indicator'))$('connection-indicator').dataset.status=offline?'error':unknown?'neutral':enabled.length?'success':'neutral';
  return {enabled:enabled.length,online,offline,unknown};
}
async function loadServers(){
  servers=items(await api('/servers'));const old=$('site-server').value;$('site-server').replaceChildren(option('','Alle Server'),...servers.map(s=>option(s.id,s.name)));$('site-server').value=old;$('server-list').replaceChildren();
  for(const s of servers){
    const card=el('article',undefined,'panel server-card'),head=el('div',undefined,'server-card-header'),identity=el('div',undefined,'server-card-title'),title=el('div');title.append(el('h2',s.name),el('small',s.id));identity.append(icon('server','icon server-avatar'),title);head.append(identity,badge(s.enabled===false?'disabled':s.status||'unknown'));card.append(head,el('p',s.origin,'server-origin'));
    const facts=el('dl',undefined,'server-facts');for(const [label,value] of [['Sites',Number(s.site_count||0).toLocaleString('de-DE')],['Synchronisiert',time(s.last_sync)]]){const fact=el('div');fact.append(el('dt',label),el('dd',value));facts.append(fact);}card.append(facts);
    const technical=el('details',undefined,'server-technical');technical.append(el('summary','Verbindungsdetails'),el('p',s.api_prefix,'job-meta'),el('p',s.radius_legacy_enabled?'RADIUS-Verwaltung: '+(s.radius_auth_mode==='local_account'?'lokales UniFi OS Konto':'lokaler API-Schlüssel'):'RADIUS-Verwaltung nicht aktiviert','job-meta'));card.append(technical);if(s.error)card.append(el('p',s.error,'error-text'));
    const actions=el('div',undefined,'form-actions'),menu=el('details',undefined,'action-menu'),toggle=el('summary'),menuItems=el('div',undefined,'action-menu-list');toggle.append(icon('more'),el('span','Weitere Aktionen'));toggle.setAttribute('aria-label','Weitere Aktionen für '+s.name);menu.append(toggle,menuItems);actions.append(button('Bearbeiten',()=>editServer(s)),menu);
    menuItems.append(button('API-Verbindung prüfen',async()=>{const result=await send('/servers/'+encodeURIComponent(s.id)+'/test','POST');notice('Lokale API erreichbar: '+result.site_count+' Sites auf '+s.name+'.');await loadServers();}),button('Synchronisieren',()=>startSync([s.id])));
    if(s.radius_supported||me.demo)menuItems.append(button('RADIUS-Verbindung prüfen',async()=>{const result=await send('/servers/'+encodeURIComponent(s.id)+'/radius/test','POST');notice('Lokale RADIUS-API erreichbar: '+result.profile_count+' Profile auf der geprüften Site von '+s.name+'.');await loadServers();}));
    menuItems.append(button(s.enabled===false?'Aktivieren':'Deaktivieren',async()=>{await send('/servers/'+encodeURIComponent(s.id),'PATCH',{enabled:s.enabled===false});await loadServers();notice('Serverstatus aktualisiert.');}));
    menuItems.append(button('Entfernen',async()=>{if(!await UI.confirm({title:'Server entfernen',message:'Die Verbindung zu „'+s.name+'“ wird aus der Verwaltung entfernt.',confirmLabel:'Server entfernen',danger:true}))return;await send('/servers/'+encodeURIComponent(s.id),'DELETE');await loadServers();notice('Server entfernt.');},'small danger'));card.append(actions);$('server-list').append(card);
  }connectionOverview();if(!servers.length)empty($('server-list'),'Verbinden Sie einen UniFi OS Server über seine lokale API.','Noch keine Server verbunden','server',can('servers.manage')?button('Server hinzufügen',()=>openServer(),'primary'):null);
}
function configureServerRadius(){
  const enabled=$('server-radius-enabled').checked,local=enabled&&$('server-radius-auth-mode').value==='local_account';$('server-radius-auth-label').hidden=!enabled;$('server-radius-auth-mode').disabled=!enabled;$('server-radius-credentials').hidden=!local;
  $('server-radius-username').disabled=!local;$('server-radius-username').required=local;$('server-radius-password').disabled=!local;$('server-radius-password').required=local&&(!serverRadiusPasswordSet||$('server-radius-username').value.trim()!==serverRadiusUsername);
  $('server-radius-password-note').textContent=serverRadiusPasswordSet?'Passwort gespeichert. Bei unverändertem Konto leer lassen, um es beizubehalten.':'Für dieses lokale Konto ist noch kein Passwort gespeichert.';
}
function editServer(s){editingServer=s.id;$('server-editor').hidden=false;$('server-form-title').textContent='Server bearbeiten: '+s.name;$('server-id').value=s.id;$('server-id').disabled=true;$('server-name').value=s.name;$('server-origin').value=s.origin;$('server-prefix').value=s.api_prefix;$('server-key').value='';$('server-ca').value=s.ca_file||'';$('server-enabled').checked=s.enabled!==false;$('server-radius-enabled').checked=Boolean(s.radius_legacy_enabled);$('server-radius-auth-mode').value=s.radius_auth_mode||'api_key';$('server-radius-username').value=s.radius_username||'';$('server-radius-password').value='';serverRadiusPasswordSet=Boolean(s.has_radius_password);serverRadiusUsername=s.radius_username||'';configureServerRadius();$('server-form').scrollIntoView({behavior:'smooth',block:'center'});$('server-name').focus();}
function resetServer(){editingServer=null;$('server-form').reset();serverRadiusPasswordSet=false;serverRadiusUsername='';$('server-radius-password').value='';$('server-id').disabled=false;$('server-form-title').textContent='Server hinzufügen';configureServerRadius();}
function openServer(){resetServer();$('server-editor').hidden=false;$('server-editor').scrollIntoView({behavior:'smooth',block:'start'});$('server-id').focus({preventScroll:true});}
$('server-reset').onclick=openServer;
$('server-radius-enabled').onchange=configureServerRadius;$('server-radius-auth-mode').onchange=configureServerRadius;$('server-radius-username').oninput=configureServerRadius;
$('server-cancel')?.addEventListener('click',()=>{resetServer();$('server-editor').hidden=true;$('server-reset').focus();});
bindForm('server-form',async()=>{const data={name:$('server-name').value.trim(),origin:$('server-origin').value.trim(),api_prefix:$('server-prefix').value.trim(),ca_file:$('server-ca').value.trim()||null,radius_legacy_enabled:$('server-radius-enabled').checked,radius_auth_mode:$('server-radius-auth-mode').value};if(data.radius_legacy_enabled&&data.radius_auth_mode==='local_account'){data.radius_username=$('server-radius-username').value.trim();if($('server-radius-password').value)data.radius_password=$('server-radius-password').value;}if($('server-key').value)data.key=$('server-key').value;if(editingServer)data.enabled=$('server-enabled').checked;else{data.id=$('server-id').value.trim();if(!data.key)throw Error('Zum Hinzufügen ist ein lokaler API-Schlüssel erforderlich.');}await send('/servers'+(editingServer?'/'+encodeURIComponent(editingServer):''),editingServer?'PATCH':'POST',data);if(!editingServer&&!$('server-enabled').checked)await send('/servers/'+encodeURIComponent(data.id),'PATCH',{enabled:false});resetServer();$('server-editor').hidden=true;await loadServers();notice('Server gespeichert. Inventar synchronisieren, um seine Sites einzulesen.');});
async function startSync(ids){
  const task=await send('/inventory/sync','POST',ids?{servers:ids}:{});notice('Inventarsynchronisation gestartet.');clearTimeout(syncTimer);
  const poll=async()=>{if(!me)return;try{const result=await api('/inventory/sync/'+encodeURIComponent(task.id));if(['running','queued','pending'].includes(result.state)){notice('Inventar wird synchronisiert: '+(result.completed||0)+' / '+(result.total||ids?.length||servers.length)+' Server');syncTimer=setTimeout(poll,2000);return;}const errors=result.errors;const errorCount=Array.isArray(errors)?errors.length:Object.keys(errors||{}).length;notice('Inventar synchronisiert.'+(errorCount?' '+errorCount+' Server mit Fehlern; Serverstatus prüfen.':''),Boolean(errorCount));await loadServers();if(currentView==='workspace')await loadSites();if(currentView==='dashboard')await loadDashboard();}catch(e){notice(e.message,true);}};await poll();
}
$('sync-all').onclick=()=>perform($('sync-all'),()=>startSync());
$('sync-inventory').onclick=()=>perform($('sync-inventory'),()=>startSync($('site-server').value?[$('site-server').value]:undefined));
async function loadDashboard(){
  const [stats,jobs]=await Promise.all([api('/stats'),api('/jobs?limit=5&offset=0')]);$('metric-servers').textContent=stats.servers??servers.length;$('metric-sites').textContent=Number(stats.sites||0).toLocaleString('de-DE');
  const st=stats.states||{},active=(st.planning||0)+(st.running||0)+(st.queued||0),health=connectionOverview();$('metric-active').textContent=active;$('metric-approval').textContent=st.planned||0;$('active-job-count').textContent=active?String(active):'';$('metric-servers-note').textContent=health.online+' verbunden · '+health.enabled+' aktiv';
  const serverGrid=el('div',undefined,'server-overview');
  for(const s of servers){const card=el('div',undefined,'server-overview-card'),identity=el('div',undefined,'server-identity'),name=el('div');name.append(el('strong',s.name),el('small',s.id));identity.append(icon('server','icon server-avatar'),name);const footer=el('div',undefined,'server-overview-footer');footer.append(el('span',Number(s.site_count||0).toLocaleString('de-DE')+' Sites'),badge(s.enabled===false?'disabled':s.status||'unknown'));card.append(identity,footer);card.title='Letzte Synchronisation: '+time(s.last_sync);serverGrid.append(card);}
  const summary=el('div',undefined,'server-overview-summary');summary.append(el('span',health.online+' verbunden','connection-good'),el('span',health.offline+' nicht erreichbar',health.offline?'error-text':''),el('span',health.unknown+' nicht geprüft'));
  $('dashboard-servers').replaceChildren(summary,serverGrid);
  const activity=el('div',undefined,'activity-list');
  for(const j of items(jobs)){const row=el('div',undefined,'activity-row'),left=el('div',undefined,'activity-copy');left.append(el('div',j.reason||j.id,'row-name'),el('div',kindLabel(j.kind)+' · '+time(j.created)+' · '+j.creator,'row-meta'));const right=el('div',undefined,'activity-actions');right.append(badge(j.state),button('Öffnen',async()=>{selectedJob=j.id;targetOffset=0;await view('jobs');},'small'));row.append(icon(kindIcon(j.kind),'icon activity-icon'),left,right);activity.append(row);} $('dashboard-jobs').replaceChildren(activity);
  if(!servers.length)empty($('dashboard-servers'),'Fügen Sie einen lokalen UniFi OS Server hinzu, um sein Inventar einzulesen.','Keine Server vorhanden','server');if(!items(jobs).length)empty($('dashboard-jobs'),'Bereiten Sie eine WLAN-, VLAN- oder RADIUS-Änderung vor. Vorschau und Freigabe begleiten jeden Rollout.','Noch keine Änderungen geplant','activity',can('plan')?button('Änderung vorbereiten',()=>view('workspace'),'primary'):null);
}
$('refresh-dashboard').onclick=()=>perform($('refresh-dashboard'),async()=>{await loadServers();await loadDashboard();});
function siteQuery(offset=siteOffset,limit=pageSize){const p=new URLSearchParams({offset:String(offset),limit:String(limit)});if($('site-search').value.trim())p.set('search',$('site-search').value.trim());if($('site-server').value)p.set('server',$('site-server').value);if($('site-tag').value.trim())p.set('tag',$('site-tag').value.trim());return '?'+p.toString();}
async function loadSites(offset=siteOffset){siteOffset=offset;const result=await api('/inventory'+siteQuery());sitePage=items(result);siteTotal=result.total??sitePage.length;renderSites();}
function renderSites(){
  $('site-rows').replaceChildren(...sitePage.map(s=>{
    const tr=el('tr'),choose=el('td',undefined,'check-cell'),check=el('input');check.type='checkbox';check.checked=selection.has(key(s));check.setAttribute('aria-label',s.name+' auswählen');check.addEventListener('change',()=>{if(check.checked)selection.set(key(s),s);else selection.delete(key(s));renderSelection();tr.classList.toggle('selected',check.checked);});choose.append(check);tr.classList.toggle('selected',check.checked);
    const name=el('td');name.append(el('strong',s.name),el('small',serverName(s.server)+' · '+(s.site||s.id)));const tags=el('td'),list=el('div',undefined,'tag-list');(s.tags||[]).forEach(tag=>list.append(el('span',tag,'tag')));tags.append(list);const action=el('td');action.append(button('Ansehen',()=>inspectSite(s),'small'));if(can('servers.manage'))action.append(button('Tags',()=>editTags(s),'small'));tr.append(choose,name,tags,action);return tr;
  }));
  if(!sitePage.length){const tr=el('tr'),td=el('td',siteTotal?'Keine Sites auf dieser Seite.':'Keine Sites gefunden. Inventar synchronisieren oder Suchfilter ändern.','empty');td.colSpan=4;tr.append(td);$('site-rows').append(tr);}pager($('site-pager'),siteOffset,siteTotal,pageSize,loadSites);renderSelection();
}
function renderSelection(){
  $('target-count').textContent=selection.size.toLocaleString('de-DE')+' ausgewählt';$('selected-summary').textContent='Ausgewählte Sites ('+selection.size.toLocaleString('de-DE')+')';
  const list=Array.from(selection.entries()).slice(0,100);$('selected-targets').replaceChildren(...list.map(([id,s])=>{const row=el('div',undefined,'selected-line');row.append(el('span',s.name+' · '+serverName(s.server)),button('Entfernen',()=>{selection.delete(id);renderSites();}));return row;}));if(selection.size>100)$('selected-targets').append(el('p','Weitere '+(selection.size-100)+' Sites ausgewählt.','help'));
  const count=sitePage.filter(s=>selection.has(key(s))).length;$('select-page').checked=Boolean(sitePage.length)&&count===sitePage.length;$('select-page').indeterminate=count>0&&count<sitePage.length;
}
bindForm('site-search-form',()=>loadSites(0));
$('select-page').onchange=()=>{sitePage.forEach(s=>{$('select-page').checked?selection.set(key(s),s):selection.delete(key(s));});renderSites();};
$('clear-selection').onclick=()=>{selection.clear();renderSites();notice('Site-Auswahl geleert.');};
$('select-matching').onclick=()=>perform($('select-matching'),async()=>{
  const p=new URLSearchParams(siteQuery(0,100));let offset=0,total;do{p.set('offset',String(offset));const result=await api('/inventory?'+p.toString());const page=items(result);page.forEach(s=>selection.set(key(s),s));total=result.total??page.length;offset+=page.length;if(!page.length)break;}while(offset<total);renderSites();notice(total.toLocaleString('de-DE')+' Suchtreffer ausgewählt. '+selection.size.toLocaleString('de-DE')+' Sites insgesamt.');
});
$('tag-selection').onclick=()=>perform($('tag-selection'),async()=>{
  if(!selection.size)throw Error('Zuerst Sites auswählen.');const raw=await UI.prompt({title:'Sites gemeinsam taggen',message:'Neue Tags werden auf '+selection.size.toLocaleString('de-DE')+' ausgewählten Sites ergänzt. Vorhandene Tags bleiben erhalten.',label:'Tags',placeholder:'Berlin, Verwaltungsstandort',confirmLabel:'Tags ergänzen'});if(raw===null)return;const tags=[...new Set(raw.split(',').map(t=>t.trim()).filter(Boolean))];if(!tags.length)throw Error('Mindestens einen Tag eingeben.');const selected=Array.from(selection.values());let cursor=0,changed=0,failed=0;await Promise.all(Array.from({length:4},async()=>{while(cursor<selected.length){const s=selected[cursor++],merged=[...new Set([...(s.tags||[]),...tags])];try{await send('/inventory/'+encodeURIComponent(s.server)+'/'+encodeURIComponent(s.site||s.id),'PATCH',{tags:merged});selection.set(key(s),{...s,tags:merged});changed++;}catch{failed++;}}}));await loadSites();notice('Tags auf '+changed+' Sites ergänzt.'+(failed?' '+failed+' Sites fehlgeschlagen; Serverzugriff und Tag-Anzahl prüfen.':''),Boolean(failed));
});
async function editTags(s){const raw=await UI.prompt({title:'Site-Tags bearbeiten',message:s.name+' · '+serverName(s.server),label:'Tags, durch Komma getrennt',value:(s.tags||[]).join(', '),placeholder:'Berlin, Verwaltungsstandort',required:false});if(raw===null)return;const tags=[...new Set(raw.split(',').map(x=>x.trim()).filter(Boolean))];await send('/inventory/'+encodeURIComponent(s.server)+'/'+encodeURIComponent(s.site||s.id),'PATCH',{tags});if(selection.has(key(s)))selection.set(key(s),{...s,tags});await loadSites();notice('Tags gespeichert.');}
async function inspectSite(s){
  const n=$('site-inspector');n.hidden=false;n.replaceChildren(el('h3',s.name+' · '+serverName(s.server)),el('p','Konfigurationen werden über die lokale UniFi API geladen.','help'));
  const base='/servers/'+encodeURIComponent(s.server)+'/sites/'+encodeURIComponent(s.site||s.id);
  const radiusEnabled=me.demo||Boolean(servers.find(server=>server.id===s.server)?.radius_legacy_enabled);
  const [wifi,vlans,profiles,radius]=await Promise.all([api(base+'/wifi'),api(base+'/network'),api(base+'/radius-profiles'),radiusEnabled?api(base+'/radius').catch(error=>({items:[],error:error.message})):null]);n.replaceChildren(el('h3',s.name+' · '+serverName(s.server)));
  const groups=[['wifi',wifi],['network',vlans]];if(radius)groups.push(['radius',radius]);
  for(const [kind,data] of groups){n.append(el('h3',{wifi:'WLANs',network:'VLANs',radius:'RADIUS-Profile'}[kind]));if(data.error){n.append(el('p',data.error,'callout danger'));continue;}const objects=items(data);if(!objects.length)n.append(el('p','Keine Konfigurationen vorhanden.','help'));for(const obj of objects){const detail=el('details'),summary=el('summary',obj.name+(obj.vlanId?' · VLAN '+obj.vlanId:''));detail.dataset.kind=kind;detail.append(summary,el('pre',JSON.stringify(obj,null,2)),button('Als Ziel verwenden',()=>{$('kind').value=kind;$('operation').value='update';$('object-name').value=obj.name;selection.set(key(s),s);resetTemplate();configureForm();renderSites();notice(kindLabel(kind)+' und Site ausgewählt. Weitere Sites können hinzugefügt werden.');},'small'));n.append(detail);}}
  if(!radiusEnabled)n.append(el('p','Die RADIUS-Profilverwaltung ist für diesen Server nicht aktiviert. Sie kann in den Servereinstellungen eingerichtet werden.','help'));
  n.append(el('h3','RADIUS-Zuordnung für WLAN'));if(!items(profiles).length)n.append(el('p','Keine RADIUS-Profile für WLAN verfügbar.','help'));for(const profile of items(profiles)){const row=el('div',undefined,'row');row.append(el('span',profile.name,'row-name'),button('Für WLAN übernehmen',()=>{$('kind').value='wifi';resetTemplate();$('wifi-radius-name').value=profile.name;configureForm();notice('RADIUS-Profilname übernommen. Das Profil wird auf jeder ausgewählten Site separat ermittelt.');},'small'));n.append(row);}n.append(button('Schließen',()=>{n.hidden=true;}));n.scrollIntoView({behavior:'smooth',block:'nearest'});
}
function radiusGroup(family){return family==='auth'?{list:'radius-auth-servers',replace:'radius-auth-replace',add:'radius-auth-add',label:'Authentifizierungsserver',port:1812}:{list:'radius-acct-servers',replace:'radius-acct-replace',add:'radius-acct-add',label:'Accounting-Server',port:1813};}
function renameRadiusRows(family){const group=radiusGroup(family);Array.from($(group.list).children).forEach((row,index)=>{row.querySelector('.radius-endpoint-title').textContent=group.label+' '+(index+1);});}
function addRadiusEndpoint(family,value={}){
  const group=radiusGroup(family),list=$(group.list);if(list.children.length>=8){notice('Je Serverliste sind höchstens acht RADIUS-Server möglich.',true);return null;}
  const row=el('div',undefined,'radius-endpoint'),heading=el('div',undefined,'radius-endpoint-heading'),remove=button('Entfernen',()=>{row.remove();renameRadiusRows(family);configureForm();},'small');remove.dataset.radiusRemove=family;remove.setAttribute('aria-label',group.label+' entfernen');heading.append(el('strong',group.label,'radius-endpoint-title'),remove);row.append(heading);
  const fields=el('div',undefined,'radius-endpoint-fields');
  for(const [field,label] of [['host','IPv4-Adresse'],['port','Port'],['sharedSecret','Shared Secret']]){
    const wrapper=el('label',label),input=el('input');input.dataset.field=field;input.required=true;
    if(field==='host'){input.type='text';input.inputMode='decimal';input.placeholder='10.20.30.40';input.maxLength=15;input.pattern='(?:[0-9]{1,3}\\.){3}[0-9]{1,3}';input.value=value.host||'';}
    if(field==='port'){input.type='number';input.min='1';input.max='65535';input.step='1';input.value=value.port??group.port;}
    if(field==='sharedSecret'){input.type='password';input.autocomplete='new-password';input.minLength=1;input.maxLength=128;input.placeholder='Shared Secret eingeben';input.value=value.sharedSecret||'';}
    wrapper.append(input);fields.append(wrapper);
  }
  row.append(fields);list.append(row);renameRadiusRows(family);return row;
}
function configureRadiusFields(active,create){
  const accounting=$('radius-accounting-enabled').value,auth=$('radius-auth-replace'),acct=$('radius-acct-replace');
  if(active&&create)auth.checked=true;auth.disabled=!active||create;
  $('radius-accounting-group').hidden=create&&accounting!=='true';
  if(active&&create)acct.checked=accounting==='true';acct.disabled=!active||create;
  for(const family of ['auth','acct']){
    const group=radiusGroup(family),enabled=active&&$(group.replace).checked&&(family!=='acct'||!$('radius-accounting-group').hidden);
    if(enabled&&create&&!$(group.list).children.length)addRadiusEndpoint(family);
    $(group.list).hidden=!$(group.replace).checked;$(group.add).hidden=!$(group.replace).checked;$(group.add).disabled=!enabled||$(group.list).children.length>=8;
    $(group.list).querySelectorAll('input').forEach(input=>{input.disabled=!enabled;input.required=enabled;});$(group.list).querySelectorAll('[data-radius-remove]').forEach(remove=>remove.disabled=!enabled);
  }
  $('radius-accounting-enabled').disabled=!active;$('radius-vlan-assignment').disabled=!active;
  const accountingDisabled=accounting==='false'||create&&accounting!=='true';$('radius-interim-enabled').disabled=!active||accountingDisabled;$('radius-accounting-interval').disabled=!active||accountingDisabled||$('radius-interim-enabled').value==='false';$('radius-accounting-interval').placeholder=create?'600 (Standard)':'Unverändert';
}
function radiusServerValues(family,validate=true){
  const group=radiusGroup(family),rows=Array.from($(group.list).children);if(validate&&family==='auth'&&!rows.length)throw Error('Mindestens einen Authentifizierungsserver angeben.');
  return rows.map(row=>{const host=row.querySelector('[data-field="host"]').value.trim(),port=Number(row.querySelector('[data-field="port"]').value),sharedSecret=row.querySelector('[data-field="sharedSecret"]').value;if(validate){if(!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(host)||host.split('.').some(octet=>Number(octet)>255))throw Error('RADIUS-Server benötigen eine gültige IPv4-Adresse.');if(!Number.isInteger(port)||port<1||port>65535)throw Error('RADIUS-Ports müssen zwischen 1 und 65535 liegen.');if(!sharedSecret||sharedSecret.length>128)throw Error('Für jeden RADIUS-Server ein Shared Secret mit 1 bis 128 Zeichen angeben.');}return {host,port,sharedSecret};});
}
function resetRadius(){for(const id of ['radius-accounting-enabled','radius-interim-enabled','radius-accounting-interval','radius-vlan-assignment'])$(id).value='';$('radius-auth-replace').checked=false;$('radius-acct-replace').checked=false;$('radius-auth-servers').replaceChildren();$('radius-acct-servers').replaceChildren();}
function clearConfigurationSecrets(){document.querySelectorAll('#guided-editor input[type="password"]').forEach(input=>input.value='');$('patch').value=selectedTemplate?JSON.stringify(selectedTemplate.patch,null,2):'{}';}
for(const family of ['auth','acct'])$(radiusGroup(family).replace).onchange=()=>{const group=radiusGroup(family);if($(group.replace).checked&&!$(group.list).children.length)addRadiusEndpoint(family);configureForm();};
$('radius-accounting-enabled').onchange=()=>{if($('radius-accounting-enabled').value==='false')$('radius-interim-enabled').value='false';configureForm();};$('radius-interim-enabled').onchange=configureForm;
for(const family of ['auth','acct'])$(radiusGroup(family).add).onclick=()=>{addRadiusEndpoint(family);configureForm();};
function configureForm(){
  const kind=$('kind').value,wifi=kind==='wifi',network=kind==='network',radius=kind==='radius',create=$('operation').value==='create',del=$('operation').value==='delete';$('wifi-fields').hidden=!wifi;$('network-fields').hidden=!network;$('selector-label').hidden=create;$('object-name').required=!create;
  $('radius-fields').hidden=!radius;configureRadiusFields(radius&&editorMode==='guided'&&!selectedTemplate&&!del,create);
  $('selector-kind-label').textContent='Vorhandenes '+kindLabel(kind)+' – exakter Name';$('config-section-title').textContent={wifi:'WLAN-Einstellungen',network:'VLAN-Einstellungen',radius:'RADIUS-Einstellungen'}[kind];$('config-name-label').textContent=wifi?'Neuer Name / SSID':'Neuer Profilname';if(network)$('config-name-label').textContent='Neuer VLAN-Name';
  $('wifi-network-label').hidden=!wifi||del;
  const enterprise=$('wifi-security').value.includes('ENTERPRISE');$('wifi-passphrase-label').hidden=enterprise;$('wifi-passphrase').disabled=enterprise;$('wifi-radius-label').hidden=!wifi||del;$('wifi-radius-name').required=wifi&&enterprise&&editorMode==='guided'&&!selectedTemplate&&!del;$('wifi-enterprise-mode-label').hidden=!wifi||del||$('wifi-security').value!=='WPA3_ENTERPRISE'||editorMode!=='guided'||Boolean(selectedTemplate);
  $('config-name').maxLength=wifi?32:128;
  $('config-name').required=create&&editorMode==='guided'&&!selectedTemplate;$('config-name').placeholder=create?{wifi:'SSID für das neue WLAN',network:'Name des neuen VLANs',radius:'Name des neuen RADIUS-Profils'}[kind]:'Bei Änderungen optional';$('edit-config').hidden=del;$('delete-warning').hidden=!del;
  $('wifi-security').required=create&&wifi&&editorMode==='guided'&&!selectedTemplate;$('wifi-passphrase').required=create&&wifi&&!enterprise&&editorMode==='guided'&&!selectedTemplate;$('vlan-id').required=create&&network&&editorMode==='guided'&&!selectedTemplate;
  $('guided-editor').hidden=editorMode!=='guided';$('json-editor').hidden=editorMode!=='json';$('guided-tab').classList.toggle('active',editorMode==='guided');$('json-tab').classList.toggle('active',editorMode==='json');$('patch').readOnly=Boolean(selectedTemplate);
}
function guidedPatch(validate=true){
  const patch={};const name=$('config-name').value.trim();if($('kind').value==='wifi'&&new TextEncoder().encode(name).length>32)throw Error('Eine WLAN-SSID darf höchstens 32 UTF-8-Bytes lang sein.');if(name)patch.name=name;
  if($('kind').value==='network'){if($('vlan-id').value)patch.vlanId=Number($('vlan-id').value);if($('operation').value==='create')Object.assign(patch,{management:'UNMANAGED',enabled:true});return patch;}
  if($('kind').value==='radius'){
    if($('radius-auth-replace').checked)patch.authenticationServers=radiusServerValues('auth',validate);if($('radius-acct-replace').checked&&!$('radius-accounting-group').hidden)patch.accountingServers=radiusServerValues('acct',validate);
    for(const [id,field] of [['radius-accounting-enabled','accountingEnabled'],['radius-interim-enabled','accountingInterimEnabled']])if($(id).value)patch[field]=$(id).value==='true';
    if($('radius-accounting-interval').value)patch.accountingInterimIntervalSeconds=Number($('radius-accounting-interval').value);if($('radius-vlan-assignment').value)patch.vlanAssignmentMode=$('radius-vlan-assignment').value;return patch;
  }
  for(const [id,field] of [['wifi-enabled','enabled'],['wifi-hidden','hideName'],['wifi-isolation','clientIsolationEnabled']])if($(id).value)patch[field]=$(id).value==='true';
  const security=$('wifi-security').value,enterprise=security.includes('ENTERPRISE'),secret=enterprise?'':$('wifi-passphrase').value;if(security||secret){patch.securityConfiguration={};if(security)patch.securityConfiguration.type=security;if(secret)patch.securityConfiguration.passphrase=secret;if(security.includes('WPA3_PERSONAL'))patch.securityConfiguration.saeConfiguration={anticloggingThresholdSeconds:5,syncTimeSeconds:5};if(security.startsWith('WPA2_WPA3_'))Object.assign(patch.securityConfiguration,{pmfMode:'OPTIONAL',wpa3FastRoamingEnabled:false});if(enterprise)patch.securityConfiguration.coaEnabled=false;if(security==='WPA3_ENTERPRISE')patch.securityConfiguration.securityMode=$('wifi-enterprise-mode').value;}return patch;
}
function getPatch(){if($('operation').value==='delete'||selectedTemplate)return {};if(editorMode==='guided')return guidedPatch();let patch;try{patch=JSON.parse($('patch').value);}catch{throw Error('Bitte gültiges JSON eingeben.');}if(!patch||typeof patch!=='object'||Array.isArray(patch))throw Error('Die Konfiguration muss ein JSON-Objekt sein.');return patch;}
function resetTemplate(){if(selectedTemplate){$('patch').value='{}';resetGuided();editorMode='guided';}$('template-select').value='';selectedTemplate=null;$('patch').readOnly=false;}
function resetGuided(){for(const id of ['config-name','wifi-enabled','wifi-hidden','wifi-isolation','wifi-security','wifi-passphrase','wifi-network-name','wifi-radius-name','vlan-id'])$(id).value='';$('wifi-enterprise-mode').value='DEFAULT';resetRadius();}
function applyTemplate(id){const t=templates.find(x=>x.id===id);if(!t){resetTemplate();configureForm();return;}selectedTemplate=t;$('template-select').value=t.id;$('kind').value=t.kind;$('operation').value=t.operation||'update';editorMode='json';$('patch').value=JSON.stringify(t.patch,null,2);resetGuided();configureForm();}
$('kind').onchange=()=>{resetTemplate();if($('kind').value==='radius'&&$('operation').value!=='create'){$('radius-auth-replace').checked=false;$('radius-acct-replace').checked=false;}configureForm();};$('operation').onchange=()=>{resetTemplate();if($('kind').value==='radius'&&$('operation').value!=='create'){$('radius-auth-replace').checked=false;$('radius-acct-replace').checked=false;}configureForm();};$('template-select').onchange=()=>applyTemplate($('template-select').value);
$('wifi-security').onchange=configureForm;
$('json-tab').onclick=()=>perform($('json-tab'),async()=>{if(editorMode==='guided')$('patch').value=JSON.stringify(guidedPatch(false),null,2);editorMode='json';configureForm();});
$('guided-tab').onclick=()=>{
  if(selectedTemplate){notice('Vorlage zuerst abwählen, um eine eigene Konfiguration einzugeben.',true);return;}
  if(editorMode==='json'){let patch;try{patch=JSON.parse($('patch').value);}catch{notice('JSON zuerst korrigieren.',true);return;}
    if(!patch||typeof patch!=='object'||Array.isArray(patch)){notice('Die Konfiguration muss ein JSON-Objekt sein.',true);return;}
    if($('kind').value==='radius'){
      const allowed=new Set(['name','authenticationServers','accountingEnabled','accountingServers','accountingInterimEnabled','accountingInterimIntervalSeconds','vlanAssignmentMode']);
      if(Object.keys(patch).some(key=>!allowed.has(key))||['authenticationServers','accountingServers'].some(key=>key in patch&&(!Array.isArray(patch[key])||patch[key].length>8||patch[key].some(endpoint=>!endpoint||typeof endpoint!=='object'||Object.keys(endpoint).some(field=>!['host','port','sharedSecret'].includes(field))||typeof endpoint.host!=='string'||!Number.isInteger(endpoint.port)||typeof endpoint.sharedSecret!=='string')))||['accountingEnabled','accountingInterimEnabled'].some(key=>key in patch&&typeof patch[key]!=='boolean')||'accountingInterimIntervalSeconds' in patch&&!Number.isInteger(patch.accountingInterimIntervalSeconds)||'vlanAssignmentMode' in patch&&!['disabled','optional','required'].includes(patch.vlanAssignmentMode)){
        notice('Diese RADIUS-Konfiguration kann nicht vollständig in die geführte Eingabe übernommen werden. Bitte im JSON-Editor bearbeiten.',true);return;
      }
      resetGuided();$('config-name').value=patch.name||'';
      for(const [family,key] of [['auth','authenticationServers'],['acct','accountingServers']])if(key in patch){$(radiusGroup(family).replace).checked=true;for(const endpoint of patch[key])addRadiusEndpoint(family,endpoint);}
      for(const [id,key] of [['radius-accounting-enabled','accountingEnabled'],['radius-interim-enabled','accountingInterimEnabled']])if(key in patch)$(id).value=String(patch[key]);$('radius-accounting-interval').value=patch.accountingInterimIntervalSeconds??'';$('radius-vlan-assignment').value=patch.vlanAssignmentMode||'';editorMode='guided';configureForm();return;
    }
    const allowed=new Set(['name','enabled','hideName','clientIsolationEnabled','securityConfiguration','vlanId','management']);
    if(Object.keys(patch).some(k=>!allowed.has(k))||patch.securityConfiguration&&Object.keys(patch.securityConfiguration).some(k=>!['type','passphrase','saeConfiguration','pmfMode','wpa3FastRoamingEnabled','coaEnabled','securityMode'].includes(k))){notice('Diese Konfiguration enthält erweiterte API-Felder. Bitte im JSON-Editor bearbeiten.',true);return;}
    const networkName=$('wifi-network-name').value,radiusName=$('wifi-radius-name').value;resetGuided();$('wifi-network-name').value=networkName;$('wifi-radius-name').value=radiusName;$('config-name').value=patch.name||'';$('vlan-id').value=patch.vlanId??'';for(const [id,field] of [['wifi-enabled','enabled'],['wifi-hidden','hideName'],['wifi-isolation','clientIsolationEnabled']])if(field in patch)$(id).value=String(patch[field]);$('wifi-security').value=patch.securityConfiguration?.type||'';$('wifi-passphrase').value=patch.securityConfiguration?.passphrase||'';$('wifi-enterprise-mode').value=patch.securityConfiguration?.securityMode||'DEFAULT';
  }editorMode='guided';configureForm();
};
bindForm('plan-form',async()=>{
  if(!selection.size)throw Error('Mindestens eine Site auswählen.');
  const patch=getPatch(),data={kind:$('kind').value,operation:$('operation').value,targets:Array.from(selection.values()).map(s=>({server:s.server,site:s.site||s.id})),patch,reason:$('reason').value.trim(),concurrency:Number($('concurrency').value),stop_on_error:$('stop-on-error').checked,canary_count:Number($('canary-count').value)};
  if(data.operation!=='create')data.selector={name:$('object-name').value.trim(),all:false};if(selectedTemplate)data.template_id=selectedTemplate.id;if(data.kind==='wifi'&&data.operation!=='delete'&&$('wifi-network-name').value.trim())data.network_selector=$('wifi-network-name').value.trim();
  if(data.kind==='wifi'&&data.operation!=='delete'&&$('wifi-radius-name').value.trim())data.radius_selector=$('wifi-radius-name').value.trim();
  const job=await send('/jobs','POST',data);clearConfigurationSecrets();selectedJob=job.id;targetOffset=0;notice('Vorschau wird für '+selection.size.toLocaleString('de-DE')+' Sites erstellt.');await view('jobs');
});
$('save-template').onclick=()=>perform($('save-template'),async()=>{if(selectedTemplate)throw Error('Zum Erstellen einer eigenen Vorlage zuerst die aktuelle Vorlage abwählen.');const patch=getPatch(),name=await UI.prompt({title:'Konfiguration als Vorlage speichern',message:'Die vorbereitete '+kindLabel($('kind').value)+'-Änderung kann für spätere Rollouts wiederverwendet werden.',label:'Vorlagenname',placeholder:'z. B. Standard-WLAN Verwaltung',confirmLabel:'Vorlage speichern'});if(!name?.trim())return;await send('/templates','POST',{name:name.trim(),kind:$('kind').value,operation:$('operation').value,patch});clearConfigurationSecrets();await loadTemplates();notice('Vorlage gespeichert.');});
async function loadTemplates(){
  templates=items(await api('/templates'));const old=$('template-select').value;$('template-select').replaceChildren(option('','Ohne Vorlage'),...templates.map(t=>option(t.id,t.name+' · '+kindLabel(t.kind))));$('template-select').value=old;
  $('template-list').replaceChildren(...templates.map(t=>{const card=el('article',undefined,'panel template-card'),head=el('div',undefined,'server-card-title');head.append(icon(kindIcon(t.kind),'icon server-avatar'),el('h2',t.name));card.append(head,el('p',kindLabel(t.kind)+' · '+({create:'Anlegen',update:'Ändern',delete:'Löschen'}[t.operation]||'Ändern'),'job-meta'));const config=el('details',undefined,'template-config');config.append(el('summary','Konfiguration ansehen'),el('pre',JSON.stringify(t.patch,null,2)));card.append(config);const actions=el('div',undefined,'form-actions');if(can('plan'))actions.append(button('Verwenden',async()=>{applyTemplate(t.id);await view('workspace');},'primary'),button('Löschen',async()=>{if(!await UI.confirm({title:'Vorlage löschen',message:'Die gespeicherte Vorlage „'+t.name+'“ wird gelöscht.',confirmLabel:'Vorlage löschen',danger:true}))return;await send('/templates/'+encodeURIComponent(t.id),'DELETE');await loadTemplates();notice('Vorlage gelöscht.');},'danger'));card.append(actions);return card;}));if(!templates.length)empty($('template-list'),'Speichern Sie eine vorbereitete WLAN-, VLAN- oder RADIUS-Änderung als Vorlage für wiederkehrende Rollouts.','Noch keine Vorlagen','folder',can('plan')?button('Vorlage vorbereiten',()=>view('workspace'),'primary'):null);
}
function scheduleJobsPolling(active){clearTimeout(pollTimer);if(currentView==='jobs'&&active)pollTimer=setTimeout(()=>perform(null,loadJobs),2500);}
async function loadJobs(offset=jobOffset){
  jobOffset=offset;const result=await api('/jobs?offset='+jobOffset+'&limit='+pageSize),jobs=items(result);
  $('job-rows').replaceChildren(...jobs.map(j=>{const tr=el('tr'),name=el('td');name.append(el('strong',kindLabel(j.kind)+' · '+({create:'Anlegen',update:'Ändern',delete:'Löschen'}[j.operation]||'Ändern')),el('small',j.reason||j.id));const status=el('td');status.append(badge(j.state));const count=el('td',j.total_targets??j.target_count??j.targets?.length??0);const action=el('td');action.append(button('Details',async()=>{selectedJob=j.id;targetOffset=0;await loadJobDetail();},'small'));tr.append(name,status,count,el('td',j.creator),el('td',time(j.created)),action);return tr;}));
  if(!jobs.length){const tr=el('tr'),td=el('td','Noch keine Aufträge. Eine Änderung unter „Sites & Änderungen“ vorbereiten.','empty');td.colSpan=6;tr.append(td);$('job-rows').append(tr);}pager($('job-pager'),jobOffset,result.total??jobs.length,pageSize,loadJobs);
  let active=jobs.some(j=>activeStates.has(j.state));if(selectedJob){const job=await loadJobDetail();active=active||Boolean(job&&activeStates.has(job.state));}scheduleJobsPolling(active);
}
async function jobAction(job,action,body){
  const result=await send('/jobs/'+encodeURIComponent(job.id)+'/'+action,'POST',body);if(['rollback','retry'].includes(action)&&result.id){selectedJob=result.id;targetOffset=0;}
  notice({approve:'Auftrag freigegeben.',execute:'Ausführung gestartet.',cancel:'Abbruch angefordert. Laufende API-Aufrufe werden abgeschlossen.',rollback:'Vorschau für die Rücknahme erstellt. Erneute Freigabe erforderlich.',retry:'Neue Vorschau für ausstehende oder fehlgeschlagene Ziele erstellt.',resume:'Rollout wird fortgesetzt.'}[action]||'Auftrag aktualisiert.');await loadJobs();
}
async function loadJobDetail(offset=targetOffset){
  if(!selectedJob)return null;targetOffset=offset;const requestedJob=selectedJob,n=$('job-detail');
  const openDetails=Array.from(n.querySelectorAll('details[open]')).map(d=>d.dataset.target);
  const scheduleValue=n.querySelector('input[type="datetime-local"]')?.value;
  const job=await api('/jobs/'+encodeURIComponent(requestedJob)+'?offset='+targetOffset+'&limit='+targetPageSize);if(selectedJob!==requestedJob)return null;n.hidden=false;
  const head=el('div',undefined,'job-header'),left=el('div');left.append(el('h2',kindLabel(job.kind)+' · '+({create:'Anlegen',update:'Ändern',delete:'Löschen'}[job.operation]||'Ändern')),el('p',job.id,'job-meta'));
  const right=el('div');right.append(badge(job.state),button('Schließen',()=>{selectedJob=null;n.hidden=true;},'small'));head.append(left,right);n.replaceChildren(head,el('p',job.reason),el('p','Erstellt: '+job.creator+' · Freigabe: '+(job.approver||'ausstehend')+' · '+time(job.created),'job-meta'));if(job.run_after)n.append(el('p','Geplante Ausführung: '+time(job.run_after),'job-meta'));
  const counts=job.counts||{},total=job.total_targets||job.input_targets||job.targets?.length||0,progress=Object.entries(counts).filter(([k])=>!['pending'].includes(k)).reduce((acc,[,v])=>acc+v,0);const track=el('div',undefined,'progress-track'),bar=el('progress',undefined,'progress-bar');bar.max=Math.max(1,total);bar.value=Math.min(total,progress);bar.setAttribute('aria-label','Fortschritt des Auftrags');track.append(bar);n.append(track);
  const summary=el('div',undefined,'job-progress');summary.append(el('span',total.toLocaleString('de-DE')+' Ziele'));for(const [status,count] of Object.entries(counts))summary.append(el('span',(states[status]||status)+': '+count));n.append(summary);
  if(job.state==='planning_failed'||counts.planning_failed)n.append(el('p','Die Vorschau enthält Fehler. Details prüfen und einen neuen Auftrag für korrigierte Ziele erstellen.','callout danger'));
  if(['interrupted','stopped'].includes(job.state)||counts.uncertain)n.append(el('p','Bereits angewendete Änderungen bleiben bestehen. Unklare Ergebnisse zuerst am UniFi Server prüfen. Eine Rücknahme erstellt eine neue Vorschau und benötigt erneut Freigabe.','callout danger'));
  if(job.state==='paused')n.append(el('p','Die Canary-Ziele wurden ausgeführt. Wirkung auf den Sites prüfen und den verbleibenden Rollout fortsetzen.','callout'));
  if(job.error)n.append(el('p',job.error,'callout danger'));
  const actions=el('div',undefined,'job-actions');
  if(job.state==='planned'&&can('approve')&&job.creator!==me.name)actions.append(button('Geprüften Auftrag freigeben',()=>jobAction(job,'approve'),'primary'));
  if(job.state==='planned'&&can('approve')&&job.creator===me.name)n.append(el('p','Die Freigabe muss durch eine andere Person erfolgen.','help'));
  if(job.state==='approved'&&can('execute')&&(me.writes||me.demo)){
    const schedule=el('label','Ausführung ab (Browser-Ortszeit)'),input=el('input');input.type='datetime-local';input.value=scheduleValue||'';input.setAttribute('aria-label','Ausführung ab');schedule.append(input);actions.append(schedule,button(me.demo?'In Simulation ausführen':'Auftrag ausführen',async()=>{const body={};if(input.value){const d=new Date(input.value);if(d.getTime()<=Date.now())throw Error('Das Ausführungsdatum muss in der Zukunft liegen.');body.run_after=Math.floor(d.getTime()/1000);}if(!await UI.confirm({title:me.demo?'Simulation starten':'Rollout starten',message:'Die freigegebene '+kindLabel(job.kind)+'-Änderung wird auf '+total.toLocaleString('de-DE')+' Zielen '+(input.value?'ab '+new Date(input.value).toLocaleString('de-DE'):'ausgeführt')+'.',confirmLabel:input.value?'Ausführung einplanen':'Ausführung starten'}))return;await jobAction(job,'execute',body);},'primary'));
  }
  if(job.state==='paused'&&can('execute')&&(me.writes||me.demo))actions.append(button('Rollout fortsetzen',()=>jobAction(job,'resume'),'primary'));
  if(['planning','planned','approved','queued','running','paused'].includes(job.state)&&can('execute'))actions.append(button('Auftrag abbrechen',async()=>{if(await UI.confirm({title:'Auftrag abbrechen',message:'Der Auftrag wird gestoppt. Bereits angewendete Änderungen bleiben bestehen; laufende API-Aufrufe werden abgeschlossen.',confirmLabel:'Auftrag abbrechen',danger:true}))await jobAction(job,'cancel');},'danger'));
  if(['completed','stopped','interrupted','cancelled','paused'].includes(job.state)&&can('plan')&&(counts.applied||job.applied))actions.append(button('Rücknahme vorbereiten',()=>jobAction(job,'rollback')));
  if(['stopped','interrupted','cancelled','planning_failed'].includes(job.state)&&can('plan'))actions.append(button('Verbleibende Ziele neu planen',()=>jobAction(job,'retry')));
  actions.append(button('Auftrag exportieren',()=>download('/jobs/'+encodeURIComponent(job.id)+'/export','unifi-auftrag-'+job.id+'.json')));n.append(actions);
  const wrap=el('div',undefined,'table-wrap'),table=el('table'),thead=el('thead'),headRow=el('tr');['Site / Server','Konfiguration','Status','Unterschiede / Ergebnis'].forEach(t=>{const th=el('th',t);th.setAttribute('scope','col');headRow.append(th);});thead.append(headRow);const tbody=el('tbody');
  for(const t of job.targets||[]){const tr=el('tr'),site=el('td');site.append(el('strong',t.site_name||t.site),el('small',serverName(t.server)));const status=el('td');status.append(badge(t.status));const detail=el('td'),d=el('details',undefined,'job-target');d.dataset.target=requestedJob+':'+t.idx;d.open=openDetails.includes(d.dataset.target);d.append(el('summary',t.error?'Fehler prüfen':'Unterschiede prüfen'),el('pre',JSON.stringify(t.diff||{before:t.before,after:t.after},null,2)));if(t.error)d.append(el('p',typeof t.error==='string'?t.error:JSON.stringify(t.error),'error-text'));detail.append(d);tr.append(site,el('td',t.object_name||t.name||t.object||'Neues Objekt'),status,detail);tbody.append(tr);}
  table.append(thead,tbody);wrap.append(table);n.append(wrap);const pagerNode=el('div',undefined,'pager');pager(pagerNode,targetOffset,total,targetPageSize,loadJobDetail);n.append(pagerNode);return job;
}
$('refresh-jobs').onclick=()=>perform($('refresh-jobs'),loadJobs);
function saveDownload(data,filename){const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=el('a');a.href=url;a.download=filename;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);notice('Export erstellt.');}
async function download(path,filename){saveDownload(await api(path),filename);}
async function exportAudit(){let after=0;const rows=[];while(true){const page=await api('/audit/export?after='+after+'&limit=10000');rows.push(...items(page));if(items(page).length<10000||page.next<=after)break;after=page.next;notice('Audit-Export wird erstellt: '+rows.length.toLocaleString('de-DE')+' Einträge');}saveDownload({items:rows},'unifi-audit-'+new Date().toISOString().slice(0,10)+'.json');}
function scopeControls(prefix,scope=['*']){$(prefix+'-scope-all').checked=scope.includes('*');$(prefix+'-scope').replaceChildren(...servers.map(s=>{const label=el('label',undefined,'check-label'),input=el('input');input.type='checkbox';input.value=s.id;input.checked=scope.includes(s.id);label.append(input,el('span',s.name));return label;}));toggleScope(prefix);}
function toggleScope(prefix){$(prefix+'-scope').querySelectorAll('input').forEach(i=>i.disabled=$(prefix+'-scope-all').checked);}
function readScope(prefix){if($(prefix+'-scope-all').checked)return ['*'];const scope=Array.from($(prefix+'-scope').querySelectorAll('input:checked')).map(i=>i.value);if(!scope.length)throw Error('Mindestens einen Server oder „Alle Server“ auswählen.');return scope;}
$('user-scope-all').onchange=()=>toggleScope('user');$('directory-scope-all').onchange=()=>toggleScope('directory');
async function loadIdentity(){
  roles=items(await api('/roles'));$('user-role').replaceChildren(...roles.map(r=>option(r.id,r.name)));
  if(can('users.manage')){const users=items(await api('/users'));$('user-rows').replaceChildren(...users.map(u=>{const tr=el('tr'),name=el('td');name.append(el('strong',u.name));if(u.directory)name.append(el('small','Verzeichniskonto'));const status=el('td');status.append(badge(u.enabled===false?'disabled':'Aktiv'));const action=el('td');action.append(button('Bearbeiten',()=>editUser(u),'small'));tr.append(name,el('td',roles.find(r=>r.id===u.role)?.name||u.role),el('td',u.scope?.includes('*')?'Alle Server':(u.scope||[]).map(serverName).join(', ')),status,action);return tr;}));}
  $('role-list').replaceChildren(...roles.map(r=>{const row=el('div',undefined,'role-row'),text=el('div');text.append(el('strong',r.name),el('small',r.permissions.map(p=>permissions[p]||p).join(' · ')));const action=el('div',undefined,'form-actions');if(r.builtin)action.append(el('span','Systemrolle','badge neutral'));else if(can('roles.manage'))action.append(button('Bearbeiten',()=>editRole(r),'small'),button('Löschen',async()=>{if(!await UI.confirm({title:'Rolle löschen',message:'Die benutzerdefinierte Rolle „'+r.name+'“ wird gelöscht. Zugewiesene Rollen müssen zuvor bei den Konten geändert werden.',confirmLabel:'Rolle löschen',danger:true}))return;await send('/roles/'+encodeURIComponent(r.id),'DELETE');await loadIdentity();notice('Rolle gelöscht.');},'small danger'));row.append(text,action);return row;}));
  $('role-permissions').replaceChildren(...Object.entries(permissions).map(([value,label])=>{const item=el('label',undefined,'check-label'),input=el('input');input.type='checkbox';input.value=value;input.disabled=!can(value);if(value==='view')input.onchange=()=>{input.checked=true;};item.append(input,el('span',label+(value==='view'?' · erforderlich':'')));return item;}));resetUser();resetRole();applyPermissions();
}
function editUser(u){editingUser=u.name;editingDirectoryUser=Boolean(u.directory);$('user-form').hidden=false;$('user-form-title').textContent='Konto bearbeiten: '+u.name;$('user-name').value=u.name;$('user-name').disabled=true;$('user-role').value=u.role;$('user-role').disabled=editingDirectoryUser;$('user-enabled').checked=u.enabled!==false;$('user-enabled').disabled=u.name===me.name;$('user-password').value='';$('user-password').required=false;$('user-password').disabled=editingDirectoryUser;scopeControls('user',u.scope);$('user-form').scrollIntoView({behavior:'smooth',block:'center'});(editingDirectoryUser?$('user-scope-all'):$('user-role')).focus({preventScroll:true});}
function resetUser(){editingUser=null;editingDirectoryUser=false;$('user-form').reset();$('user-form').hidden=true;$('user-form-title').textContent='Lokales Konto erstellen';$('user-name').disabled=false;$('user-role').disabled=false;$('user-enabled').disabled=false;$('user-password').disabled=false;$('user-password').required=true;scopeControls('user');}
$('user-reset').onclick=()=>{resetUser();$('user-form').hidden=false;$('user-form').scrollIntoView({behavior:'smooth',block:'center'});$('user-name').focus({preventScroll:true});};
$('user-cancel')?.addEventListener('click',()=>{resetUser();$('user-reset').focus();});
bindForm('user-form',async()=>{const data={scope:readScope('user')};if(!editingDirectoryUser)data.role=$('user-role').value;if(editingUser)data.enabled=$('user-enabled').checked;else data.name=$('user-name').value.trim();if($('user-password').value)data.password=$('user-password').value;await send('/users'+(editingUser?'/'+encodeURIComponent(editingUser):''),editingUser?'PATCH':'POST',data);$('user-password').value='';await loadIdentity();notice('Benutzerkonto gespeichert.');});
function editRole(r){editingRole=r.id;$('role-form').hidden=false;$('role-form-title').textContent='Rolle bearbeiten: '+r.name;$('role-id').value=r.id;$('role-id').disabled=true;$('role-name').value=r.name;$('role-permissions').querySelectorAll('input').forEach(i=>i.checked=r.permissions.includes(i.value));$('role-form').scrollIntoView({behavior:'smooth',block:'center'});$('role-name').focus({preventScroll:true});}
function resetRole(){editingRole=null;$('role-form').reset();$('role-form').hidden=true;$('role-id').disabled=false;$('role-form-title').textContent='Rolle erstellen';const viewPermission=$('role-permissions').querySelector('input[value="view"]');if(viewPermission)viewPermission.checked=true;}
$('role-reset').onclick=()=>{resetRole();$('role-form').hidden=false;$('role-form').scrollIntoView({behavior:'smooth',block:'center'});$('role-id').focus({preventScroll:true});};
$('role-cancel')?.addEventListener('click',()=>{resetRole();$('role-reset').focus();});
bindForm('role-form',async()=>{const data={name:$('role-name').value.trim(),permissions:Array.from($('role-permissions').querySelectorAll('input:checked')).map(i=>i.value)};if(!editingRole)data.id=$('role-id').value.trim();await send('/roles'+(editingRole?'/'+encodeURIComponent(editingRole):''),editingRole?'PATCH':'POST',data);await loadIdentity();notice('Rolle gespeichert.');});
$('refresh-identity').onclick=()=>perform($('refresh-identity'),loadIdentity);
async function loadDirectory(){
  const [data,roleData]=await Promise.all([api('/directory'),api('/roles')]);roles=items(roleData);$('directory-enabled').checked=data.enabled;$('directory-url').value=data.url||'';$('directory-base').value=data.base_dn||'';$('directory-bind').value=data.bind_dn||'';$('directory-ca').value=data.ca_file||'';$('directory-password').value='';$('directory-user-attribute').value=data.user_attribute||'sAMAccountName';$('directory-object-class').value=data.object_class||'user';$('directory-group-attribute').value=data.group_attribute||'memberOf';$('directory-nested-groups').checked=Boolean(data.nested_ad_groups);$('directory-password-note').textContent=data.bind_password_set?'Bind-Passwort gespeichert. Leer lassen, um es beizubehalten.':'Noch kein Bind-Passwort gespeichert.';
  $('directory-groups').replaceChildren(...roles.map(r=>{const label=el('label',r.name+' ('+r.id+')'),input=el('input');input.dataset.role=r.id;input.value=data.role_groups?.[r.id]||'';input.placeholder='CN=UniFi-'+r.id+',OU=Gruppen,DC=behoerde,DC=intern';label.append(input);return label;}));scopeControls('directory',data.scope||['*']);
}
bindForm('directory-form',async()=>{
  const data={enabled:$('directory-enabled').checked,url:$('directory-url').value.trim(),base_dn:$('directory-base').value.trim(),bind_dn:$('directory-bind').value.trim(),ca_file:$('directory-ca').value.trim(),role_groups:{},scope:readScope('directory'),user_attribute:$('directory-user-attribute').value.trim(),object_class:$('directory-object-class').value.trim(),group_attribute:$('directory-group-attribute').value.trim(),nested_ad_groups:$('directory-nested-groups').checked};$('directory-groups').querySelectorAll('input').forEach(i=>{if(i.value.trim())data.role_groups[i.dataset.role]=i.value.trim();});if($('directory-password').value)data.bind_password=$('directory-password').value;await send('/directory','PUT',data);$('directory-password').value='';await loadDirectory();notice('Verzeichnisanbindung gespeichert.');
});
bindForm('password-form',async()=>{if($('new-password').value!==$('repeat-password').value)throw Error('Die neuen Passwörter stimmen nicht überein.');await send('/password','POST',{current_password:$('current-password').value,password:$('new-password').value});$('password-form').reset();notice('Passwort geändert.');});
async function loadAudit(offset=auditOffset){auditOffset=offset;const result=await api('/audit?offset='+offset+'&limit='+pageSize);$('audit-rows').replaceChildren(...items(result).map(row=>{const tr=el('tr'),event=el('td');event.append(el('strong',events[row.action]||row.action),el('small',row.action,'technical-id'));const reference=el('td',typeof row.detail==='string'?row.detail:JSON.stringify(row.detail),'audit-reference');tr.append(el('td',row.seq,'technical-id'),el('td',time(row.timestamp)),el('td',row.actor),event,reference);return tr;}));if(!items(result).length){const tr=el('tr'),td=el('td','Noch keine Ereignisse protokolliert.','empty');td.colSpan=5;tr.append(td);$('audit-rows').append(tr);}pager($('audit-pager'),offset,result.total??items(result).length,pageSize,loadAudit);}
$('refresh-audit').onclick=()=>perform($('refresh-audit'),loadAudit);$('export-audit').onclick=()=>perform($('export-audit'),exportAudit);
$('verify-audit').onclick=()=>perform($('verify-audit'),async()=>{const result=await api('/audit/verify');notice(result.valid?'Audit-Integrität bestätigt: '+result.checked+' verkettete Einträge geprüft.':'Audit-Integrität verletzt bei Eintrag '+result.seq+'.',!result.valid);});
configureForm();configureServerRadius();
showApp().catch(error=>{if(me)notice(error.message,true);else showLogin();});
