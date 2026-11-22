if(window.AndroidVPN){
 const A=window.AndroidVPN;
 window.vpn_ready=async()=>A.ready();
 window.vpn_toggle=async()=>A.toggle();
 window.vpn_ping=async()=>A.ping();
 window.vpn_openLogFile=async()=>A.shareLog();
 window.vpn_saveSettings=async s=>A.saveSettings(JSON.stringify(s));
 window.vpn_parseLink=async t=>JSON.parse(A.parseLink(t||''));
 document.documentElement.classList.add('android');
}
// Мост к Go: функции привязаны как window.vpn_<имя> и возвращают Promise.
function api(name,...args){const f=window['vpn_'+name];return f?f(...args):Promise.resolve(null)}
const $=id=>document.getElementById(id);
let S=null,form=null,since=0,activePage='home',procs=[],toastTimer=null;
let previousPinging=false,lastProbeOk=null,lastProbeTime=0,lastSessionSince=0,probeHistory=[];
let onboardingShown=false,onboardingDismissed=false,wizardType='socks5',logRows=[],currentTheme='';
const pageInfo={
 home:['Главная','Состояние подключения и быстрые действия'],
 connection:['Подключение','Параметры upstream-прокси и ускорителя'],
 routing:['Маршрутизация','Домены и приложения, которые подключаются напрямую'],
 diagnostics:['Проверка','Измерение реальной задержки через выбранный маршрут'],
 logs:['Журнал','Системные сообщения и события сетевого ядра'],
 settings:['Параметры','Дополнительные параметры работы туннеля'],
 about:['О программе','Версия клиента и информация об обновлениях'],
 mini:['Мини-панель','Компактное управление подключением']
};
function setPage(page){
 if(!pageInfo[page])page='home';
 activePage=page;
 document.querySelectorAll('.view').forEach(v=>v.classList.toggle('active',v.id==='view-'+page));
 document.querySelectorAll('.nav button').forEach(b=>b.classList.toggle('active',b.dataset.page===page));
 $('pageTitle').textContent=pageInfo[page][0];$('pageSubtitle').textContent=pageInfo[page][1];
 if(page==='logs')renderLogs();
 if(page==='diagnostics')renderProbeHistory();
 if(page==='routing')renderApps();
}
window.openMiniPanel=function(){$('app').classList.add('mini-window');setPage('mini')};
window.exitMiniPanel=function(){$('app').classList.remove('mini-window');setPage('home')};
function fmtMs(ms){return ms>0?ms+' мс':'—'}
function fmtDur(sec){const h=Math.floor(sec/3600),m=Math.floor(sec%3600/60),s=sec%60;return (h?String(h).padStart(2,'0')+':':'')+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0')}
function latClass(ms){return !(ms>0)?'':ms<400?'good':ms<900?'mid':'bad'}
function esc(t){const d=document.createElement('div');d.textContent=String(t??'');return d.innerHTML}
function baseName(p){return p.split(/[\\/]/).pop()}
function applyTheme(theme,persist=true){
 const allowed=['violet','ocean','emerald','rose','amber'];
 if(!allowed.includes(theme))theme='violet';
 const previous=currentTheme||'violet';
 currentTheme=theme;
 document.documentElement.dataset.theme=theme;
 document.querySelectorAll('.theme-option').forEach(button=>{
  const active=button.dataset.theme===theme;
  button.classList.toggle('active',active);
  button.setAttribute('aria-pressed',active?'true':'false');
 });
 if(form)form.theme=theme;
 if(S&&S.settings)S.settings.theme=theme;
 if(persist){
  api('saveTheme',theme).then(err=>{
   if(err){
    if(form)form.theme=previous;
    if(S&&S.settings)S.settings.theme=previous;
    applyTheme(previous,false);
    toast('Тема не сохранена',err,false);
   }
  }).catch(e=>{
   if(form)form.theme=previous;
   if(S&&S.settings)S.settings.theme=previous;
   applyTheme(previous,false);
   toast('Тема не сохранена',e.message,false);
  });
 }
}
function toast(t,m,ok){$('toastT').textContent=t;$('toastM').textContent=m||'';$('toast').classList.toggle('ok',!!ok);$('toast').classList.add('show');clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').classList.remove('show'),ok?3000:6500)}
function setStatus(st){
 const app=$('app');app.classList.remove('state-off','state-connecting','state-on');app.classList.add('state-'+st.state);
 app.classList.toggle('locked',st.state!=='off');
 const on=st.state==='on',busy=st.state==='connecting';
 $('status').textContent=on?'Подключено':busy?(st.stopping?'Отключение…':'Подключение…'):'Не защищено';
 $('connectBtn').textContent=on?'Отключить':busy?(st.stopping?'Отключение…':'Подключение…'):'Подключить';
 $('connectBtn').disabled=busy;$('miniToggle').textContent=on?'Отключить':busy?'Подключение…':'Подключить';$('miniToggle').disabled=busy;
 $('sub').textContent=on&&st.since?'Подключено '+fmtDur(Math.max(0,Math.floor(Date.now()/1000-st.since))):busy?(st.step||'Подготовка соединения'):(st.settings.host?'Готово к подключению':'Сначала настройте прокси-сервер');
 $('topStatusText').textContent=on?'Подключено':busy?(st.stopping?'Отключение…':'Подключение…'):'Не подключено';
 $('sideState').textContent=on?'Подключено':busy?'Выполняется операция':'Не подключено';
 $('topStatus').classList.toggle('on',on);$('topStatus').classList.toggle('busy',busy);
 $('topDot').className='dot'+(on?' on':busy?' busy':'');$('sideDot').className='dot'+(on?' on':busy?' busy':'');
 $('ip').textContent=st.ip||'—';$('diagIP').textContent=st.ip||'—';$('miniIP').textContent=st.ip||'—';
 $('pingBtn').disabled=!!st.pinging||!on;$('diagPing').disabled=!!st.pinging||!on;
 since=st.since||0;$('uptime').textContent=on&&since?fmtDur(Math.max(0,Math.floor(Date.now()/1000-since))):'—';
 const s=st.settings||{};
 const selectedTheme=s.theme||'violet';
 if(selectedTheme!==currentTheme)applyTheme(selectedTheme,false);
 $('srv').textContent=s.host?s.host+':'+s.port:'Сервер не настроен';
 $('srvSub').textContent=s.host?(s.username?'Вход: '+s.username:'Без авторизации'):'Добавьте адрес прокси';
 setProfileProtocol(s.proxy_type||'socks5',busy||on||!s.host);
 $('srvAuth').textContent=s.username?'Настроена':'Не задана';
 $('srvAccel').textContent=s.accelerate?'Включено':'Выключено';
 $('srvBypass').textContent=String((s.bypass||'').split(/[\\s,;]+/).filter(Boolean).length);
 $('srvApps').textContent=String((s.bypass_apps||[]).length);
 $('accelStat').textContent=s.accelerate?'Включено':'Выключено';$('accelStat').className='stat-value '+(s.accelerate?'good':'');
 $('q_accel').checked=!!s.accelerate;
 $('q_accel').disabled=busy||st.state!=='off'||!s.host;
 $('quickBypass').textContent=(s.bypass||'').trim()?(s.bypass.split(/[\\s,;]+/).filter(Boolean).length+' доменов'):'Не заданы';
 $('miniStatus').textContent=on?'Подключено':busy?'Подключение…':'Не подключено';
 $('miniServer').textContent=s.host?s.host+':'+s.port:'Сервер не настроен';
 $('miniType').textContent=s.proxy_type==='http'?'HTTP':'SOCKS5';$('miniAccel').textContent=s.accelerate?'Включено':'Выключено';
 $('profileType').textContent=s.proxy_type==='http'?'HTTP CONNECT':'SOCKS5';$('profileHost').textContent=s.host?s.host+':'+s.port:'Не задан';
 $('profileAuth').textContent=s.username?'Настроена':'Не задана';
 if(st.log){logRows=st.log.slice();if(activePage==='logs')renderLogs()}
 if(st.toast)toast(st.toast.title,st.toast.text,st.toast.ok);
 if(!form)fillForm(s);
 if(st.state==='on'&&st.since&&st.since!==lastSessionSince){lastSessionSince=st.since;lastProbeOk=true;lastProbeTime=Date.now();addProbeSample(st.latency,true);renderProbeHistory()}
 if(previousPinging&&!st.pinging){lastProbeOk=st.rtt>0;lastProbeTime=Date.now();if(st.rtt>0)addProbeSample(st.rtt,true);renderProbeHistory();if(st.rtt<=0){$('probeText').textContent='Последняя проверка завершилась ошибкой';$('probeDot').className='result-dot fail'}}
 previousPinging=!!st.pinging;
 const displayLatency=st.pinging?0:(lastProbeOk===false?0:(st.rtt>0?st.rtt:st.latency));
 const displayLatencyText=st.pinging?'Проверка…':fmtMs(displayLatency);
 $('lat').textContent=displayLatencyText;$('lat').className='stat-value '+latClass(displayLatency);
 $('diagLatency').textContent=displayLatencyText;$('diagLatency').className='metric-value '+latClass(displayLatency);
 $('miniLatency').textContent=displayLatencyText;
 const probeState=st.pinging?'pending':lastProbeOk===true?'success':lastProbeOk===false?'fail':'idle';
 $('diagLatency').parentElement.classList.toggle('probe-success',probeState==='success');
 $('diagLatency').parentElement.classList.toggle('probe-fail',probeState==='fail');
 $('diagConnect').parentElement.classList.toggle('probe-success',probeState==='success');
 $('diagConnect').parentElement.classList.toggle('probe-fail',probeState==='fail');
 $('probeChart').parentElement.classList.toggle('probe-success',probeState==='success');
 $('probeChart').parentElement.classList.toggle('probe-fail',probeState==='fail');
 if(lastProbeOk!==null){$('diagConnect').textContent=lastProbeOk?'OK':'Ошибка';$('diagConnect').className='metric-value '+(lastProbeOk?'good':'bad');$('diagConnectDesc').textContent=lastProbeOk?'TCP CONNECT подтверждён':'TCP CONNECT не завершён'}
 else if(st.latency>0){$('diagConnect').textContent='OK';$('diagConnect').className='metric-value good';$('diagConnectDesc').textContent='Подтверждено при подключении';}
 if(!s.host&&!onboardingShown&&!onboardingDismissed){onboardingShown=true;openOnboarding()}
}
window.onUpdate=function(st){S=st;setStatus(st)};
function addProbeSample(ms,ok){if(!(ms>0))return;probeHistory.push({ms:ms,ok:!!ok,time:Date.now()});if(probeHistory.length>12)probeHistory.shift()}
function renderProbeHistory(){
 const el=$('probeChart');$('probeCount').textContent=probeHistory.length+' измерений';
 if(!probeHistory.length){el.innerHTML='<div class="chart-empty">Пока нет измерений</div>';return}
 const last=probeHistory[probeHistory.length-1],accent=lastProbeOk===false?'#f06b73':last.ok?'#22c875':'#f06b73';
 const vals=probeHistory.map(x=>x.ms);
 const maxValue=Math.max(1,...vals);
 const step=maxValue<=600?100:maxValue<=1200?200:maxValue<=3000?500:1000;
 const scaleMax=Math.max(step,Math.ceil(maxValue/step)*step);
 const W=900,H=210,left=62,right=18,top=17,bottom=30;
 const plotW=W-left-right,plotH=H-top-bottom;
 const xFor=i=>left+(vals.length===1?plotW/2:i*plotW/(vals.length-1));
 const yFor=v=>top+plotH-(v/scaleMax)*plotH;
 const points=vals.map((v,i)=>({x:xFor(i),y:yFor(v),value:v}));
 const pointList=points.map(p=>p.x.toFixed(1)+','+p.y.toFixed(1)).join(' ');
 const area=pointList+' '+points[points.length-1].x.toFixed(1)+','+(top+plotH)+' '+points[0].x.toFixed(1)+','+(top+plotH);
 let grid='',labels='';
 for(let tick=0;tick<=scaleMax;tick+=step){
  const y=yFor(tick);
  grid+='<line class="chart-gridline" x1="'+left+'" y1="'+y.toFixed(1)+'" x2="'+(W-right)+'" y2="'+y.toFixed(1)+'"/>';
  labels+='<text class="chart-axis-label" x="'+(left-12)+'" y="'+(y+4).toFixed(1)+'" text-anchor="end">'+tick+'</text>';
 }
 const hits=points.map((p,i)=>'<circle class="chart-hit" data-index="'+i+'" cx="'+p.x.toFixed(1)+'" cy="'+p.y.toFixed(1)+'" r="13"/>').join('');
 el.innerHTML='<svg viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none" role="img" aria-label="График задержки в миллисекундах"><defs><linearGradient id="chartFill" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="'+accent+'" stop-opacity=".28"/><stop offset="1" stop-color="'+accent+'" stop-opacity="0"/></linearGradient></defs><text class="chart-unit-label" x="8" y="12">мс</text>'+grid+labels+'<polygon class="chart-area" points="'+area+'"/><polyline class="chart-line" style="stroke:'+accent+'" points="'+pointList+'"/>'+hits+'</svg><div class="chart-hover-line" hidden></div><div class="chart-hover-dot" hidden></div><div class="chart-tooltip" hidden></div>';
 const svg=el.querySelector('svg'),tooltip=el.querySelector('.chart-tooltip'),dot=el.querySelector('.chart-hover-dot'),line=el.querySelector('.chart-hover-line');
 function hideHover(){tooltip.hidden=true;dot.hidden=true;line.hidden=true}
 svg.addEventListener('pointermove',event=>{
  const rect=svg.getBoundingClientRect();
  if(!rect.width||!points.length)return;
  const svgX=(event.clientX-rect.left)/rect.width*W;
  const boundedX=Math.max(left,Math.min(W-right,svgX));
  const index=points.length===1?0:Math.max(0,Math.min(points.length-1,Math.round((boundedX-left)/plotW*(points.length-1))));
  const point=points[index],sample=probeHistory[index];
  const xPct=point.x/W*100,yPct=point.y/H*100;
  dot.hidden=false;line.hidden=false;tooltip.hidden=false;
  dot.style.left=xPct+'%';dot.style.top=yPct+'%';
  line.style.left=xPct+'%';line.style.top=top/H*100+'%';line.style.height=plotH/H*100+'%';
  tooltip.style.left=xPct+'%';tooltip.style.top=yPct+'%';
  tooltip.style.transform=point.x>W*.78?'translate(-100%,-125%)':point.x<W*.22?'translate(0,-125%)':'translate(-50%,-125%)';
  const time=new Date(sample.time).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
  tooltip.textContent=sample.ms+' мс · '+time;
 });
 svg.addEventListener('pointerleave',hideHover);
 $('probeText').textContent='Последнее измерение: '+last.ms+' мс';$('probeDot').className='result-dot '+(last.ok?'ok':'fail');
}
function tick(){if(S&&S.state==='on'&&since){$('uptime').textContent=fmtDur(Math.max(0,Math.floor(Date.now()/1000-since)));$('sub').textContent='Подключено '+fmtDur(Math.max(0,Math.floor(Date.now()/1000-since)))}}
setInterval(tick,1000);
function toggle(){if(S&&S.state==='off'&&!(S.settings&&S.settings.host)){setPage('connection');return}api('toggle')}
function ping(){api('ping')}
function fillForm(s){
 form=JSON.parse(JSON.stringify(s||{}));form.bypass_apps=(s.bypass_apps||[]).slice();
 $('f_host').value=s.host||'';$('f_port').value=s.port||'';$('f_user').value=s.username||'';$('f_pass').value=s.password||'';
 $('f_quic').checked=!!s.block_quic;$('f_udp').checked=!!s.udp_over_socks;$('f_accel').checked=!!s.accelerate;
 $('f_bypass').value=s.bypass||'';setType(s.proxy_type||'socks5',true);renderApps();
}
function setProfileProtocol(t,disabled){
 const group=$('profileProtocol');
 if(!group)return;
 group.querySelectorAll('button').forEach(button=>{
  const active=button.dataset.v===t;
  button.classList.toggle('active',active);
  button.disabled=!!disabled;
  button.title=disabled?'Отключите VPN, чтобы сменить протокол':'Переключить тип прокси';
 });
}
async function quickProxyType(t){
 if(!S||!S.settings||!S.settings.host)return;
 if(S.state!=='off'){toast('Нельзя сменить протокол','Сначала отключите VPN',false);return}
 const previous=S.settings.proxy_type||'socks5';
 if(previous===t)return;
 const s=Object.assign({},S.settings,{proxy_type:t});
 if(t==='http'){
  if(!s.port||s.port===1080)s.port=8080;
  s.udp_over_socks=false;
 }else if(!s.port||s.port===8080){s.port=1080}
 setProfileProtocol(previous,true);
 try{
  const err=await api('saveSettings',s);
  if(err){setProfileProtocol(previous,false);toast('Протокол не изменён',err,false);return}
  S.settings=s;form=JSON.parse(JSON.stringify(s));fillForm(s);
  setProfileProtocol(t,false);
  toast('Протокол изменён',t==='http'?'Выбран HTTP CONNECT':'Выбран SOCKS5',true);
 }catch(e){setProfileProtocol(previous,false);toast('Не удалось сменить протокол',e.message,false)}
}
function setType(t,silent){
 if(!form)form={};form.proxy_type=t;
 document.querySelectorAll('#seg button').forEach(b=>b.classList.toggle('active',b.dataset.v===t));
 $('f_udp').disabled=t==='http';if(t==='http')$('f_udp').checked=false;
 $('profileType').textContent=t==='http'?'HTTP CONNECT':'SOCKS5';
 if(!silent&&$('f_port').value==='')$('f_port').value=t==='http'?'8080':'1080';
}
function eye(){const p=$('f_pass');p.type=p.type==='password'?'text':'password'}
function readForm(){if(!form)form={proxy_type:'socks5',bypass_apps:[]};return Object.assign({},form,{
 host:$('f_host').value.trim(),port:parseInt($('f_port').value,10)||0,
 username:$('f_user').value.trim(),password:$('f_pass').value,
 block_quic:$('f_quic').checked,udp_over_socks:$('f_udp').checked,accelerate:$('f_accel').checked,
 bypass:$('f_bypass').value,bypass_apps:(form.bypass_apps||[]).slice()
})}
async function save(){
 try{const s=readForm(),err=await api('saveSettings',s);if(err){toast('Не сохранено',err,false);return}
 form=JSON.parse(JSON.stringify(s));toast('Настройки сохранены','Изменения будут применены при следующем подключении',true);setPage('home');
 }catch(e){toast('Ошибка сохранения',e.message,false)}
}
async function quick(key,val){
 if(!S)return;const s=Object.assign({},S.settings,{[key]:val});
 try{const err=await api('saveSettings',s);if(err){$('q_accel').checked=!!S.settings.accelerate;toast('Не сохранено',err,false);return}
 if(form)form[key]=val;if(key==='accelerate')$('f_accel').checked=!!val;
 }catch(e){$('q_accel').checked=!!S.settings.accelerate;toast('Ошибка сохранения',e.message,false)}
}
async function pasteLink(){
 let text='';try{text=await navigator.clipboard.readText()}catch(e){}
 try{const r=await api('parseLink',text);if(!r)return;if(r.error){toast('Не получилось',r.error,false);return}
 const keep=readForm();const s=Object.assign(keep,r.settings,{block_quic:keep.block_quic,udp_over_socks:keep.udp_over_socks,accelerate:keep.accelerate,bypass:keep.bypass,bypass_apps:keep.bypass_apps});
 fillForm(s);toast('Данные из ссылки вставлены','Проверьте параметры и сохраните профиль',true);
 }catch(e){toast('Ошибка чтения ссылки',e.message,false)}
}
function renderApps(){
 const L=form&&form.bypass_apps||[];$('appCount').textContent=String(L.length);
 $('bypassApps').innerHTML=L.length?L.map((p,i)=>'<div class="app-item"><div class="app-avatar">'+esc(baseName(p).slice(0,2))+'</div><div class="app-detail"><b>'+esc(baseName(p))+'</b><span title="'+esc(p)+'">'+esc(p)+'</span></div><button class="remove" title="Удалить" onclick="delApp('+i+')">×</button></div>').join(''):'<div class="app-empty">Пока нет исключённых приложений</div>';
 $('domainCount').textContent=String(($('f_bypass').value||'').split(/[\\s,;]+/).filter(Boolean).length);
}
function addApp(p){if(!p||!form)return false;if((form.bypass_apps||[]).some(x=>x.toLowerCase()===p.toLowerCase()))return false;form.bypass_apps=(form.bypass_apps||[]).concat([p]);renderApps();return true}
function delApp(i){form.bypass_apps.splice(i,1);renderApps()}
function pickApp(){api('pickApp')}
window.onPickedApp=p=>{if(p&&!addApp(p))toast('Уже в списке',baseName(p),true)}
async function openProcs(){
 $('procQ').value='';$('procList').innerHTML='<div class="app-empty">Загружаю список процессов…</div>';$('app').classList.add('show-procs');
 try{procs=(await api('listProcs'))||[];renderProcs()}catch(e){$('procList').innerHTML='<div class="app-empty">Не удалось получить список процессов</div>'}
}
function closeProcs(){$('app').classList.remove('show-procs')}
function renderProcs(){
 const q=$('procQ').value.trim().toLowerCase(),L=procs.filter(p=>!q||p.path.toLowerCase().includes(q));
 $('procList').innerHTML=L.length?L.map(p=>{const i=procs.indexOf(p),on=(form.bypass_apps||[]).some(x=>x.toLowerCase()===p.path.toLowerCase());
 return '<div class="app-item'+(on?' added':'')+'" onclick="procClick('+i+')"><div class="app-avatar">'+esc(p.name.slice(0,2))+'</div><div class="app-detail"><b>'+esc(p.name)+'</b><span title="'+esc(p.path)+'">'+esc(p.path)+'</span></div><div class="remove">'+(on?'✓':'+')+'</div></div>'
 }).join(''):'<div class="app-empty">Ничего не найдено</div>'
}
function procClick(i){const p=procs[i];if(!p)return;const ix=form.bypass_apps.findIndex(x=>x.toLowerCase()===p.path.toLowerCase());if(ix>=0)form.bypass_apps.splice(ix,1);else addApp(p.path);renderApps();renderProcs()}
function renderLogs(){
 const q=$('logSearch').value.trim().toLowerCase(),filter=$('logFilter').value;
 const L=logRows.filter(line=>{const x=line.toLowerCase();if(q&&!x.includes(q))return false;
 const type=/ошибка|error|fatal|panic|не удалось|отклон/.test(x)?'error':/предупреж|warning|warn|timeout|повтор/.test(x)?'warn':/подключён|успеш|пройдена|сохранены|внешний ip/.test(x)?'success':'all';
 return filter==='all'||type===filter});
 $('logList').innerHTML=L.length?L.slice().reverse().map(line=>{
 const m=line.match(/^(\d{2}:\d{2}:\d{2})\s*(.*)$/),time=m?m[1]:'',msg=m?m[2]:line,x=msg.toLowerCase();
 const type=/ошибка|error|fatal|panic|не удалось|отклон/.test(x)?'error':/предупреж|warning|warn|timeout|повтор/.test(x)?'warn':/подключён|успеш|пройдена|сохранены|внешний ip/.test(x)?'success':'';
 const symbol=type==='error'?'!':type==='warn'?'▲':type==='success'?'✓':'·';
 return '<div class="log-entry '+type+'"><span class="log-time">'+esc(time)+'</span><span class="log-symbol">'+symbol+'</span><span class="log-message">'+esc(msg)+'</span></div>'
 }).join(''):'<div class="log-empty"><div class="empty-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3h9l5 5v13H6z"/><path d="M15 3v5h5M9 13h8M9 17h6"/></svg></div>По заданным условиям событий нет</div>'
}
async function clearLogs(){try{const err=await api('clearLog');if(err){toast('Не удалось очистить журнал',err,false);return}logRows=[];renderLogs();toast('Журнал очищен','Текущий журнал приложения очищен',true)}catch(e){toast('Не удалось очистить журнал',e.message,false)}}
async function copyLogs(){try{await navigator.clipboard.writeText(logRows.join('\n'));toast('Скопировано','Журнал скопирован в буфер обмена',true)}catch(e){toast('Буфер обмена недоступен','Откройте файл журнала через кнопку «Открыть файл»',false)}}
function openOnboarding(){
 $('onboarding').classList.add('show');
 if(S&&S.settings){wizardType=S.settings.proxy_type||'socks5';setWizardType(wizardType);$('w_host').value=S.settings.host||'';$('w_port').value=S.settings.port||1080;$('w_user').value=S.settings.username||'';$('w_pass').value=S.settings.password||'';$('w_accel').checked=!!S.settings.accelerate}
}
function setWizardType(t){wizardType=t;document.querySelectorAll('#wSeg button').forEach(b=>b.classList.toggle('active',b.dataset.v===t));if(!$('w_port').value||$('w_port').value==='1080'||$('w_port').value==='8080')$('w_port').value=t==='http'?'8080':'1080'}
function skipOnboarding(){onboardingDismissed=true;$('onboarding').classList.remove('show');setPage('home')}
async function saveOnboarding(){
 const s=Object.assign({},S&&S.settings||{},{
  proxy_type:wizardType,host:$('w_host').value.trim(),port:parseInt($('w_port').value,10)||0,
  username:$('w_user').value.trim(),password:$('w_pass').value,accelerate:$('w_accel').checked
 });
 try{const err=await api('saveSettings',s);if(err){toast('Не удалось сохранить',err,false);return}
 form=JSON.parse(JSON.stringify(s));onboardingDismissed=true;$('onboarding').classList.remove('show');fillForm(s);toast('Профиль сохранён','Теперь можно подключаться',true);setPage('home')
 }catch(e){toast('Ошибка сохранения',e.message,false)}
}
$('f_bypass').addEventListener('input',renderApps);
function tickLogs(){if(activePage==='routing')renderApps()}
document.addEventListener('keydown',e=>{if(e.key==='Escape'){if($('app').classList.contains('show-procs'))closeProcs();else if($('onboarding').classList.contains('show'))skipOnboarding()}});
document.addEventListener('contextmenu',e=>{if(!e.target.closest('input,textarea,pre'))e.preventDefault()});
api('ready');
