const $=s=>document.querySelector(s),$=s=>[...document.querySelectorAll(s)];
window.addEventListener("error",e=>{const el=document.querySelector("#authMessage");if(el)el.textContent="Application error: "+(e.message||"Unknown error")+". Refresh the page; if it continues, share this message."});
window.addEventListener("unhandledrejection",e=>{const el=document.querySelector("#authMessage");if(el)el.textContent="Application error: "+(e.reason?.message||String(e.reason)||"Background operation failed")+". Refresh the page; if it continues, share this message."});
const tracks={
 engineering:["Define system context, assets and trust boundaries","Write a threat model with abuse cases and mitigations","Harden identity, endpoint, network and platform baselines","Add secrets scanning, SAST, SCA and IaC checks to CI/CD","Validate logging, alerting, backup and recovery controls","Document control owner, evidence and exception expiry"],
 vapt:["Obtain written authorization, scope, ROE and test window","Confirm assets, exclusions, rate limits and emergency contacts","Perform discovery and map attack surface within scope","Validate vulnerabilities safely and preserve redacted evidence","Rate business impact and write actionable remediation","Retest fixes and record residual risk and closure"],
 app:["Map roles, trust boundaries, endpoints and API inventory","Test authentication, session lifecycle and MFA behavior","Test object- and function-level authorization (BOLA/BFLA)","Review injection, XSS, CSRF, SSRF and file handling","Test business logic, rate limits and security headers","Validate fixes with regression tests and ASVS requirements"],
 cloud:["Inventory accounts, projects, subscriptions and workloads","Review IAM roles, federation, MFA and privilege paths","Check public exposure, segmentation and security groups","Review encryption, key lifecycle, secrets and storage policy","Enable audit logs, detections, retention and alert routing","Scan IaC and containers; track exceptions and remediation"]
};
const cfg=window.BLACKSITE_SUPABASE;
const client=window.supabase?.createClient(cfg?.url,cfg?.publishableKey);
const freshState=()=>({projects:[],labs:[],findings:[],evidence:[],achievements:[],controls:[],appTests:[],cloudAssets:[],intel:[],incidents:[],assets:[],references:[],checks:{},activity:[]});
const charts={};
let pendingFindingImport=[];
const severityValue=v=>({informational:"info"}[String(v||"").toLowerCase()]||String(v||"").toLowerCase());
function recordCard(r,meta,kind){return '<div class="record"><div><b>'+safe(r.title)+'</b><small>'+safe(meta||"")+'</small>'+(r.content?.notes?'<small>'+safe(r.content.notes)+'</small>':"")+(r.reference_url&&/^https?:\/\//i.test(r.reference_url)?'<small><a href="'+safe(r.reference_url)+'" target="_blank" rel="noopener noreferrer">Open source ↗</a></small>':"")+(r.content?.path?'<small><button type="button" class="inline-link" data-evidence="'+safe(r.id)+'" data-path="'+safe(r.content.path)+'">Open attachment ↗</button></small>':"")+'</div><button data-remove="'+kind+'" data-id="'+safe(r.id)+'">Remove</button></div>'}
function drawChart(id,type,labels,values,label){
 if(!window.Chart)return;
 const canvas=document.getElementById(id);
 if(!canvas)return;
 if(charts[id])charts[id].destroy();
 charts[id]=new Chart(canvas,{type:type,data:{labels:labels,datasets:[{label:label,data:values,borderWidth:2,backgroundColor:type==="doughnut"?["#ff647c","#ffad66","#f7d56b","#70c7b2","#71869d"]:"rgba(199,255,114,.18)",borderColor:"#c7ff72",tension:.35,fill:type==="line"}]},options:{responsive:true,maintainAspectRatio:false}});
}
function renderCharts(){const keys=["critical","high","medium","low","info"],counts=keys.map(k=>state.findings.filter(x=>severityValue(x.severity)===k).length);drawChart("severityChart","doughnut",["Critical","High","Medium","Low","Info"],counts,"Findings");drawChart("vaptChart","doughnut",["Critical","High","Medium","Low","Info"],counts,"Findings");const now=new Date(),months=[];for(let i=5;i>=0;i--){const d=new Date(now.getFullYear(),now.getMonth()-i,1);months.push({label:d.toLocaleString(undefined,{month:"short"}),year:d.getFullYear(),month:d.getMonth()})}drawChart("trendChart","line",months.map(x=>x.label),months.map(m=>state.findings.filter(x=>{const d=new Date(x.created_at||x.updated_at||0);return d.getFullYear()===m.year&&d.getMonth()===m.month}).length),"Created");drawChart("findingStatusChart","doughnut",["Open","In progress","Resolved"],[state.findings.filter(x=>!["completed","resolved","closed"].includes(x.status)).length,state.findings.filter(x=>x.status==="in_progress").length,state.findings.filter(x=>["completed","resolved","closed"].includes(x.status)).length],"Status");drawChart("cloudExposureChart","doughnut",["Public","Private","Internal","Unknown"],["Public","Private","Internal","Unknown"].map(k=>state.cloudAssets.filter(x=>x.content?.exposure===k).length),"Exposure");drawChart("cloudPostureChart","doughnut",["Healthy","Needs review","Misconfigured","Exception"],["Healthy","Needs review","Misconfigured","Exception accepted"].map(k=>state.cloudAssets.filter(x=>x.content?.posture===k).length),"Posture")}

function isFindingActive(x){return !["completed","resolved","closed","accepted","false_positive"].includes(String(x.status||"open").toLowerCase())}
function findingAgeDays(x){return Math.max(0,Math.floor((Date.now()-new Date(x.created_at||x.updated_at||Date.now()).getTime())/86400000))}
function findingDueDate(x){if(x.content?.due_date)return new Date(x.content.due_date+"T23:59:59");const d=new Date(x.created_at||x.updated_at||Date.now());d.setDate(d.getDate()+({critical:7,high:30,medium:90,low:180,info:365}[severityValue(x.severity)]||90));return d}
function findingRiskScore(x){const c=Number(x.content?.cvss);if(x.content?.cvss!==""&&x.content?.cvss!=null&&Number.isFinite(c)&&c>=0&&c<=10)return c;const i=Number(x.content?.impact),l=Number(x.content?.likelihood);if(i>=1&&i<=5&&l>=1&&l<=5)return i*l*.4;return ({critical:9.5,high:8,medium:5,low:2,info:.5}[severityValue(x.severity)]||0)}
function riskBand(s){return s>=9?"Critical":s>=7?"High":s>=4?"Medium":"Low"}
function renderRiskDashboard(){
 const active=state.findings.filter(isFindingActive),today=new Date();today.setHours(0,0,0,0);
 const overdue=active.filter(x=>findingDueDate(x)<today).sort((x,y)=>findingDueDate(x)-findingDueDate(y));
 const urgent=active.filter(x=>["critical","high"].includes(severityValue(x.severity)));
 const avg=active.length?active.reduce((n,x)=>n+findingRiskScore(x),0)/active.length:0;
 $("#riskOpen").textContent=active.length;$("#riskOverdue").textContent=overdue.length;$("#riskUrgent").textContent=urgent.length;$("#riskAverage").textContent=active.length?avg.toFixed(1)+"/10":"—";
 const ages=[0,0,0,0];active.forEach(x=>{const d=findingAgeDays(x);ages[d<=7?0:d<=30?1:d<=90?2:3]++});
 drawChart("findingAgeChart","bar",["0–7 days","8–30 days","31–90 days","90+ days"],ages,"Open findings");
 const scores=[0,0,0,0];active.forEach(x=>{const s=findingRiskScore(x);scores[s>=9?3:s>=7?2:s>=4?1:0]++});
 drawChart("riskScoreChart","doughnut",["Low <4","Medium 4–6.9","High 7–8.9","Critical 9+"],scores,"Risk score");
 const matrix=Array.from({length:5},()=>Array(5).fill(0));
 active.forEach(x=>{const l=Number(x.content?.likelihood),im=Number(x.content?.impact);if(l>=1&&l<=5&&im>=1&&im<=5)matrix[5-l][im-1]++});
 $("#riskHeatmap").innerHTML='<div class="heat-axis">L</div>'+matrix.map((row,r)=>'<div class="heat-row"><span class="heat-y">'+(5-r)+'</span>'+row.map((n,c)=>{const s=(5-r)*(c+1);return '<div class="heat-cell heat-'+(s>=20?"critical":s>=12?"high":s>=6?"medium":"low")+'" title="Likelihood '+(5-r)+' × impact '+(c+1)+': '+n+' finding(s)">'+n+'</div>'}).join("")+'</div>').join("")+'<div class="heat-x"></div>'+[1,2,3,4,5].map(n=>'<span class="heat-x-label">'+n+'</span>').join("");
 $("#overdueList").innerHTML=overdue.length?overdue.slice(0,5).map(x=>recordCard(x,"Due "+findingDueDate(x).toLocaleDateString()+" · "+findingAgeDays(x)+" days old","finding")).join(""):'<p class="empty">No overdue open findings.</p>';
 const oldest=[...active].sort((x,y)=>findingAgeDays(y)-findingAgeDays(x)).slice(0,5);
 $("#agingList").innerHTML=oldest.length?oldest.map(x=>recordCard(x,findingAgeDays(x)+" days old · "+riskBand(findingRiskScore(x))+" · "+findingRiskScore(x).toFixed(1)+"/10","finding")).join(""):'<p class="empty">No open findings to age.</p>';
}
function parseFindingCSV(t){const rows=[];let row=[],cell="",q=false;for(let i=0;i<t.length;i++){const c=t[i],n=t[i+1];if(c==='"'&&q&&n==='"'){cell+='"';i++}else if(c==='"')q=!q;else if(c===","&&!q){row.push(cell);cell=""}else if((c==="\n"||c==="\r")&&!q){if(c==="\r"&&n==="\n")i++;row.push(cell);if(row.some(v=>v.trim()))rows.push(row);row=[];cell=""}else cell+=c}row.push(cell);if(row.some(v=>v.trim()))rows.push(row);if(!rows.length)return [];const keys=rows.shift().map(k=>k.trim().toLowerCase().replace(/[^a-z0-9]+/g,"_").replace(/^_|_$/g,""));return rows.map(r=>Object.fromEntries(keys.map((k,i)=>[k,(r[i]||"").trim()])))}
function normalizeImportedFinding(raw,domain){const o={};for(const [k,v] of Object.entries(raw||{}))o[String(k).toLowerCase().replace(/[^a-z0-9]+/g,"_").replace(/^_|_$/g,"")]=v;const pick=(...ks)=>{for(const k of ks)if(o[k]!=null&&String(o[k]).trim())return String(o[k]).trim();return ""};const title=pick("title","name","finding","vulnerability","issue","vulnerability_name"),s=pick("severity","risk","priority")||"medium",sev=({informational:"info",info:"info",critical:"critical",high:"high",medium:"medium",moderate:"medium",low:"low"})[s.toLowerCase()]||"medium",rawCv=pick("cvss","cvss_score","cvss_v3","cvss3","score"),cv=rawCv===""?null:Number(rawCv),due=pick("due_date","remediation_due","sla_due_date"),l=Number(pick("likelihood","probability")),i=Number(pick("impact","business_impact"));return {title,severity:sev,status:({"open":"open","new":"open","in_progress":"in_progress","in progress":"in_progress","resolved":"completed","closed":"completed","fixed":"completed","accepted risk":"accepted","accepted":"accepted"})[pick("status","state").toLowerCase()]||"open",content:{domain:pick("domain","category")||domain,asset:pick("asset","host","hostname","url","target"),cve:pick("cve","cwe","cve_cwe","id","finding_id"),cvss:cv!==null&&Number.isFinite(cv)&&cv>=0&&cv<=10?cv:null,due_date:/^\d{4}-\d{2}-\d{2}$/.test(due)?due:"",likelihood:l>=1&&l<=5?l:null,impact:i>=1&&i<=5?i:null,notes:pick("notes","description","summary","detail"),remediation:pick("remediation","recommendation","solution","fix")}}}

async function attachEvidence(file){if(!file)return null;if(file.size>20*1024*1024)throw new Error(file.name+" exceeds 20 MB");const ext=(file.name.split(".").pop()||"").toLowerCase(),allowed=["pdf","png","jpg","jpeg","txt","csv","json","zip"];if(!allowed.includes(ext))throw new Error("Unsupported file type: "+file.name);const path=user.id+"/"+crypto.randomUUID()+"-"+file.name.replace(/[^a-zA-Z0-9._-]/g,"_");const types={pdf:"application/pdf",png:"image/png",jpg:"image/jpeg",jpeg:"image/jpeg",txt:"text/plain",csv:"text/csv",json:"application/json",zip:"application/zip"};const up=await client.storage.from("security-evidence").upload(path,file,{contentType:types[ext],upsert:false});if(up.error)throw up.error;return {filename:file.name,path,size:file.size,mime:types[ext]}}
let state=freshState(),user=null,checklistId=null,authMode="signin",busy=false;
function safe(s=""){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function setStatus(t){const el=$("#syncStatus");if(el)el.textContent=t}
function message(t){$("#authMessage").textContent=t}
function note(action,detail){state.activity.unshift({action,detail,at:new Date().toISOString()});state.activity=state.activity.slice(0,12)}
function item(kind,title,content,status="open",severity=null,reference_url=null){return {user_id:user.id,kind,title,status,severity,content,reference_url,tags:[]}}
function dbStatus(value){return ({"Planned":"open","In progress":"in_progress","Completed":"completed"})[value]||value}
function dbSeverity(value){return value==="Informational"?"info":String(value||"").toLowerCase()}
function fromRow(r){return {id:r.id,...(r.content||{}),title:r.title,status:r.status,severity:r.severity,reference_url:r.reference_url,created_at:r.created_at,updated_at:r.updated_at,content:r.content||{}}}
async function loadWorkspace(){
 setStatus("SYNCING");
 const {data,error}=await client.from("workspace_items").select("*").order("updated_at",{ascending:false});
 if(error)throw error;
 state=freshState();checklistId=null;
 for(const r of data||[]){
  if(r.kind==="project")state.projects.push(fromRow(r));
  if(r.kind==="finding")state.findings.push(fromRow(r));
  if(r.kind==="learning")state.labs.push(fromRow(r));
  if(r.kind==="evidence")state.evidence.push(fromRow(r));
  if(r.kind==="achievement")state.achievements.push(fromRow(r));
  if(r.kind==="control")state.controls.push(fromRow(r));
  if(r.kind==="app_test")state.appTests.push(fromRow(r));
  if(r.kind==="cloud_asset")state.cloudAssets.push(fromRow(r));
  if(r.kind==="intel")state.intel.push(fromRow(r));
  if(r.kind==="incident")state.incidents.push(fromRow(r));
  if(r.kind==="asset")state.assets.push(fromRow(r));
  if(r.kind==="reference")state.references.push(fromRow(r));
  if(r.kind==="note")state.activity.push({action:r.title,detail:r.content?.detail||"",at:r.created_at});
  if(r.kind==="checklist"&&r.title==="checklist-progress"){state.checks=r.content?.checks||{};checklistId=r.id}
 }
 state.activity=state.activity.slice(0,12);render();setStatus("CLOUD SYNCED");
}
async function insertRecord(kind,title,content,status="open",severity=null,reference_url=null){
 const payload=item(kind,title,content,status,severity,reference_url);
 const {data,error}=await client.from("workspace_items").insert(payload).select().single();
 if(error)throw error;return fromRow(data);
}
async function removeRecord(id){const {error}=await client.from("workspace_items").delete().eq("id",id);if(error)throw error}
async function persistChecks(){
 const payload={user_id:user.id,kind:"checklist",title:"checklist-progress",status:"in_progress",content:{checks:state.checks},tags:[]};
 let result;
 if(checklistId)result=await client.from("workspace_items").update(payload).eq("id",checklistId);
 else {const r=await client.from("workspace_items").insert(payload).select("id").single();if(!r.error)checklistId=r.data.id;result=r}
 if(result.error)throw result.error;setStatus("CLOUD SYNCED");
}
async function logActivity(action,detail){
 try{await insertRecord("note",action,{detail},"completed");note(action,detail);render()}catch(e){setStatus("SYNC ERROR");alert("Could not save activity: "+e.message)}
}
function addChecks(id,items){const host=$("#"+id);host.innerHTML=items.map((t,i)=>{const key=id+"-"+i;return '<label class="check '+(state.checks[key]?"done":"")+'"><input type="checkbox" data-check="'+key+'" '+(state.checks[key]?"checked":"")+'><span>'+safe(t)+'</span></label>'}).join("")}
function render(){
 $("#mProjects").textContent=state.projects.length;$("#mLabs").textContent=state.labs.filter(x=>x.status==="completed").length;$("#mFindings").textContent=state.findings.length;
 const total=Object.values(tracks).flat().length,done=Object.values(state.checks).filter(Boolean).length;$("#mSkills").textContent=Math.round(done/total*100)+"%";
 $("#findingList").innerHTML=state.findings.length?state.findings.map(x=>'<div class="record"><div><b>'+safe(x.title)+'</b><small>'+safe(x.content?.domain)+' · '+safe(x.severity)+'</small></div><button data-remove="finding" data-id="'+x.id+'">Remove</button></div>').join(""):'<p class="empty">No findings recorded yet.</p>';
 $("#projectList").innerHTML=state.projects.length?state.projects.map(x=>'<div class="record"><div><b>'+safe(x.title)+'</b><small>'+safe(x.content?.domain)+' · '+safe(x.status)+' · '+safe(x.content?.summary||"No summary added")+(x.content?.stack?" · "+safe(x.content.stack):"")+(x.content?.tags?.length?" · "+safe(x.content.tags.join(", ")):"")+'</small>'+(x.reference_url?'<small><a href="'+safe(x.reference_url)+'" target="_blank" rel="noreferrer">Evidence ↗</a></small>':"")+'</div><button data-remove="project" data-id="'+x.id+'">Remove</button></div>').join(""):'<p class="empty">No projects yet. Add a project and link verifiable evidence.</p>';
 $("#labList").innerHTML=state.labs.length?state.labs.map(x=>'<div class="record"><div><b>'+safe(x.title)+'</b><small>'+safe(x.content?.domain)+' · '+safe(x.status)+' · '+safe(x.content?.source||"")+(x.content?.difficulty?" · "+safe(x.content.difficulty):"")+(x.content?.hours?" · "+safe(x.content.hours)+"h":"")+' · '+safe(x.content?.notes||"")+'</small></div><button data-remove="learning" data-id="'+x.id+'">Remove</button></div>').join(""):'<p class="empty">No learning activities logged yet.</p>';
 $("#evidenceList").innerHTML=state.evidence.length?state.evidence.map(x=>'<div class="record"><div><b>'+safe(x.content?.filename||x.title)+'</b><small>'+safe(((x.content?.size||0)/1024/1024).toFixed(2))+' MB · '+safe(x.content?.mime||"file")+'</small></div><button data-evidence="'+x.id+'" data-path="'+safe(x.content?.path||"")+'">Open</button></div>').join(""):'<p class="empty">No evidence uploaded yet. Attach files to a project to store them privately.</p>';
 $("#activity").innerHTML=state.activity.length?state.activity.map(x=>'<div class="record"><div><b>'+safe(x.action)+'</b><small>'+safe(x.detail)+' · '+new Date(x.at).toLocaleString()+'</small></div></div>').join(""):'<p class="empty">No activity yet. Log a lab, project or finding to start.</p>';
 $("#hallCount").textContent=state.achievements.length+" ITEMS";
 $("#hallList").innerHTML=state.achievements.length?state.achievements.map(x=>{const c=x.content||{},url=/^https?:\/\//i.test(x.reference_url||"")?'<a href="'+safe(x.reference_url)+'" target="_blank" rel="noopener noreferrer">View source ↗</a>':"";return '<div class="record hall-record"><div><span class="hall-category">'+safe(c.category||"Achievement")+'</span><b>'+safe(x.title)+'</b><small>'+safe(c.issuer||"")+(c.date?" · "+safe(c.date):"")+'</small>'+(c.description?'<p>'+safe(c.description)+'</p>':"")+'<div class="hall-links">'+url+(c.path?'<button type="button" data-hall-evidence="'+safe(x.id)+'">Open attachment ↗</button>':"")+'</div></div><button data-remove="achievement" data-id="'+safe(x.id)+'">Remove</button></div>'}).join(""):'<p class="empty">Your Hall of Fame is ready. Add your first award, certificate, achievement or published paper above.</p>';

 $("#controlList").innerHTML=state.controls.length?state.controls.map(x=>recordCard(x,[x.content?.framework,x.status,x.content?.owner,x.content?.review].filter(Boolean).join(" · "),"control")).join(""):'<p class="empty">No control validations logged yet.</p>';
 $("#appTestList").innerHTML=state.appTests.length?state.appTests.map(x=>recordCard(x,[x.content?.asset,x.content?.endpoint,x.content?.category,x.content?.result,x.content?.method].filter(Boolean).join(" · "),"app_test")).join(""):'<p class="empty">No application test cases yet.</p>';
 $("#cloudAssetList").innerHTML=state.cloudAssets.length?state.cloudAssets.map(x=>recordCard(x,[x.content?.provider,x.content?.environment,x.content?.exposure,x.content?.criticality,x.content?.posture].filter(Boolean).join(" · "),"cloud_asset")).join(""):'<p class="empty">No cloud assets registered yet.</p>';
 $("#intelList").innerHTML=state.intel.length?state.intel.map(x=>recordCard(x,[x.content?.type,x.content?.confidence,x.severity,x.content?.date].filter(Boolean).join(" · "),"intel")).join(""):'<p class="empty">No intel records saved yet.</p>';
 $("#incidentList").innerHTML=state.incidents.length?state.incidents.map(x=>recordCard(x,[x.content?.type,x.content?.status,x.severity,x.content?.date].filter(Boolean).join(" · "),"incident")).join(""):'<p class="empty">No incident or tabletop records yet.</p>';
 $("#assetList").innerHTML=state.assets.length?state.assets.map(x=>recordCard(x,[x.content?.type,x.content?.environment,x.content?.authorization,x.content?.criticality].filter(Boolean).join(" · "),"asset")).join(""):'<p class="empty">No assets registered. Add an owned or authorized target and its scope.</p>';
 $("#referenceList").innerHTML=state.references.length?state.references.map(x=>recordCard(x,x.content?.type,"reference")).join(""):'<p class="empty">No custom bookmarks yet.</p>';
 const q=$("#findingSearch")?.value?.toLowerCase()||"",sev=$("#findingSeverityFilter")?.value||"";const visible=state.findings.filter(x=>(!q||[x.title,x.content?.asset,x.content?.cve,x.content?.domain].some(v=>String(v||"").toLowerCase().includes(q)))&&(!sev||severityValue(x.severity)===sev));
 $("#findingList").innerHTML=visible.length?visible.map(x=>recordCard(x,[x.content?.domain,x.content?.asset,x.content?.cve,x.severity,x.status,x.content?.cvss?"CVSS "+x.content.cvss:"",x.content?.due_date?"Due "+x.content.due_date:""].filter(Boolean).join(" · "),"finding")).join(""):'<p class="empty">No matching findings. Capture a finding to build your risk register.</p>';
 renderCharts();
 renderRiskDashboard();
}
const cyberNewsFeeds=[{name:"The Hacker News",url:"https://feeds.feedburner.com/TheHackersNews"},{name:"BleepingComputer",url:"https://www.bleepingcomputer.com/feed/"},{name:"SecurityWeek",url:"https://www.securityweek.com/feed/"}];
let cyberNewsItems=[],cyberNewsBusy=false;
function classifyCyberNews(item){
 const t=(item.title+" "+(item.description||"")+" "+(item.content||"")).toLowerCase();
 if(/zero.?day|actively exploit|exploited in the wild|kev catalog|cve-20\d\d|critical vulnerability|remote code execution|rce\b/.test(t))return "exploits";
 if(/ransomware|data breach|breach|stolen data|leak(ed)?|extortion|victim data/.test(t))return "breaches";
 if(/apt\d*|threat actor|campaign|botnet|malware|infostealer|backdoor|spyware|phishing|nation.?state|cyber.?espionage/.test(t))return "threats";
 if(/artificial intelligence|\bai\b|large language model|llm|prompt injection|model security|machine learning/.test(t))return "ai";
 if(/cloud|kubernetes|container|aws|azure|google cloud|api security|web application|network security|firewall|identity/.test(t))return "cloud";
 return "research";
}
function newsCategoryLabel(c){return ({exploits:"Zero-days & exploitation",breaches:"Breaches & ransomware",threats:"Threat intelligence & malware",cloud:"Cloud, network & application",ai:"AI security",research:"Tools, research & industry"})[c]||"Security research"}
function renderCyberNews(){
 const cat=$("#newsCategory")?.value||"all",q=($("#newsSearch")?.value||"").trim().toLowerCase();
 const items=cyberNewsItems.filter(x=>(cat==="all"||x.category===cat)&&(!q||(x.title+" "+x.source+" "+x.summary).toLowerCase().includes(q)));
 $("#newsFeed").innerHTML=items.length?items.map(x=>'<article class="panel news-card"><div class="news-card-top"><span class="news-category news-'+x.category+'">'+safe(newsCategoryLabel(x.category))+'</span><small>'+safe(x.source)+'</small></div><h3><a href="'+safe(x.link)+'" target="_blank" rel="noopener noreferrer">'+safe(x.title)+'</a></h3><p>'+safe(x.summary)+'</p><div class="news-card-foot"><time>'+safe(x.date?new Date(x.date).toLocaleString():"Date unavailable")+'</time><a href="'+safe(x.link)+'" target="_blank" rel="noopener noreferrer">Read original ↗</a></div></article>').join(""):'<div class="panel news-empty"><h3>No matching stories</h3><p class="muted">'+(cyberNewsItems.length?"Try another category or search term.":"Refresh the feeds to load current stories.")+'</p></div>';
}
function newsSummary(html){const d=document.createElement("div");d.innerHTML=html||"";return (d.textContent||"").replace(/\s+/g," ").trim().slice(0,260)}
async function loadCyberNews(){
 if(cyberNewsBusy)return;cyberNewsBusy=true;const btn=$("#refreshCyberNews");if(btn){btn.disabled=true;btn.textContent="Refreshing…"}$("#newsStatus").textContent="Fetching public security feeds…";
 try{
  const results=await Promise.allSettled(cyberNewsFeeds.map(async feed=>{const endpoint="https://api.rss2json.com/v1/api.json?rss_url="+encodeURIComponent(feed.url);const response=await fetch(endpoint,{cache:"no-store"});if(!response.ok)throw new Error(feed.name+" returned HTTP "+response.status);const data=await response.json();if(data.status!=="ok")throw new Error(data.message||feed.name+" feed unavailable");return (data.items||[]).map(item=>({title:item.title||"Untitled story",link:item.link||"",date:item.pubDate||"",source:feed.name,summary:newsSummary(item.description||item.content),category:classifyCyberNews(item)})).filter(x=>x.title&&/^https?:\/\//i.test(x.link))}));
  const good=results.filter(x=>x.status==="fulfilled").flatMap(x=>x.value),failed=results.filter(x=>x.status==="rejected");
  const seen=new Set();cyberNewsItems=good.filter(x=>{const k=x.link||x.title;if(seen.has(k))return false;seen.add(k);return true}).sort((a,b)=>new Date(b.date||0)-new Date(a.date||0));
  $("#newsUpdated").textContent="Last refreshed "+new Date().toLocaleString();
  $("#newsStatus").textContent=cyberNewsItems.length+" stories loaded from "+(results.length-failed.length)+" of "+results.length+" feeds"+(failed.length?" · "+failed.length+" feed(s) unavailable":"")+".";
  renderCyberNews();
 }catch(err){$("#newsStatus").textContent="Could not load news feeds: "+err.message}
 finally{cyberNewsBusy=false;if(btn){btn.disabled=false;btn.textContent="↻ Refresh feeds"}}
}
function view(id){$(".view").forEach(x=>x.classList.toggle("active",x.id===id));$("nav button").forEach(x=>x.classList.toggle("active",x.dataset.view===id));$("#crumb").textContent=id.toUpperCase();$("#heading").textContent=({overview:"Security command center",engineering:"Security Engineering",vapt:"VAPT & Penetration Testing",appsec:"Web Application Security",cloud:"Cloud Security",intel:"Security Intelligence",cybernews:"Cyber News Intelligence",incidents:"Incident Desk",assets:"Asset Inventory",projects:"Projects & Evidence",tracker:"Learning Tracker",references:"Reference Library",hall:"Hall of Fame"})[id];if(id==="vapt")renderRiskDashboard();if(id==="cybernews"&&!cyberNewsItems.length)loadCyberNews();window.scrollTo({top:0,behavior:"smooth"})}
function showWorkspace(){ $("#authGate").classList.add("hidden");$("#signOut").style.display="inline-block" }
function showAuth(){ $("#authGate").classList.remove("hidden");$("#signOut").style.display="none" }
async function authenticate(){
 if(busy)return;busy=true;$("#authSubmit").disabled=true;message("Working…");
 const email=$("#authForm").elements.email.value.trim(),password=$("#authForm").elements.password.value;
 try{
  const result=authMode==="signin"?await client.auth.signInWithPassword({email,password}):await client.auth.signUp({email,password});
  if(result.error)throw result.error;
  if(authMode==="signup"&&!result.data.session){message("Account created. Check your email to confirm, then sign in.");}
  else message("Authenticated. Loading your workspace…");
 }catch(e){message(e.message)}finally{busy=false;$("#authSubmit").disabled=false}
}
async function start(){
 if(!client){showAuth();message(cfg?.url?"Could not load the Supabase client library. Check your connection, refresh the page, and try again.":"Supabase configuration is missing. Check supabase-config.js.");return}
 $("#authForm").addEventListener("submit",e=>{e.preventDefault();authenticate()});
 $("#authMode").addEventListener("click",()=>{authMode=authMode==="signin"?"signup":"signin";$("#authTitle").textContent=authMode==="signin"?"Sign in to BLACKSITE":"Create your BLACKSITE account";$("#authSubmit").textContent=authMode==="signin"?"Sign in":"Create account";$("#authMode").textContent=authMode==="signin"?"Create your account":"Back to sign in";$("#authForm").elements.password.autocomplete=authMode==="signin"?"current-password":"new-password";message("")});
 $("#signOut").addEventListener("click",async()=>{await client.auth.signOut();state=freshState();showAuth();setStatus("SIGNED OUT")});
 client.auth.onAuthStateChange(async(_event,session)=>{
  if(session?.user){user=session.user;showWorkspace();$("#authMessage").textContent="";try{await loadWorkspace()}catch(e){setStatus("SYNC ERROR");alert("Workspace load failed: "+e.message)}}
  else{user=null;showAuth()}
 });
 const {data:{session},error}=await client.auth.getSession();if(error)message(error.message);
 if(session?.user){user=session.user;showWorkspace();try{await loadWorkspace()}catch(e){setStatus("SYNC ERROR");message(e.message)}}
 else showAuth();
}
document.addEventListener("click",e=>{const b=e.target.closest("#nav button[data-view]");if(!b)return;e.preventDefault();const target=b.dataset.view;if(document.getElementById(target))view(target)},true);
$("#refreshCyberNews").addEventListener("click",loadCyberNews);
$("#newsCategory").addEventListener("change",renderCyberNews);
$("#newsSearch").addEventListener("input",renderCyberNews);
$("#newsFeed").addEventListener("click",e=>{if(e.target.closest("[data-news-refresh]"))loadCyberNews()});
document.addEventListener("click",async e=>{
 const ev=e.target.closest("[data-evidence]");if(ev&&user){try{const {data,error}=await client.storage.from("security-evidence").createSignedUrl(ev.dataset.path,60);if(error)throw error;window.open(data.signedUrl,"_blank","noopener")}catch(err){alert("Could not open evidence: "+err.message)}}
 const hallEv=e.target.closest("[data-hall-evidence]");if(hallEv&&user){const record=state.achievements.find(x=>x.id===hallEv.dataset.hallEvidence);if(record?.content?.path){try{const {data,error}=await client.storage.from("security-evidence").createSignedUrl(record.content.path,60);if(error)throw error;window.open(data.signedUrl,"_blank","noopener")}catch(err){alert("Could not open attachment: "+err.message)}}}

 const b=e.target.closest("[data-jump]");if(b)view(b.dataset.jump);
 const r=e.target.closest("[data-remove]");if(r&&user){try{const entry=Object.values(state).filter(Array.isArray).flat().find(x=>x&&x.id===r.dataset.id);if(entry?.content?.path){const gone=await client.storage.from("security-evidence").remove([entry.content.path]);if(gone.error)throw gone.error}await removeRecord(r.dataset.id);await loadWorkspace()}catch(err){alert("Delete failed: "+err.message)}}
});
document.addEventListener("change",async e=>{
 if(e.target.matches("[data-check]")){state.checks[e.target.dataset.check]=e.target.checked;e.target.closest(".check").classList.toggle("done",e.target.checked);try{setStatus("SAVING");await persistChecks()}catch(err){setStatus("SYNC ERROR");alert("Checklist save failed: "+err.message)}}
});
$("#findingForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");await insertRecord("finding",f.get("title"),{domain:f.get("domain")},"open",dbSeverity(f.get("severity")));await logActivity("Finding logged",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save finding: "+err.message)}};
$("#projectForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const project=await insertRecord("project",f.get("name"),{domain:f.get("domain"),summary:f.get("summary"),repo:f.get("repo"),stack:f.get("stack"),tags:String(f.get("tags")||"").split(",").map(x=>x.trim()).filter(Boolean)},dbStatus(f.get("status")),null,f.get("url")||null);for(const file of [...e.target.elements.evidence.files]){if(file.size>20*1024*1024)throw new Error(file.name+" exceeds the 20 MB limit");const path=user.id+"/"+crypto.randomUUID()+"-"+file.name.replace(/[^a-zA-Z0-9._-]/g,"_");const up=await client.storage.from("security-evidence").upload(path,file,{contentType:file.type,upsert:false});if(up.error)throw up.error;await insertRecord("evidence",file.name,{filename:file.name,path,size:file.size,mime:file.type,project_id:project.id},"completed");}await logActivity("Project updated",f.get("name"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save project/evidence: "+err.message)}};
$("#hallForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);const file=e.target.elements.evidence.files[0];try{setStatus("SAVING");let content={category:f.get("category"),issuer:f.get("issuer"),date:f.get("date"),description:f.get("description")};if(file){if(file.size>20*1024*1024)throw new Error(file.name+" exceeds the 20 MB limit");const path=user.id+"/"+crypto.randomUUID()+"-"+file.name.replace(/[^a-zA-Z0-9._-]/g,"_");const up=await client.storage.from("security-evidence").upload(path,file,{contentType:file.type,upsert:false});if(up.error)throw up.error;content={...content,filename:file.name,path,size:file.size,mime:file.type}}await insertRecord("achievement",f.get("title"),content,"completed",null,f.get("url")||null);await logActivity("Hall of Fame entry added",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save Hall of Fame entry: "+err.message)}};
$("#labForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const evidence=await attachEvidence(e.target.elements.evidence.files[0]);await insertRecord("learning",f.get("name"),{domain:f.get("domain"),source:f.get("source"),notes:f.get("notes"),hours:Number(f.get("hours")||0),difficulty:f.get("difficulty"),...evidence},dbStatus(f.get("status")),null,f.get("url")||null);await logActivity("Learning activity logged",f.get("name"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save learning activity: "+err.message)}};


$("#findingImportForm").onsubmit=async e=>{e.preventDefault();const file=e.target.elements.file.files[0];if(!file)return;if(file.size>20*1024*1024){alert("Import file exceeds 20 MB");return}try{const raw=await file.text();let rows;if(file.name.toLowerCase().endsWith(".json")){const p=JSON.parse(raw);rows=Array.isArray(p)?p:(p.findings||p.vulnerabilities||p.results||[]);if(!Array.isArray(rows))throw new Error("JSON must contain an array of findings.")}else rows=parseFindingCSV(raw);const domain=new FormData(e.target).get("domain");pendingFindingImport=rows.map(x=>normalizeImportedFinding(x,domain)).filter(x=>x.title);const host=$("#findingImportPreview");host.innerHTML=pendingFindingImport.length?'<p class="empty">Validated '+pendingFindingImport.length+' finding(s). Review the sample, then confirm import.</p>'+pendingFindingImport.slice(0,8).map(x=>recordCard({id:"preview",title:x.title,content:x.content,severity:x.severity,status:x.status},[x.severity,x.content.asset,x.content.cve,x.content.cvss?"CVSS "+x.content.cvss:""].filter(Boolean).join(" · "),"preview")).join("")+'<button type="button" class="primary" id="confirmFindingImport">Import '+pendingFindingImport.length+' findings</button>':'<p class="empty">No valid finding titles found. Check the file headers.</p>'}catch(err){pendingFindingImport=[];$("#findingImportPreview").textContent="Could not parse file: "+err.message}};
$("#findingImportPreview").addEventListener("click",async e=>{if(e.target.id!=="confirmFindingImport"||!pendingFindingImport.length)return;const btn=e.target;btn.disabled=true;try{setStatus("IMPORTING");const batch=pendingFindingImport;for(const x of batch)await insertRecord("finding",x.title,x.content,x.status,x.severity);pendingFindingImport=[];$("#findingImportPreview").innerHTML='<p class="empty">Imported '+batch.length+' findings successfully.</p>';await logActivity("Scan findings imported",batch.length+" records from CSV / JSON");await loadWorkspace()}catch(err){btn.disabled=false;setStatus("SYNC ERROR");alert("Import stopped: "+err.message+" Some rows may already be saved; review the register before retrying.")}});
$("#findingDetailForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const evidence=await attachEvidence(e.target.elements.evidence.files[0]);const status=({"Open":"open","In progress":"in_progress","Resolved":"completed","Accepted risk":"accepted","False positive":"false_positive"})[f.get("status")];await insertRecord("finding",f.get("title"),{domain:f.get("domain"),asset:f.get("asset"),cve:f.get("cve"),cvss:f.get("cvss"),due_date:f.get("due_date"),likelihood:Number(f.get("likelihood")),impact:Number(f.get("impact")),notes:f.get("notes"),remediation:f.get("remediation"),...(evidence||{})},status,dbSeverity(f.get("severity")));await logActivity("Vulnerability added",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save vulnerability: "+err.message)}};
$("#controlForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const evidence=await attachEvidence(e.target.elements.evidence.files[0]);await insertRecord("control",f.get("title"),{framework:f.get("framework"),owner:f.get("owner"),review:f.get("review"),notes:f.get("notes"),...evidence},({"Planned":"open","In progress":"in_progress","Passed":"completed","Failed":"open","Needs review":"open"})[f.get("status")]);await logActivity("Control validation saved",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save control: "+err.message)}};
$("#appTestForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const evidence=await attachEvidence(e.target.elements.evidence.files[0]);await insertRecord("app_test",f.get("asset")+" · "+f.get("category"),{asset:f.get("asset"),endpoint:f.get("endpoint"),category:f.get("category"),result:f.get("result"),method:f.get("method"),notes:f.get("notes"),...evidence},f.get("result")==="Passed"?"completed":"open");await logActivity("Application test logged",f.get("asset")+" · "+f.get("category"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save test case: "+err.message)}};
$("#cloudAssetForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const evidence=await attachEvidence(e.target.elements.evidence.files[0]);await insertRecord("cloud_asset",f.get("title"),{provider:f.get("provider"),environment:f.get("environment"),exposure:f.get("exposure"),criticality:f.get("criticality"),posture:f.get("posture"),location:f.get("location"),notes:f.get("notes"),...evidence},f.get("posture")==="Healthy"?"completed":"open",dbSeverity(f.get("criticality")));await logActivity("Cloud asset registered",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save cloud asset: "+err.message)}};
$("#intelForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const evidence=await attachEvidence(e.target.elements.evidence.files[0]);await insertRecord("intel",f.get("title"),{type:f.get("type"),confidence:f.get("confidence"),date:f.get("date"),notes:f.get("notes"),...evidence},"open",dbSeverity(f.get("severity")),f.get("url")||null);await logActivity("Threat intel record saved",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save intel: "+err.message)}};
$("#incidentForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const evidence=await attachEvidence(e.target.elements.evidence.files[0]);await insertRecord("incident",f.get("title"),{type:f.get("type"),status:f.get("status"),date:f.get("date"),summary:f.get("summary"),lessons:f.get("lessons"),notes:f.get("lessons"),...evidence},f.get("status").toLowerCase(),dbSeverity(f.get("severity")));await logActivity("Incident record saved",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save incident: "+err.message)}};
$("#assetForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const evidence=await attachEvidence(e.target.elements.evidence.files[0]);await insertRecord("asset",f.get("title"),{type:f.get("type"),environment:f.get("environment"),authorization:f.get("authorization"),owner:f.get("owner"),criticality:f.get("criticality"),review:f.get("review"),notes:f.get("notes"),...evidence},"open",dbSeverity(f.get("criticality")),f.get("url")||null);await logActivity("Asset registered",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not register asset: "+err.message)}};
$("#referenceForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");await insertRecord("reference",f.get("title"),{type:f.get("type"),notes:f.get("notes")},"completed",null,f.get("url"));await logActivity("Reference bookmarked",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save bookmark: "+err.message)}};
["findingSearch","findingSeverityFilter"].forEach(id=>$("#"+id)?.addEventListener("input",()=>render()));
$("#export").onclick=()=>{const a=document.createElement("a"),u=URL.createObjectURL(new Blob([JSON.stringify({projects:state.projects,labs:state.labs,findings:state.findings,achievements:state.achievements,controls:state.controls,appTests:state.appTests,cloudAssets:state.cloudAssets,intel:state.intel,incidents:state.incidents,assets:state.assets,references:state.references,checks:state.checks,activity:state.activity},null,2)],{type:"application/json"}));a.href=u;a.download="blacksite-workspace-backup.json";a.click();URL.revokeObjectURL(u)};
$("#date").textContent=new Date().toLocaleDateString(undefined,{year:"numeric",month:"short",day:"numeric"});
addChecks("engChecks",tracks.engineering);addChecks("vaptChecks",tracks.vapt);addChecks("appChecks",tracks.app);addChecks("cloudChecks",tracks.cloud);
start();
