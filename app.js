const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const tracks={
 engineering:["Define system context, assets and trust boundaries","Write a threat model with abuse cases and mitigations","Harden identity, endpoint, network and platform baselines","Add secrets scanning, SAST, SCA and IaC checks to CI/CD","Validate logging, alerting, backup and recovery controls","Document control owner, evidence and exception expiry"],
 vapt:["Obtain written authorization, scope, ROE and test window","Confirm assets, exclusions, rate limits and emergency contacts","Perform discovery and map attack surface within scope","Validate vulnerabilities safely and preserve redacted evidence","Rate business impact and write actionable remediation","Retest fixes and record residual risk and closure"],
 app:["Map roles, trust boundaries, endpoints and API inventory","Test authentication, session lifecycle and MFA behavior","Test object- and function-level authorization (BOLA/BFLA)","Review injection, XSS, CSRF, SSRF and file handling","Test business logic, rate limits and security headers","Validate fixes with regression tests and ASVS requirements"],
 cloud:["Inventory accounts, projects, subscriptions and workloads","Review IAM roles, federation, MFA and privilege paths","Check public exposure, segmentation and security groups","Review encryption, key lifecycle, secrets and storage policy","Enable audit logs, detections, retention and alert routing","Scan IaC and containers; track exceptions and remediation"]
};
const cfg=window.BLACKSITE_SUPABASE;
const client=window.supabase?.createClient(cfg?.url,cfg?.publishableKey);
const starter={projects:[],labs:[],findings:[],evidence:[],achievements:[],controls:[],appTests:[],cloudAssets:[],intel:[],incidents:[],assets:[],references:[],checks:{},activity:[]};
const charts={};
const severityValue=v=>({informational:"info"}[String(v||"").toLowerCase()]||String(v||"").toLowerCase());
function recordCard(r,meta,kind){return '<div class="record"><div><b>'+safe(r.title)+'</b><small>'+safe(meta||"")+'</small>'+(r.content?.notes?'<small>'+safe(r.content.notes)+'</small>':"")+(r.reference_url&&/^https?:\\/\\//i.test(r.reference_url)?'<small><a href="'+safe(r.reference_url)+'" target="_blank" rel="noopener noreferrer">Open source ↗</a></small>':"")+(r.content?.path?'<small><button type="button" class="inline-link" data-evidence="'+safe(r.id)+'" data-path="'+safe(r.content.path)+'">Open attachment ↗</button></small>':"")+'</div><button data-remove="'+kind+'" data-id="'+safe(r.id)+'">Remove</button></div>'}
function drawChart(id,type,labels,values,label){if(!window.Chart)return;const c=document.getElementById(id);if(!c)return;if(charts[id])charts[id].destroy();charts[id]=new Chart(c,{type,data:{labels,datasets:[{label,data:values,borderWidth:2,borderRadius:type==="bar"?5:0,backgroundColor:type==="doughnut"?["#ff647c","#ffad66","#f7d56b","#70c7b2","#71869d"]:"rgba(199,255,114,.18)",borderColor:"#c7ff72",tension:.35,fill:type==="line"}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:type==="doughnut",labels:{color:"#a9bbce",boxWidth:9,font:{size:10}}}},scales:type==="doughnut"?{}:{x:{ticks:{color:"#8fa3b8",font:{size:9}},grid:{color:"#24364a"}},y:{beginAtZero:true,ticks:{color:"#8fa3b8",precision:0,font:{size:9}},grid:{color:"#24364a"}}}}}})}
function renderCharts(){const keys=["critical","high","medium","low","info"],counts=keys.map(k=>state.findings.filter(x=>severityValue(x.severity)===k).length);drawChart("severityChart","doughnut",["Critical","High","Medium","Low","Info"],counts,"Findings");drawChart("vaptChart","doughnut",["Critical","High","Medium","Low","Info"],counts,"Findings");const now=new Date(),months=[];for(let i=5;i>=0;i--){const d=new Date(now.getFullYear(),now.getMonth()-i,1);months.push({label:d.toLocaleString(undefined,{month:"short"}),year:d.getFullYear(),month:d.getMonth()})}drawChart("trendChart","line",months.map(x=>x.label),months.map(m=>state.findings.filter(x=>{const d=new Date(x.created_at||x.updated_at||0);return d.getFullYear()===m.year&&d.getMonth()===m.month}).length),"Created");drawChart("findingStatusChart","doughnut",["Open","In progress","Resolved"],[state.findings.filter(x=>!["completed","resolved","closed"].includes(x.status)).length,state.findings.filter(x=>x.status==="in_progress").length,state.findings.filter(x=>["completed","resolved","closed"].includes(x.status)).length],"Status");drawChart("cloudExposureChart","doughnut",["Public","Private","Internal","Unknown"],["Public","Private","Internal","Unknown"].map(k=>state.cloudAssets.filter(x=>x.content?.exposure===k).length),"Exposure");drawChart("cloudPostureChart","doughnut",["Healthy","Needs review","Misconfigured","Exception"],["Healthy","Needs review","Misconfigured","Exception accepted"].map(k=>state.cloudAssets.filter(x=>x.content?.posture===k).length),"Posture")}
async function attachEvidence(file){if(!file)return null;if(file.size>20*1024*1024)throw new Error(file.name+" exceeds 20 MB");const ext=(file.name.split(".").pop()||"").toLowerCase(),allowed=["pdf","png","jpg","jpeg","txt","csv","json","zip"];if(!allowed.includes(ext))throw new Error("Unsupported file type: "+file.name);const path=user.id+"/"+crypto.randomUUID()+"-"+file.name.replace(/[^a-zA-Z0-9._-]/g,"_");const types={pdf:"application/pdf",png:"image/png",jpg:"image/jpeg",jpeg:"image/jpeg",txt:"text/plain",csv:"text/csv",json:"application/json",zip:"application/zip"};const up=await client.storage.from("security-evidence").upload(path,file,{contentType:file.type||types[ext],upsert:false});if(up.error)throw up.error;return {filename:file.name,path,size:file.size,mime:file.type||types[ext]}}
let state={...starter},user=null,checklistId=null,authMode="signin",busy=false;
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
 state={...starter};checklistId=null;
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
 $("#projectList").innerHTML=state.projects.length?state.projects.map(x=>'<div class="record"><div><b>'+safe(x.title)+'</b><small>'+safe(x.content?.domain)+' · '+safe(x.status)+' · '+safe(x.content?.summary||"No summary added")+'</small>'+(x.reference_url?'<small><a href="'+safe(x.reference_url)+'" target="_blank" rel="noreferrer">Evidence ↗</a></small>':"")+'</div><button data-remove="project" data-id="'+x.id+'">Remove</button></div>').join(""):'<p class="empty">No projects yet. Add a project and link verifiable evidence.</p>';
 $("#labList").innerHTML=state.labs.length?state.labs.map(x=>'<div class="record"><div><b>'+safe(x.title)+'</b><small>'+safe(x.content?.domain)+' · '+safe(x.status)+' · '+safe(x.content?.source||"")+' · '+safe(x.content?.notes||"")+'</small></div><button data-remove="learning" data-id="'+x.id+'">Remove</button></div>').join(""):'<p class="empty">No learning activities logged yet.</p>';
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
}
function view(id){$$(".view").forEach(x=>x.classList.toggle("active",x.id===id));$$("nav button").forEach(x=>x.classList.toggle("active",x.dataset.view===id));$("#crumb").textContent=id.toUpperCase();$("#heading").textContent=({overview:"Security command center",engineering:"Security Engineering",vapt:"VAPT & Penetration Testing",appsec:"Web Application Security",cloud:"Cloud Security",intel:"Security Intelligence",incidents:"Incident Desk",assets:"Asset Inventory",projects:"Projects & Evidence",tracker:"Learning Tracker",references:"Reference Library",hall:"Hall of Fame"})[id];window.scrollTo({top:0,behavior:"smooth"})}
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
 if(!client){showAuth();message("Supabase configuration is missing. Check supabase-config.js.");return}
 $("#authForm").addEventListener("submit",e=>{e.preventDefault();authenticate()});
 $("#authMode").addEventListener("click",()=>{authMode=authMode==="signin"?"signup":"signin";$("#authTitle").textContent=authMode==="signin"?"Sign in to BLACKSITE":"Create your BLACKSITE account";$("#authSubmit").textContent=authMode==="signin"?"Sign in":"Create account";$("#authMode").textContent=authMode==="signin"?"Create your account":"Back to sign in";$("#authForm").elements.password.autocomplete=authMode==="signin"?"current-password":"new-password";message("")});
 $("#signOut").addEventListener("click",async()=>{await client.auth.signOut();state={...starter};showAuth();setStatus("SIGNED OUT")});
 client.auth.onAuthStateChange(async(_event,session)=>{
  if(session?.user){user=session.user;showWorkspace();$("#authMessage").textContent="";try{await loadWorkspace()}catch(e){setStatus("SYNC ERROR");alert("Workspace load failed: "+e.message)}}
  else{user=null;showAuth()}
 });
 const {data:{session},error}=await client.auth.getSession();if(error)message(error.message);
 if(session?.user){user=session.user;showWorkspace();try{await loadWorkspace()}catch(e){setStatus("SYNC ERROR");message(e.message)}}
 else showAuth();
}
$("#nav").addEventListener("click",e=>{const b=e.target.closest("[data-view]");if(b)view(b.dataset.view)});
document.addEventListener("click",async e=>{
 const ev=e.target.closest("[data-evidence]");if(ev&&user){try{const {data,error}=await client.storage.from("security-evidence").createSignedUrl(ev.dataset.path,60);if(error)throw error;window.open(data.signedUrl,"_blank","noopener")}catch(err){alert("Could not open evidence: "+err.message)}}
 const hallEv=e.target.closest("[data-hall-evidence]");if(hallEv&&user){const record=state.achievements.find(x=>x.id===hallEv.dataset.hallEvidence);if(record?.content?.path){try{const {data,error}=await client.storage.from("security-evidence").createSignedUrl(record.content.path,60);if(error)throw error;window.open(data.signedUrl,"_blank","noopener")}catch(err){alert("Could not open attachment: "+err.message)}}}

 const b=e.target.closest("[data-jump]");if(b)view(b.dataset.jump);
 const r=e.target.closest("[data-remove]");if(r&&user){try{if(r.dataset.remove==="achievement"){const entry=state.achievements.find(x=>x.id===r.dataset.id);if(entry?.content?.path){const gone=await client.storage.from("security-evidence").remove([entry.content.path]);if(gone.error)throw gone.error}}await removeRecord(r.dataset.id);await loadWorkspace()}catch(err){alert("Delete failed: "+err.message)}}
});
document.addEventListener("change",async e=>{
 if(e.target.matches("[data-check]")){state.checks[e.target.dataset.check]=e.target.checked;e.target.closest(".check").classList.toggle("done",e.target.checked);try{setStatus("SAVING");await persistChecks()}catch(err){setStatus("SYNC ERROR");alert("Checklist save failed: "+err.message)}}
});
$("#findingForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");await insertRecord("finding",f.get("title"),{domain:f.get("domain")},"open",dbSeverity(f.get("severity")));await logActivity("Finding logged",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save finding: "+err.message)}};
$("#projectForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const project=await insertRecord("project",f.get("name"),{domain:f.get("domain"),summary:f.get("summary")},dbStatus(f.get("status")),null,f.get("url")||null);for(const file of [...e.target.elements.evidence.files]){if(file.size>20*1024*1024)throw new Error(file.name+" exceeds the 20 MB limit");const path=user.id+"/"+crypto.randomUUID()+"-"+file.name.replace(/[^a-zA-Z0-9._-]/g,"_");const up=await client.storage.from("security-evidence").upload(path,file,{contentType:file.type,upsert:false});if(up.error)throw up.error;await insertRecord("evidence",file.name,{filename:file.name,path,size:file.size,mime:file.type,project_id:project.id},"completed");}await logActivity("Project updated",f.get("name"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save project/evidence: "+err.message)}};
$("#hallForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);const file=e.target.elements.evidence.files[0];try{setStatus("SAVING");let content={category:f.get("category"),issuer:f.get("issuer"),date:f.get("date"),description:f.get("description")};if(file){if(file.size>20*1024*1024)throw new Error(file.name+" exceeds the 20 MB limit");const path=user.id+"/"+crypto.randomUUID()+"-"+file.name.replace(/[^a-zA-Z0-9._-]/g,"_");const up=await client.storage.from("security-evidence").upload(path,file,{contentType:file.type,upsert:false});if(up.error)throw up.error;content={...content,filename:file.name,path,size:file.size,mime:file.type}}await insertRecord("achievement",f.get("title"),content,"completed",null,f.get("url")||null);await logActivity("Hall of Fame entry added",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save Hall of Fame entry: "+err.message)}};
$("#labForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");await insertRecord("learning",f.get("name"),{domain:f.get("domain"),source:f.get("source"),notes:f.get("notes")},dbStatus(f.get("status")));await logActivity("Learning activity logged",f.get("name"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save learning activity: "+err.message)}};

$("#findingDetailForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const evidence=await attachEvidence(e.target.elements.evidence.files[0]);const status=({"Open":"open","In progress":"in_progress","Resolved":"completed","Accepted risk":"accepted","False positive":"false_positive"})[f.get("status")];await insertRecord("finding",f.get("title"),{domain:f.get("domain"),asset:f.get("asset"),cve:f.get("cve"),cvss:f.get("cvss"),due_date:f.get("due_date"),notes:f.get("notes"),remediation:f.get("remediation"),...evidence},status,dbSeverity(f.get("severity")));await logActivity("Vulnerability added",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save vulnerability: "+err.message)}};
$("#controlForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const evidence=await attachEvidence(e.target.elements.evidence.files[0]);await insertRecord("control",f.get("title"),{framework:f.get("framework"),owner:f.get("owner"),review:f.get("review"),notes:f.get("notes"),...evidence},({"Planned":"open","In progress":"in_progress","Passed":"completed","Failed":"open","Needs review":"open"})[f.get("status")]);await logActivity("Control validation saved",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save control: "+err.message)}};
$("#appTestForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const evidence=await attachEvidence(e.target.elements.evidence.files[0]);await insertRecord("app_test",f.get("asset")+" · "+f.get("category"),{asset:f.get("asset"),endpoint:f.get("endpoint"),category:f.get("category"),result:f.get("result"),method:f.get("method"),notes:f.get("notes"),...evidence},f.get("result")==="Passed"?"completed":"open");await logActivity("Application test logged",f.get("asset")+" · "+f.get("category"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save test case: "+err.message)}};
$("#cloudAssetForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const evidence=await attachEvidence(e.target.elements.evidence.files[0]);await insertRecord("cloud_asset",f.get("title"),{provider:f.get("provider"),environment:f.get("environment"),exposure:f.get("exposure"),criticality:f.get("criticality"),posture:f.get("posture"),location:f.get("location"),notes:f.get("notes"),...evidence},f.get("posture")==="Healthy"?"completed":"open",dbSeverity(f.get("criticality")));await logActivity("Cloud asset registered",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save cloud asset: "+err.message)}};
$("#intelForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const evidence=await attachEvidence(e.target.elements.evidence.files[0]);await insertRecord("intel",f.get("title"),{type:f.get("type"),confidence:f.get("confidence"),date:f.get("date"),notes:f.get("notes"),...evidence},"open",dbSeverity(f.get("severity")),f.get("url")||null);await logActivity("Threat intel record saved",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save intel: "+err.message)}};
$("#incidentForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const evidence=await attachEvidence(e.target.elements.evidence.files[0]);await insertRecord("incident",f.get("title"),{type:f.get("type"),status:f.get("status"),date:f.get("date"),summary:f.get("summary"),lessons:f.get("lessons"),notes:f.get("lessons"),...evidence},f.get("status").toLowerCase(),dbSeverity(f.get("severity")));await logActivity("Incident record saved",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save incident: "+err.message)}};
$("#assetForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");const evidence=await attachEvidence(e.target.elements.evidence.files[0]);await insertRecord("asset",f.get("title"),{type:f.get("type"),environment:f.get("environment"),authorization:f.get("authorization"),owner:f.get("owner"),criticality:f.get("criticality"),review:f.get("review"),notes:f.get("notes"),...evidence},"open",dbSeverity(f.get("criticality")),f.get("url")||null);await logActivity("Asset registered",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not register asset: "+err.message)}};
$("#referenceForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{setStatus("SAVING");await insertRecord("reference",f.get("title"),{type:f.get("type"),notes:f.get("notes")},"completed",null,f.get("url"));await logActivity("Reference bookmarked",f.get("title"));await loadWorkspace();e.target.reset()}catch(err){setStatus("SYNC ERROR");alert("Could not save bookmark: "+err.message)}};
["findingSearch","findingSeverityFilter"].forEach(id=>$("#"+id)?.addEventListener("input",()=>render()));
$("#export").onclick=()=>{const a=document.createElement("a"),u=URL.createObjectURL(new Blob([JSON.stringify({projects:state.projects,labs:state.labs,findings:state.findings,achievements:state.achievements,checks:state.checks,activity:state.activity},null,2)],{type:"application/json"}));a.href=u;a.download="blacksite-workspace-backup.json";a.click();URL.revokeObjectURL(u)};
$("#date").textContent=new Date().toLocaleDateString(undefined,{year:"numeric",month:"short",day:"numeric"});
addChecks("engChecks",tracks.engineering);addChecks("vaptChecks",tracks.vapt);addChecks("appChecks",tracks.app);addChecks("cloudChecks",tracks.cloud);
start();
