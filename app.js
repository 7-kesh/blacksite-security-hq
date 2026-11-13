const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const tracks={
 engineering:["Define system context, assets and trust boundaries","Write a threat model with abuse cases and mitigations","Harden identity, endpoint, network and platform baselines","Add secrets scanning, SAST, SCA and IaC checks to CI/CD","Validate logging, alerting, backup and recovery controls","Document control owner, evidence and exception expiry"],
 vapt:["Obtain written authorization, scope, ROE and test window","Confirm assets, exclusions, rate limits and emergency contacts","Perform discovery and map attack surface within scope","Validate vulnerabilities safely and preserve redacted evidence","Rate business impact and write actionable remediation","Retest fixes and record residual risk and closure"],
 app:["Map roles, trust boundaries, endpoints and API inventory","Test authentication, session lifecycle and MFA behavior","Test object- and function-level authorization (BOLA/BFLA)","Review injection, XSS, CSRF, SSRF and file handling","Test business logic, rate limits and security headers","Validate fixes with regression tests and ASVS requirements"],
 cloud:["Inventory accounts, projects, subscriptions and workloads","Review IAM roles, federation, MFA and privilege paths","Check public exposure, segmentation and security groups","Review encryption, key lifecycle, secrets and storage policy","Enable audit logs, detections, retention and alert routing","Scan IaC and containers; track exceptions and remediation"]
};
const cfg=window.BLACKSITE_SUPABASE;
const client=window.supabase?.createClient(cfg?.url,cfg?.publishableKey);
const starter={projects:[],labs:[],findings:[],evidence:[],achievements:[],checks:{},activity:[]};
let state={...starter},user=null,checklistId=null,authMode="signin",busy=false;
function safe(s=""){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function setStatus(t){const el=$("#syncStatus");if(el)el.textContent=t}
function message(t){$("#authMessage").textContent=t}
function note(action,detail){state.activity.unshift({action,detail,at:new Date().toISOString()});state.activity=state.activity.slice(0,12)}
function item(kind,title,content,status="open",severity=null,reference_url=null){return {user_id:user.id,kind,title,status,severity,content,reference_url,tags:[]}}
function dbStatus(value){return ({"Planned":"open","In progress":"in_progress","Completed":"completed"})[value]||value}
function dbSeverity(value){return value==="Informational"?"info":String(value||"").toLowerCase()}
function fromRow(r){return {id:r.id,...(r.content||{}),title:r.title,status:r.status,severity:r.severity,reference_url:r.reference_url,updated_at:r.updated_at}}
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

}
function view(id){$$(".view").forEach(x=>x.classList.toggle("active",x.id===id));$$("nav button").forEach(x=>x.classList.toggle("active",x.dataset.view===id));$("#crumb").textContent=id.toUpperCase();$("#heading").textContent=({overview:"Security command center",engineering:"Security Engineering",vapt:"VAPT & Penetration Testing",appsec:"Web Application Security",cloud:"Cloud Security",intel:"Security Intelligence",projects:"Projects & Evidence",tracker:"Learning Tracker",references:"Reference Library",hall:"Hall of Fame"})[id];window.scrollTo({top:0,behavior:"smooth"})}
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
$("#export").onclick=()=>{const a=document.createElement("a"),u=URL.createObjectURL(new Blob([JSON.stringify({projects:state.projects,labs:state.labs,findings:state.findings,achievements:state.achievements,checks:state.checks,activity:state.activity},null,2)],{type:"application/json"}));a.href=u;a.download="blacksite-workspace-backup.json";a.click();URL.revokeObjectURL(u)};
$("#date").textContent=new Date().toLocaleDateString(undefined,{year:"numeric",month:"short",day:"numeric"});
addChecks("engChecks",tracks.engineering);addChecks("vaptChecks",tracks.vapt);addChecks("appChecks",tracks.app);addChecks("cloudChecks",tracks.cloud);
start();
