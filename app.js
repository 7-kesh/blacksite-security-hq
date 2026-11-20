(() => {
"use strict";
const $ = (selector, root=document) => root.querySelector(selector);
const $$ = (selector, root=document) => Array.from(root.querySelectorAll(selector));
const cfg = window.BLACKSITE_SUPABASE || {};
let client = null, currentUser = null, records = [], checklistRow = null, checks = {}, authMode = "signin", busy = false;
const bucket = "security-evidence";
const kinds = ["project","finding","learning","checklist","intel","note","evidence","achievement","control","app_test","cloud_asset","incident","asset","reference"];
const titles = {overview:"Security command center",projects:"Projects & Evidence",engineering:"Security Engineering",vapt:"VAPT & Risk Command Center",appsec:"Web Application Security",cloud:"Cloud Security",intel:"Threat Intelligence",cybernews:"Cyber News Intelligence",incidents:"Incident Desk",assets:"Asset Inventory",learning:"Learning Tracker",references:"Reference Library",hall:"Hall of Fame"};
const tracks = {
 engineering:["Map systems, data flows, trust boundaries and critical assets","Document threats, abuse cases and security requirements","Harden identity, endpoints, network and platform baselines","Integrate SAST, SCA, secrets and IaC checks into CI/CD","Validate logging, alerting, backup and recovery controls","Assign owners and expiry dates to security exceptions"],
 cloud:["Inventory cloud accounts, subscriptions and workloads","Review IAM, MFA, federation and privilege escalation paths","Check public exposure, segmentation and security groups","Review encryption, key rotation, secrets and storage policies","Enable audit logs, detections, retention and alert routing","Scan IaC and containers; track remediation and exceptions"]
};
const escapeHtml = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const setStatus = (message, ok=false) => { const el=$("#syncStatus"); if(el){el.textContent=message;el.parentElement.classList.toggle("ok",ok);} };
const showMessage = message => { const el=$("#authMessage"); if(el) el.textContent=message; };
const today = () => new Date().toISOString().slice(0,10);
const isActiveFinding = r => r.kind==="finding" && !["completed","accepted","false_positive","archived"].includes(r.status);
const severityRank = s => ({critical:5,high:4,medium:3,low:2,info:1}[String(s||"").toLowerCase()]||0);
const scoreFinding = r => { const cv=Number(r.content?.cvss); if(Number.isFinite(cv)&&cv>=0&&cv<=10&&r.content?.cvss!=="")return cv; const l=Number(r.content?.likelihood),i=Number(r.content?.impact); if(l>=1&&l<=5&&i>=1&&i<=5)return Math.round((l*i/25)*100)/10; return ({critical:9.5,high:7.5,medium:5,low:2.5,info:0.5}[r.severity]||0); };
const messageForm = (form,msg) => { const el=$(".form-status",form); if(el)el.textContent=msg; };
function navigate(view){
 if(!titles[view]) return;
 $$("[data-panel]").forEach(panel=>panel.classList.toggle("active",panel.dataset.panel===view));
 $$("#nav [data-view]").forEach(button=>button.classList.toggle("active",button.dataset.view===view));
 $("#crumb").textContent=view.toUpperCase();
 $("#pageTitle").textContent=titles[view];
 window.scrollTo({top:0,behavior:"smooth"});
}
function authVisible(visible){$("#authGate").classList.toggle("hidden",!visible);$("#appShell").classList.toggle("hidden",visible);}
function fromRow(row){return {...row,content:row.content||{},tags:row.tags||[]};}
async function loadWorkspace(){
 setStatus("SYNCING");
 const {data,error}=await client.from("workspace_items").select("*").order("updated_at",{ascending:false});
 if(error) throw error;
 records=(data||[]).map(fromRow);
 const check=records.find(r=>r.kind==="checklist"&&r.title==="checklist-progress");
 checklistRow=check||null; checks=check?.content?.checks||{};
 renderAll();setStatus("CLOUD SYNCED",true);
}
function renderChecklist(id,items){
 const host=$("#"+id); if(!host)return;
 host.innerHTML=items.map((label,index)=>{const key=id+"-"+index;return '<label class="check-item '+(checks[key]?"done":"")+'"><input type="checkbox" data-check="'+key+'" '+(checks[key]?"checked":"")+'><span>'+escapeHtml(label)+'</span></label>';}).join("");
}
async function saveChecklist(){
 const payload={user_id:currentUser.id,kind:"checklist",title:"checklist-progress",status:"in_progress",severity:null,content:{checks},tags:[]};
 let result;
 if(checklistRow){result=await client.from("workspace_items").update(payload).eq("id",checklistRow.id).select().single();}
 else {result=await client.from("workspace_items").insert(payload).select().single();}
 if(result.error)throw result.error;checklistRow=fromRow(result.data);
}
function renderRecord(r){
 const meta=[r.kind.replaceAll("_"," "),r.content?.domain,r.content?.type,r.severity,r.status?.replaceAll("_"," ")].filter(Boolean).join(" · ");
 const details=[r.content?.asset,r.content?.cve,r.content?.framework,r.content?.provider,r.content?.endpoint,r.content?.owner,r.content?.issuer,r.content?.source,r.content?.date,r.content?.due_date].filter(Boolean).join(" · ");
 const note=r.content?.notes||r.content?.summary||r.content?.description||r.content?.detail||"";
 const attachment=r.content?.attachment;
 const link=r.reference_url&&/^https?:\/\//i.test(r.reference_url)?'<a class="mini-button" href="'+escapeHtml(r.reference_url)+'" target="_blank" rel="noopener">Open link ↗</a>':"";
 const file=attachment?.path?'<button class="mini-button" type="button" data-open-file="'+escapeHtml(attachment.path)+'">Evidence ↗</button>':"";
 return '<article class="record"><div class="record-main"><div class="record-title">'+escapeHtml(r.title)+'</div><div class="record-meta">'+escapeHtml(meta)+'</div>'+(details?'<div class="record-meta">'+escapeHtml(details)+'</div>':"")+(note?'<div class="record-notes">'+escapeHtml(note)+'</div>':"")+'</div><div class="record-actions">'+(r.severity?'<span class="pill '+escapeHtml(r.severity)+'">'+escapeHtml(r.severity)+'</span>':"")+(r.status?'<span class="pill '+escapeHtml(r.status)+'">'+escapeHtml(r.status.replaceAll("_"," "))+'</span>':"")+link+file+'<button class="mini-button danger" type="button" data-delete="'+escapeHtml(r.id)+'">Delete</button></div></article>';
}
function renderLists(){
 $$("[data-list]").forEach(host=>{
   const kind=host.dataset.list;
   const list=records.filter(r=>r.kind===kind);
   if(kind==="finding"&&$("#findingSearch")?.value.trim()){const q=$("#findingSearch").value.trim().toLowerCase();const filtered=list.filter(r=>(r.title+" "+JSON.stringify(r.content)).toLowerCase().includes(q));host.innerHTML=filtered.length?filtered.map(renderRecord).join(""):'<p class="empty">No findings match this filter.</p>';}
   else host.innerHTML=list.length?list.map(renderRecord).join(""):'<p class="empty">No records yet.</p>';
 });
 $$("[data-count]").forEach(el=>el.textContent=records.filter(r=>r.kind===el.dataset.count).length);
}
function renderDashboard(){
 const projects=records.filter(r=>r.kind==="project");
 const findings=records.filter(isActiveFinding);
 const severe=findings.filter(r=>["critical","high"].includes(r.severity));
 const hours=records.filter(r=>r.kind==="learning").reduce((sum,r)=>sum+(Number(r.content?.hours)||0),0);
 $("#metricProjects").textContent=projects.length;
 $("#metricFindings").textContent=findings.length;
 $("#metricSevere").textContent=severe.length;
 $("#metricHours").textContent=Number(hours.toFixed(1));
 const recent=records.filter(r=>r.kind!=="checklist").slice(0,7);
 $("#recentRecords").innerHTML=recent.length?recent.map(renderRecord).join(""):'<p class="empty">Your workspace is ready. Add a project or security record to get started.</p>';
}
function renderRisk(){
 const open=records.filter(isActiveFinding),high=open.filter(r=>["critical","high"].includes(r.severity));
 const overdue=open.filter(r=>r.content?.due_date&&r.content.due_date<today());
 const scores=open.map(scoreFinding).filter(n=>Number.isFinite(n));
 $("#riskOpen").textContent=open.length;$("#riskHigh").textContent=high.length;$("#riskOverdue").textContent=overdue.length;
 $("#riskAverage").textContent=scores.length?(scores.reduce((a,b)=>a+b,0)/scores.length).toFixed(1):"—";
}
function renderAll(){
 renderDashboard();renderLists();renderRisk();
 renderChecklist("engineeringChecks",tracks.engineering);renderChecklist("cloudChecks",tracks.cloud);
}
async function uploadFile(file){
 if(!file)return null;
 if(file.size>20*1024*1024)throw new Error(file.name+" exceeds 20 MB.");
 const allowed=["application/pdf","image/png","image/jpeg","text/plain","text/csv","application/json","application/zip","application/x-zip-compressed"];
 const ext=(file.name.split(".").pop()||"").toLowerCase();
 if(!["pdf","png","jpg","jpeg","txt","csv","json","zip"].includes(ext))throw new Error("Unsupported evidence file type: "+file.name);
 if(file.type&&!allowed.includes(file.type)&&!["jpg","jpeg"].includes(ext))throw new Error("Unsupported file type: "+file.type);
 const safeName=file.name.replace(/[^a-zA-Z0-9._-]/g,"_");
 const path=currentUser.id+"/"+crypto.randomUUID()+"-"+safeName;
 const {error}=await client.storage.from(bucket).upload(path,file,{contentType:file.type||"application/octet-stream",upsert:false});
 if(error)throw error;
 return {filename:file.name,path,size:file.size,mime:file.type||"application/octet-stream"};
}
async function submitRecord(form){
 const kind=form.dataset.kind;
 if(!kinds.includes(kind))throw new Error("Unknown record type.");
 const fd=new FormData(form);
 const title=String(fd.get("title")||"").trim();
 if(!title)throw new Error("A title is required.");
 const content={};
 for(const [key,value] of fd.entries()){
   if(key==="title"||key==="severity"||key==="status"||key==="reference_url"||key==="evidence"||key==="tags")continue;
   if(value!==""&&value!=null)content[key]=value;
 }
 if(fd.get("tags"))content.tags=String(fd.get("tags")).split(",").map(x=>x.trim()).filter(Boolean);
 const files=form.elements.evidence?.files;
 if(files?.length){
   if(kind==="project"&&files.length>1){content.attachments=[];for(const file of files)content.attachments.push(await uploadFile(file));}
   else content.attachment=await uploadFile(files[0]);
 }
 const severity=fd.get("severity")?String(fd.get("severity")).toLowerCase():null;
 let status=String(fd.get("status")||"open");
 if(kind==="incident"&&status==="closed")status="completed";
 const reference=String(fd.get("reference_url")||"").trim()||null;
 const payload={user_id:currentUser.id,kind,title,status,severity,content,reference_url:reference,tags:content.tags||[]};
 const {error}=await client.from("workspace_items").insert(payload);
 if(error)throw error;
}
async function removeRecord(id){
 const record=records.find(r=>r.id===id);
 if(record?.content?.attachment?.path){const {error}=await client.storage.from(bucket).remove([record.content.attachment.path]);if(error)throw error;}
 if(record?.content?.attachments?.length){const paths=record.content.attachments.map(x=>x.path).filter(Boolean);if(paths.length){const {error}=await client.storage.from(bucket).remove(paths);if(error)throw error;}}
 const {error}=await client.from("workspace_items").delete().eq("id",id);
 if(error)throw error;
}
async function openEvidence(path){
 const {data,error}=await client.storage.from(bucket).createSignedUrl(path,60);
 if(error)throw error;
 window.open(data.signedUrl,"_blank","noopener,noreferrer");
}
async function exportBackup(){
 const payload={exported_at:new Date().toISOString(),workspace:"BLACKSITE Security HQ",records};
 const blob=new Blob([JSON.stringify(payload,null,2)],{type:"application/json"});
 const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="blacksite-workspace-backup-"+today()+".json";a.click();URL.revokeObjectURL(url);
}
async function handleAuth(event){
 event.preventDefault();if(busy||!client)return;
 busy=true;$("#authSubmit").disabled=true;showMessage("Working…");
 try{
   const email=$("#authForm").elements.email.value.trim(),password=$("#authForm").elements.password.value;
   const result=authMode==="signin"?await client.auth.signInWithPassword({email,password}):await client.auth.signUp({email,password});
   if(result.error)throw result.error;
   if(authMode==="signup"&&!result.data.session)showMessage("Account created. Check your email to confirm, then sign in.");
   else showMessage("Signed in. Loading your private workspace…");
 }catch(error){showMessage(error.message||"Authentication failed.");}
 finally{busy=false;$("#authSubmit").disabled=false;}
}
async function start(){
 if(!cfg.url||!cfg.publishableKey){authVisible(true);showMessage("Supabase configuration is missing.");setStatus("CONFIG ERROR");return;}
 if(!window.supabase?.createClient){authVisible(true);showMessage("Supabase client library did not load. Check your connection and refresh.");setStatus("LIBRARY ERROR");return;}
 client=window.supabase.createClient(cfg.url,cfg.publishableKey,{auth:{persistSession:true,autoRefreshToken:true,detectSessionInUrl:true}});
 $("#authForm").addEventListener("submit",handleAuth);
 $("#authMode").addEventListener("click",()=>{
   authMode=authMode==="signin"?"signup":"signin";
   $("#authTitle").textContent=authMode==="signin"?"Sign in to your workspace":"Create your workspace account";
   $("#authSubmit").textContent=authMode==="signin"?"Sign in":"Create account";
   $("#authMode").textContent=authMode==="signin"?"Create an account":"Back to sign in";
   $("#authForm").elements.password.autocomplete=authMode==="signin"?"current-password":"new-password";
   showMessage("");
 });
 $("#signOut").addEventListener("click",async()=>{const {error}=await client.auth.signOut();if(error){setStatus("SIGN OUT ERROR");return;}records=[];authVisible(true);setStatus("SIGNED OUT");});
 client.auth.onAuthStateChange((_event,session)=>{
   if(session?.user){currentUser=session.user;authVisible(false);loadWorkspace().catch(error=>{setStatus("SYNC ERROR");console.error(error);});}
   else{currentUser=null;authVisible(true);setStatus("SIGNED OUT");}
 });
 const {data,error}=await client.auth.getSession();
 if(error)throw error;
 if(data.session?.user){currentUser=data.session.user;authVisible(false);await loadWorkspace();}
 else{authVisible(true);setStatus("SIGN IN REQUIRED");}
}
document.addEventListener("click",async event=>{
 const nav=event.target.closest("[data-view]");if(nav){event.preventDefault();navigate(nav.dataset.view);return;}
 const jump=event.target.closest("[data-jump]");if(jump){navigate(jump.dataset.jump);return;}
 const del=event.target.closest("[data-delete]");if(del&&currentUser){if(!confirm("Delete this record and its attached evidence?"))return;del.disabled=true;try{setStatus("SAVING");await removeRecord(del.dataset.delete);await loadWorkspace();}catch(error){alert("Delete failed: "+error.message);del.disabled=false;setStatus("SYNC ERROR");}return;}
 const file=event.target.closest("[data-open-file]");if(file&&currentUser){try{await openEvidence(file.dataset.openFile);}catch(error){alert("Could not open evidence: "+error.message);}}
});
document.addEventListener("submit",async event=>{
 const form=event.target.closest("form[data-kind]");if(!form)return;
 event.preventDefault();if(!currentUser){messageForm(form,"Sign in first.");return;}
 const button=$('button[type="submit"]',form);if(button)button.disabled=true;messageForm(form,"Saving to your private workspace…");setStatus("SAVING");
 try{await submitRecord(form);form.reset();await loadWorkspace();messageForm(form,"Saved and synced.");}
 catch(error){console.error(error);messageForm(form,error.message||"Save failed.");setStatus("SYNC ERROR");}
 finally{if(button)button.disabled=false;}
});
document.addEventListener("change",async event=>{
 const input=event.target.closest("[data-check]");if(!input||!currentUser)return;
 checks[input.dataset.check]=input.checked;input.closest(".check-item").classList.toggle("done",input.checked);
 try{setStatus("SAVING");await saveChecklist();setStatus("CLOUD SYNCED",true);}
 catch(error){setStatus("SYNC ERROR");alert("Checklist save failed: "+error.message);}
});
$("#exportData").addEventListener("click",exportBackup);
$("#findingSearch").addEventListener("input",renderLists);
$("#todayLabel").textContent=new Date().toLocaleDateString(undefined,{year:"numeric",month:"short",day:"numeric"});
start().catch(error=>{console.error(error);authVisible(true);showMessage(error.message||"Could not start BLACKSITE.");setStatus("STARTUP ERROR");});
})();