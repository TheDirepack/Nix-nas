(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  let selected = null;
  let exists = false;

  function notice(message, kind = "") { const n=$("notice"); n.textContent=message || ""; n.className=kind; }
  function parseJson(id, fallback) { const text=$(id).value.trim(); if(!text) return fallback; try{return JSON.parse(text);}catch(e){throw new Error(`${id}: ${e.message}`);} }
  function csv(id){ return $(id).value.split(",").map(v=>v.trim()).filter(Boolean); }
  function spawn(args, input=null){
    const proc = cockpit.spawn(["nas-managed-service", ...args], {superuser:"require", err:"message"});
    if(input !== null) proc.input(input);
    return proc.then(text => text.trim() ? JSON.parse(text) : {});
  }
  function updateRuntimeFields(){ const type=$("runtime").value; document.querySelectorAll(".runtime").forEach(el=>el.classList.toggle("hidden", !el.classList.contains(type))); }
  function sourcePath(id, type){ return `/var/lib/nas-control/apps/${id}/${type === "vm" ? "domain.xml" : "compose.yaml"}`; }
  async function stageIfNeeded(){
    const type=$("runtime").value, text=$("source-text").value;
    if(!text || !["compose","vm"].includes(type)) return;
    const id=$("service-id").value.trim();
    const result=await spawn(["stage-source",id,type],text);
    $("source").value=result.path;
  }
  function definition(){
    const type=$("runtime").value, id=$("service-id").value.trim();
    const runtime={type,startPolicy:$("start-policy").value};
    if(type==="container") runtime.image=$("image").value.trim();
    if(["compose","vm"].includes(type)) runtime.source=$("source").value.trim() || sourcePath(id,type);
    if(type==="vm" && $("vm-name").value.trim()) runtime.name=$("vm-name").value.trim();
    if(type==="native") runtime.systemdUnit=$("systemd-unit").value.trim();
    const env=parseJson("environment",{}); if(Object.keys(env).length) runtime.environment=env;
    const service={label:$("label").value.trim(),enabled:$("start-policy").value!=="disabled",runtime,storage:parseJson("storage",[])};
    const resources={};
    if($("memory").value) resources.memoryBytes=Number($("memory").value)*1024*1024;
    if($("cpus").value) resources.cpus=Number($("cpus").value);
    const gpus=csv("gpus"); if(gpus.length) resources.gpus=gpus;
    if(Object.keys(resources).length) service.resources=resources;
    service.network={outboundDefault:$("outbound").value,lanAccess:$("lan-access").checked,hostAccess:$("host-access").checked,allowedEgress:parseJson("allowed-egress",[]),allowedServices:parseJson("allowed-services",[])};
    const endpoints=parseJson("extra-endpoints",{});
    const endpointId=$("endpoint-id").value.trim();
    if(endpointId){
      const endpoint={transport:$("transport").value,targetPort:Number($("target-port").value),exposure:{type:$("exposure").value},auth:{mode:$("auth-mode").value,allow:$("auth-allow").value,groups:csv("auth-groups"),users:csv("auth-users")},portal:{visible:$("portal-visible").checked,category:$("portal-category").value,icon:"box"}};
      const value=$("exposure-value").value.trim(); if(endpoint.exposure.type!=="none") endpoint.exposure.value=endpoint.exposure.type==="port"?Number(value):value;
      if($("target-service").value.trim()) endpoint.targetService=$("target-service").value.trim();
      if($("target-host").value.trim()) endpoint.targetHost=$("target-host").value.trim();
      endpoints[endpointId]=endpoint;
    }
    service.endpoints=endpoints;
    return service;
  }
  async function refresh(){
    try{const data=await spawn(["list"]); const root=$("services"); root.textContent=""; for(const s of data.services||[]){const d=document.createElement("div");d.className="service";d.dataset.id=s.id;const strong=document.createElement("strong");strong.textContent=s.label||s.id;const small=document.createElement("small");small.textContent=`${s.runtime} · ${s.startPolicy} · generation ${s.generation}`;d.append(strong,small);d.onclick=()=>load(s.id);root.appendChild(d);} notice("");}catch(e){notice(e.message,"error");}
  }
  function reset(){selected=null;exists=false;$("delete").dataset.confirm="";$("delete").textContent="Delete";$("editor").reset();$("service-id").disabled=false;$("endpoint-id").value="web";$("target-port").value="8080";$("exposure-value").value="/apps/example/";$("allowed-egress").value="[]";$("allowed-services").value="[]";$("storage").value="[]";$("extra-endpoints").value="{}";$("environment").value="{}";$("editor-title").textContent="New service";$("plan-output").textContent="";updateRuntimeFields();}
  async function load(id){
    try{const s=await spawn(["show",id]);selected=id;exists=true;$("service-id").value=id;$("service-id").disabled=true;$("label").value=s.label||id;const r=s.runtime||{};$("runtime").value=r.type||"container";$("start-policy").value=r.startPolicy||"manual";$("image").value=r.image||"";$("source").value=r.source||"";$("vm-name").value=r.name||"";$("systemd-unit").value=r.systemdUnit||"";$("environment").value=JSON.stringify(r.environment||{},null,2);const res=s.resources||{};$("memory").value=res.memoryBytes?Math.round(res.memoryBytes/1048576):"";$("cpus").value=res.cpus||"";$("gpus").value=(res.gpus||[]).join(",");const n=s.network||{};$("outbound").value=n.outboundDefault||"allow";$("lan-access").checked=!!n.lanAccess;$("host-access").checked=!!n.hostAccess;$("allowed-egress").value=JSON.stringify(n.allowedEgress||[],null,2);$("allowed-services").value=JSON.stringify(n.allowedServices||[],null,2);$("storage").value=JSON.stringify(s.storage||[],null,2);const eps={...(s.endpoints||{})};const first=Object.keys(eps)[0];if(first){const e=eps[first];delete eps[first];$("endpoint-id").value=first;$("transport").value=e.transport||"http";$("target-port").value=e.targetPort||8080;$("target-service").value=e.targetService||"";$("target-host").value=e.targetHost||"";$("exposure").value=e.exposure?.type||"none";$("exposure-value").value=e.exposure?.value??"";$("auth-mode").value=e.auth?.mode||"forward-auth";$("auth-allow").value=e.auth?.allow||"any";$("auth-groups").value=(e.auth?.groups||[]).join(",");$("auth-users").value=(e.auth?.users||[]).join(",");$("portal-visible").checked=!!e.portal?.visible;$("portal-category").value=e.portal?.category||"Other";}$("extra-endpoints").value=JSON.stringify(eps,null,2);$("editor-title").textContent=`Edit ${id}`;updateRuntimeFields();const st=await spawn(["status",id]);$("runtime-state").textContent=st.state||"";}catch(e){notice(e.message,"error");}
  }
  async function plan(){try{await stageIfNeeded();const id=$("service-id").value.trim();const result=await spawn(["plan",id,"-"],JSON.stringify(definition()));$("plan-output").textContent=JSON.stringify(result,null,2);notice("Plan generated. Review it before Apply.","success");}catch(e){notice(e.message,"error");}}
  async function apply(ev){ev.preventDefault();try{await stageIfNeeded();const id=$("service-id").value.trim();const result=await spawn([exists?"update":"create",id,"-"],JSON.stringify(definition()));$("plan-output").textContent=JSON.stringify(result,null,2);notice("Application configuration applied.","success");exists=true;selected=id;$("service-id").disabled=true;await refresh();await load(id);}catch(e){notice(e.message,"error");}}
  async function remove(){
    if(!selected)return;
    const button=$("delete");
    if(button.dataset.confirm!==selected){button.dataset.confirm=selected;button.textContent=`Confirm delete ${selected}`;notice("Click the delete button again to confirm. Persistent host data will not be deleted.","error");return;}
    try{await spawn(["delete",selected]);button.dataset.confirm="";button.textContent="Delete";notice("Managed service deleted.","success");reset();await refresh();}catch(e){notice(e.message,"error");}
  }
  async function lifecycle(action){if(!selected)return;try{const r=await spawn([action,selected]);$("plan-output").textContent=JSON.stringify(r,null,2);notice(`${action} completed.`,"success");await load(selected);}catch(e){notice(e.message,"error");}}
  $("runtime").onchange=updateRuntimeFields;$("refresh").onclick=refresh;$("new-service").onclick=reset;$("plan").onclick=plan;$("editor").onsubmit=apply;$("delete").onclick=remove;document.querySelectorAll(".lifecycle button").forEach(b=>b.onclick=()=>lifecycle(b.dataset.action));
  reset();refresh();
})();
