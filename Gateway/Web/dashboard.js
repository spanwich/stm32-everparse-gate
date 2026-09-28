'use strict';
const $=id=>document.getElementById(id);
const paths=[{id:0x55555555,name:'/demo',input:$('allowDemo')},{id:0x33333333,name:'/api/status',input:$('allowStatus')}];
let token='',busy=false;
function show(status,text){
 const box=$('result');box.hidden=false;box.className=status>=200&&status<400?'ok':'err';
 box.textContent=(status?'HTTP '+status+'\n':'')+text;
}
function clearIdentity(){
 token='';$('policy').hidden=true;$('operatorNote').hidden=true;
 $('identity').textContent='Log in to access protected paths.';
}
async function api(method,path,body){
 const headers={};if(token)headers.Authorization='Bearer '+token;
 const opt={method,headers,cache:'no-store'};
 if(body instanceof Uint8Array){headers['Content-Type']='application/octet-stream';opt.body=body;}
 else if(method==='POST'){headers['Content-Type']='application/json';opt.body=JSON.stringify(body||{});}
 const response=await fetch(path,opt),text=await response.text();
 return {status:response.status,text};
}
function readRules(r){
 if(r.status!==200)throw Error('Cannot read policy: HTTP '+r.status);
 const rules=JSON.parse(r.text).rules;
 if(!Array.isArray(rules)||rules.length<1||rules.length>8)throw Error('Invalid policy response');
 for(const rule of rules){
  for(const key of ['id','method','min_role','scope'])if(!Number.isInteger(rule[key]))throw Error('Invalid policy rule');
  if(rule.id<0||rule.id>0xffffffff||rule.method<0||rule.method>63||rule.min_role<0||rule.min_role>2||rule.scope<0||rule.scope>65535)throw Error('Invalid policy bounds');
 }
 return rules;
}
function displayPolicy(rules){
 for(const path of paths)path.input.checked=rules.some(r=>r.id===path.id&&(r.method&1)===1&&r.min_role<=1&&(r.scope&3)===r.scope);
 $('policy').hidden=false;
 $('policyState').textContent=paths.map(p=>p.name+': operator '+(p.input.checked?'allowed':'denied')).join(' · ');
}
async function loadPolicy(){
 const r=await api('GET','/api/policy');
 if(r.status===403){$('policy').hidden=true;$('operatorNote').hidden=false;return;}
 displayPolicy(readRules(r));$('operatorNote').hidden=true;
}
function encodePolicy(rules){
 if(rules.length<1||rules.length>8)throw Error('Policy has no free rule slots');
 const bytes=new Uint8Array(65),view=new DataView(bytes.buffer);bytes[0]=rules.length;
 rules.forEach((r,i)=>{const n=1+i*8;view.setUint32(n,r.id,true);bytes[n+4]=r.method;bytes[n+5]=r.min_role;view.setUint16(n+6,r.scope,true);});
 for(let i=rules.length;i<8;i++)view.setUint32(1+i*8,0xDEADDEAD,true);
 return bytes;
}
async function run(work){
 if(busy)return;busy=true;
 document.querySelectorAll('button,input[type=checkbox]').forEach(e=>e.disabled=true);
 try{await work();}catch(e){show(0,e.message);}
 finally{busy=false;document.querySelectorAll('button,input[type=checkbox]').forEach(e=>e.disabled=false);}
}
$('loginForm').onsubmit=e=>{e.preventDefault();run(async()=>{
 clearIdentity();const body={username:$('user').value,password:$('pass').value};$('pass').value='';
 const r=await api('POST','/api/login',body);
 if(r.status!==200){show(r.status,r.text);return;}
 const data=JSON.parse(r.text);if(typeof data.token!=='string'||!data.token)throw Error('Missing token');
 token=data.token;$('identity').textContent='Logged in as '+body.username+'.';
 await loadPolicy();show(200,'Logged in. Open /demo to test live access.');
});};
for(const [id,path] of [['btnStatus','/api/status'],['btnDemo','/demo']])$(id).onclick=()=>run(async()=>{
 if(!token)throw Error('Log in first');const r=await api('GET',path);show(r.status,r.text);
});
$('btnLogout').onclick=()=>run(async()=>{
 try{if(!token)throw Error('Log in first');const r=await api('POST','/api/logout');show(r.status,r.text+'\nToken cleared from this page.');}
 finally{clearIdentity();}
});
$('btnRefresh').onclick=()=>run(loadPolicy);
for(const path of paths)path.input.onchange=()=>{
 const allow=path.input.checked;
 run(async()=>{
  try{
   // Read current rules immediately before changing only this GET path.
   const current=readRules(await api('GET','/api/policy'));
   const rules=[];
   for(const rule of current){
    const grantsOperator=rule.id===path.id&&(rule.method&1)===1&&rule.min_role<=1&&(rule.scope&3)===rule.scope;
    if(!allow&&grantsOperator){
     const narrowed={...rule,method:rule.method&~1};
     if(narrowed.method)rules.push(narrowed);
    }else rules.push(rule);
   }
   const grants=(role,scope)=>rules.some(r=>r.id===path.id&&(r.method&1)===1&&r.min_role<=role&&(r.scope&scope)===r.scope);
   if(allow&&!grants(1,3))rules.push({id:path.id,method:1,min_role:1,scope:1});
   if(!allow&&!grants(2,0x3f))rules.push({id:path.id,method:1,min_role:2,scope:1});
   const r=await api('PUT','/api/policy',encodePolicy(rules));
   if(r.status!==200)throw Error('Policy update rejected: HTTP '+r.status);
   await loadPolicy();show(200,path.name+': operator access '+(allow?'allowed':'denied')+'.');
  }catch(e){$('policy').hidden=true;throw e;}
 });
};
