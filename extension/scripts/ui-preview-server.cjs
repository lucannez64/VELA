// Local visual/interaction fixture for the production UI. Never shipped in dist.
// Run node scripts/ui-preview-server.cjs after node build.js; open /popup/popup.html
// or /content-test.html. Every browser/native response is synthetic and recorded.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../dist/chrome');
const fixture = `(() => {
 const listeners=[],changes=[]; const store={}; const calls=[]; const errors=[];
 addEventListener('error',e=>errors.push(e.message));addEventListener('unhandledrejection',e=>errors.push(String(e.reason)));
 const noop={addListener(){},removeListener(){}};
 const state=new URL(location.href).searchParams.get('state')||'ready';
 const logins=[{id:'personal',name:'Personal',username:'alex@example.test',url:'https://fieldwork.example',password:'EXAMPLE-ONLY-password',totp:'284619'},{id:'work',name:'Studio',username:'alex@studio.example',url:'https://fieldwork.example',password:'OTHER-EXAMPLE-password',totp:null}];
 async function rawResponse(m){calls.push(m);switch(m.command){
 case 'checkDesktopConnection':return {connected:state!=='offline'};
 case 'getLogins':case 'getAvailableLogins':return state==='locked'?{requires_biometric:true,logins:[]}:state==='empty'||state==='offline'?{success:true,logins:[]}:{success:true,logins:logins.map(x=>m.userInitiated?x:{id:x.id,name:x.name,username:x.username,url:x.url})};
 case 'getIdentities':return {success:true,identities:[{id:'ada',name:'Ada — Personal',firstName:'Ada',middleName:'Byron',lastName:'Lovelace',email:'ada@example.test',phone:'+44123456789',company:'Analytical Engines',addresses:[{id:'home',label:'Home',line1:'12 Computing Lane',line2:'Suite 2',city:'London',region:'London',postalCode:'N1 1AA',countryCode:'GB'},{id:'office',label:'Office',line1:'42 Engine Street',city:'Oxford',postalCode:'OX1 1AA',countryCode:'GB'}]}]};
 case 'getCards':return {success:true,cards:[{id:'visa',name:'Everyday Visa',cardholderName:'Alex Demo',number:'4242424242424242',exp:'08/29',cvv:'123'},{id:'master',name:'Studio Mastercard',number:'5555555555555556',cardholderName:'Alex Demo',exp:'11/28',cvv:'456'}]};
 case 'getTotpCode':return m.loginId==='personal'?{success:true,code:'284619',remainingSecs:18}:{success:false};
 case 'inCoreLoginCandidates':return {success:true,candidates:[]};
 case 'getAliasProvider':return {configured:false};
 case 'getTotpPending':return {};
 case 'getPendingCapture':return {};
 default:return {success:true};}}
 async function respond(m) {
  const response = await rawResponse(m);
  if(m.userInitiated===false && m.command==='getCards')response.cards=response.cards.map(c=>({id:c.id,name:c.name,cardholderName:c.cardholderName,exp:c.exp,last4:c.number.slice(-4)}));
  if(m.userInitiated===false && m.command==='getIdentities')response.identities=response.identities.map(i=>({id:i.id,name:i.name,addresses:i.addresses.map(a=>({id:a.id,label:a.label}))}));
  return response;
 }
 window.browser={runtime:{sendMessage:respond,onMessage:{addListener(fn){listeners.push(fn)}},connect(){return {onDisconnect:noop}},getURL:p=>'/'+p},tabs:{query:async()=>[{id:1,url:'https://fieldwork.example/login'}],sendMessage:async(id,m)=>respond(m)},storage:{local:{async get(key){if(typeof key==='string')return {[key]:store[key]};return {...store}},async set(data){const patch={};for(const key in data)patch[key]={oldValue:store[key],newValue:data[key]};Object.assign(store,data);changes.forEach(fn=>fn(patch,'local'))},async remove(key){delete store[key]}},session:{get:async()=>({}),set:async()=>{}},onChanged:{addListener(fn){changes.push(fn)}}},permissions:{request:async()=>false}};
 window.close=()=>calls.push({command:'window.close'});
 Object.defineProperty(navigator,'clipboard',{value:{writeText:async text=>calls.push({command:'clipboard',text})},configurable:true});
 window.UI_FIXTURE={calls,errors,store,dispatch(message){return Promise.all(listeners.map(fn=>new Promise(resolve=>{const result=fn(message,{},resolve);if(result!==true)resolve(result)})))}};
})();`;
const page = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VELA UI fixture — synthetic data</title><link rel="stylesheet" href="/content/content-styles.css"><style>body{background:#eeeee9;color:#252a20;font:14px system-ui;margin:0;padding:60px 24px;min-height:950px}main{max-width:340px;margin:auto}h1{font-size:32px;letter-spacing:-.04em}p{font-size:12px;color:#777}form{margin:30px 0}label{display:block;font-size:11px;margin:14px 0 7px}input{display:block;padding:13px;border-radius:10px;background:#fbfcf7;border:1px solid #c9cfbf;width:100%;box-sizing:border-box}button[type=submit]{padding:12px;border:0;border-radius:12px;margin-top:18px;background:#313929;color:white}header{font-size:10px;color:#888;margin-bottom:40px}</style><script src="/fixture.js"></script><script src="/shared/autofill-utils.js"></script><script src="/shared/instrument-ui.js"></script></head><body><main><header>ISOLATED UI FIXTURE · FAKE DATA · NO DESKTOP CONNECTION</header><h1>Welcome back.</h1><p>Production extension components on a sample form.</p><form id="login"><label for="username">Email</label><input id="username" autocomplete="username" value=""><label for="password">Password</label><input id="password" type="password" autocomplete="current-password"><button type="submit">Sign in</button></form><form id="verify"><label for="code">Verification code</label><input id="code" autocomplete="one-time-code" inputmode="numeric"></form><form id="payment"><label for="card">Card number</label><input id="card" autocomplete="cc-number"><label for="holder">Cardholder</label><input id="holder" autocomplete="cc-name"><label for="exp">Expiry</label><input id="exp" autocomplete="cc-exp"><label for="cvv">Security code</label><input id="cvv" autocomplete="cc-csc"></form><form id="identity"><label>First name</label><input id="first" autocomplete="given-name"><label>Last name</label><input id="last" autocomplete="family-name"><label>Email</label><input id="contact-email" type="email" autocomplete="email"><label>Address</label><textarea id="street" autocomplete="street-address"></textarea><label>City</label><input id="city" autocomplete="address-level2"><label>Country</label><select id="country" autocomplete="country"><option value="">Choose</option><option value="GB">United Kingdom</option><option value="US">United States</option></select><input id="hidden-name" type="hidden" autocomplete="given-name"></form><form id="split-card"><input id="split-number" autocomplete="cc-number"><select id="month" autocomplete="cc-exp-month"><option value="">Month</option><option value="8">August</option></select><select id="year" autocomplete="cc-exp-year"><option value="">Year</option><option value="2029">2029</option></select><input id="secret-cvv" type="password" autocomplete="cc-csc"></form><form id="register"><label for="new-password">New password</label><input id="new-password" type="password" autocomplete="new-password"></form></main><script>document.querySelectorAll('form').forEach(f=>f.addEventListener('submit',e=>e.preventDefault()));</script><script src="/content/content-script.js"></script></body></html>`;
const types={'.js':'text/javascript','.css':'text/css','.html':'text/html','.woff2':'font/woff2','.svg':'image/svg+xml','.png':'image/png'};
const server=http.createServer((req,res)=>{const url=new URL(req.url,'http://localhost');res.setHeader('Cache-Control','no-store');
 if(url.pathname==='/fixture.js'){res.setHeader('Content-Type','text/javascript');res.end(fixture);return}
 if(url.pathname==='/content-test.html'){res.setHeader('Content-Type','text/html');res.end(page);return}
 const file=path.resolve(root,'.'+decodeURIComponent(url.pathname));if(!file.startsWith(root+path.sep)){res.writeHead(403);res.end();return}
 try{let body=fs.readFileSync(file);if(url.pathname==='/popup/popup.html')body=body.toString().replace('<script src="../shared/browser-polyfill.js"></script>','<script src="/fixture.js"></script>');res.setHeader('Content-Type',(types[path.extname(file)]||'application/octet-stream')+'; charset=utf-8');res.end(body)}catch(_){res.writeHead(404);res.end('Not found')}
});
server.listen(Number(process.env.VELA_UI_PORT)||8877,'127.0.0.1',()=>console.log('VELA synthetic UI fixture: http://localhost:'+(Number(process.env.VELA_UI_PORT)||8877)));
