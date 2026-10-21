// Exercises the real background handlers with a synthetic browser/native bridge.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const on = {addListener(){}};
let active = {id:1,url:'https://shop.example/checkout'};
const calls = [], fills = [];
let changePage = false;
const browser = {
  runtime:{id:"test",getManifest:()=>({action:{default_popup:"popup/popup.html"}}),onConnect:on,onMessage:on,onInstalled:on,onStartup:on,getURL:p=>'chrome-extension://test/'+p,
    async sendNativeMessage(host,m){calls.push(m);if(changePage)active={...active,url:'https://other.example/'};return {success:true,[m.action==='getCards'?'cards':'identities']:[{id:'one',name:'Native item'}]};}},
  tabs:{onRemoved:on,onUpdated:on,query:async()=>[active],sendMessage:async(id,m,options)=>{fills.push({id,m,options});return {success:true};}},
  contextMenus:{onClicked:on,create(){},removeAll(){}},commands:{onCommand:on},action:{},
  storage:{session:{get:async()=>({}),set:async()=>{},remove:async()=>{}},local:{get:async()=>({}),set:async()=>{}}}
};
const context = vm.createContext({browser,URL,console:{log(){}},setTimeout,clearTimeout});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../src/background/background.js'),'utf8')+'\nglobalThis.handlers={handleGetIdentities,handleGetCards,handleFillVaultItem,handleExtensionMessage};',context);
const ui = {url:'chrome-extension://test/popup/popup.html'};
const page = {tab:{id:1},frameId:0,url:active.url};
const invoke=(name,data,sender=ui)=>new Promise(resolve=>context.handlers[name](data,sender,resolve));
(async()=>{
  for (const name of ['handleGetCards','handleGetIdentities']) {
    const before=calls.length;
    for (const [url,sender] of [
      ['file:///tmp/test',ui],['https://evil.example',ui],
      [active.url,{...page,tab:{id:2}}],[active.url,{...page,frameId:1}],
      [active.url,{url:'https://shop.example'}]
    ]) assert.equal((await invoke(name,{url},sender)).success,false);
    assert.equal(calls.length,before,'unauthorized requests never reach native host');
    assert.equal((await invoke(name,{url:active.url},page)).success,true);
    assert.equal(calls.at(-1).userInitiated,true);
    assert.equal((await invoke(name,{url:active.url,userInitiated:false},page)).success,true);
    assert.equal(calls.at(-1).userInitiated,false,'passive metadata flag survives the background bridge');
  }
  for(const itemType of ['card','identity']) {
    const result=await invoke('handleFillVaultItem',{url:active.url,itemType,itemId:'one',addressId:'home'});
    assert.equal(result.success,true);
    const sent=fills.at(-1);
    assert.equal(sent.m.item.name,'Native item');
    assert.equal(sent.m.addressId,'home');assert.equal(sent.options.frameId,0);
    assert.equal((await invoke('handleFillVaultItem',{url:active.url,itemType,itemId:'missing'})).success,false);
  }
  const before=fills.length;
  changePage=true;
  assert.equal((await invoke('handleFillVaultItem',{url:active.url,itemType:'identity',itemId:'one'})).success,false);
  assert.equal(fills.length,before,'navigation during native lookup prevents fill');
  const nativeBefore = calls.length;
  for (const sender of [page, ui, {id:'other',url:'chrome-extension://test/popup/manager.html'}, {id:'test',url:'chrome-extension://test/popup/manager.html?spoof=1'}]) {
    const denied = await invoke('handleExtensionMessage', {command:'vaultManage',request:{operation:'list'}}, sender);
    assert.equal(denied.success,false);
  }
  assert.equal(calls.length,nativeBefore,'content scripts and other extension pages cannot manage the vault');
  await invoke('handleExtensionMessage', {command:'vaultManage',request:{operation:'list'}}, {id:'test',url:'chrome-extension://test/popup/manager.html',tab:{id:22}});
  assert.equal(calls.at(-1).action,'vaultManage','dedicated extension tab can call the native editor');
  console.log('Vault autofill authorization, native ID resolution and navigation checks passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
