// Local-only fixture for the production extension editor. Synthetic data only.
const http = require('node:http'), fs = require('node:fs'), path = require('node:path');
const root = path.resolve(__dirname, '../src');
const fixture = `
const sample={item_type:'login',id:'sample',name:'Example account',url:'https://example.test',username:'alex@example.test',password:'synthetic-secret',createdAt:'2026-01-01T00:00:00Z',updatedAt:'2026-01-01T00:00:00Z',folderId:'work',tagIds:['twofa'],customFields:[{id:'field',label:'Backup PIN',type:'concealed',value:'1234'}]};
let items=[sample]; let organization={folders:[{id:'work',name:'Work'}],tags:[{id:'twofa',name:'2FA'}]};
window.fixtureRequests=[];
window.browser={runtime:{getURL:p=>'/'+p,getManifest:()=>({}),sendMessage:async m=>{
 if(m.command!=='vaultManage')return {success:true}; const r=m.request; fixtureRequests.push(structuredClone(r));
 if(r.operation==='list')return {success:true,data:structuredClone({items:items.map(i=>({id:i.id,name:i.name,kind:i.item_type,folderId:i.folderId,tagIds:i.tagIds})),collections:{enabled:true,organization}})};
 if(r.operation==='read')return {success:true,data:{item:structuredClone(items.find(i=>i.id===r.id)),readOnly:false}};
 if(r.operation==='create')items.push(structuredClone(r.item));
 if(r.operation==='update')items=items.map(i=>i.id===r.item.id?structuredClone(r.item):i);
 if(r.operation==='delete')items=items.filter(i=>i.id!==r.id);
 if(r.operation==='mutate'){let a=r.action,k=a.operation.toLowerCase().includes('folder')?'folders':'tags';if(a.operation.startsWith('create'))organization[k].push({id:crypto.randomUUID(),name:a.name,parentId:a.parentId});else if(a.operation.startsWith('delete'))organization[k]=organization[k].filter(i=>i.id!==a.id);else Object.assign(organization[k].find(i=>i.id===a.id),a);}
 if(r.operation==='assign')items.forEach(i=>{if(!r.changes.ids.includes(i.id))return;if(r.changes.folderId!==null)i.folderId=r.changes.folderId;i.tagIds=[...new Set([...(i.tagIds||[]),...r.changes.addTags])].filter(id=>!r.changes.removeTags.includes(id));});
 return {success:true,data:{ok:true}};
}},storage:{local:{get:async()=>({}),set:async()=>{}},onChanged:{addListener(){}}}};`;
http.createServer((req,res)=>{
 const name=new URL(req.url,'http://localhost').pathname;
 if(name==='/fixture.js'){res.setHeader('Content-Type','text/javascript');return res.end(fixture);}
 const filename=path.resolve(root,'.'+name);if(!filename.startsWith(root+path.sep)){res.writeHead(403);return res.end();}
 try{let body=fs.readFileSync(filename);if(name.endsWith('manager.html'))body=body.toString().replace('<script src="../shared/browser-polyfill.js"></script>','<script src="/fixture.js"></script>');res.setHeader('Content-Type',({'.html':'text/html','.css':'text/css','.js':'text/javascript','.woff2':'font/woff2'})[path.extname(filename)]||'application/octet-stream');res.end(body);}catch{res.writeHead(404);res.end();}
}).listen(8884,'127.0.0.1',()=>console.log('Synthetic editor fixture: http://127.0.0.1:8884/popup/manager.html'));
