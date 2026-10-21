// Development-only fixture: real desktop components, synthetic in-memory IPC.
// Never imports App or opens a real vault. Not included in the production build.
import {useState} from 'react';
import {createRoot} from 'react-dom/client';
import {AppProvider,useApp,fromBackendItem} from '../../src/context/AppContext';
import VaultBrowser from '../../src/views/VaultBrowser';
import ItemDetail from '../../src/views/ItemDetail';
import AddItemModal from '../../src/components/AddItemModal';
import '../../src/index.css';

const folder=crypto.randomUUID(),tag=crypto.randomUUID();
const status={enabled:true,organization:{folders:[{id:folder,name:'Personal',parentId:null}],tags:[{id:tag,name:'Important'}],organizationTombstones:[] as {id:string;kind:string}[]}};
let items:Record<string,any>[]=[
  {id:crypto.randomUUID(),name:'Example login',item_type:'login',url:'https://example.com',username:'demo@example.com',password:'synthetic-password',folderId:folder,tagIds:[tag],customFields:[{id:crypto.randomUUID(),label:'Recovery code',type:'concealed',value:'synthetic-recovery-code'}],additionalUrls:[],createdAt:'2026-10-20T10:00:00Z',updatedAt:'2026-10-20T10:00:00Z'},
  {id:crypto.randomUUID(),name:'Personal identity',item_type:'identity',firstName:'Demo',lastName:'Person',ssn:'synthetic-id',identityDetails:{email:'demo@example.com',addresses:[]},createdAt:'2026-10-20T10:00:00Z',updatedAt:'2026-10-20T10:00:00Z'},
];
(window as any).__fixture={status,get items(){return items;}};
(window as any).__TAURI_INTERNALS__={invoke:async(command:string,args:any={})=>{
  if(command==='get_organization')return structuredClone(status);
  if(command==='activate_rich_items'){status.enabled=true;return structuredClone(status);}
  if(command==='get_vault_health')return {weak_passwords:0,reused_passwords:0,total_logins:1,health_score:100,status:'GOOD'};
  if(command==='get_items')return structuredClone(items);
  if(command==='fetch_favicon')return null;
  if(command==='add_item'||command==='update_item'){const item={...args.item,id:args.item.id||crypto.randomUUID()};items=items.filter(i=>i.id!==item.id).concat(item);return item;}
  if(command==='mutate_organization'){
    const a=args.action;const records=a.operation.includes('Tag')?status.organization.tags:status.organization.folders;
    if(a.operation.startsWith('create'))records.push({id:crypto.randomUUID(),name:a.name,parentId:a.parentId} as any);
    if(a.operation.startsWith('rename')){const record=records.find(r=>r.id===a.id);if(record)record.name=a.name;}
    if(a.operation==='updateFolder'){const record=status.organization.folders.find(r=>r.id===a.id);if(record){record.name=a.name;record.parentId=a.parentId;}}
    if(a.operation==='moveFolder'){const record=status.organization.folders.find(r=>r.id===a.id);if(record)record.parentId=a.parentId;}
    if(a.operation==='deleteFolder'){status.organization.folders=status.organization.folders.filter(f=>f.id!==a.id);items.forEach(i=>{if(i.folderId===a.id)i.folderId='';});}
    if(a.operation==='deleteTag'){status.organization.tags=status.organization.tags.filter(t=>t.id!==a.id);items.forEach(i=>i.tagIds=(i.tagIds??[]).filter((id:string)=>id!==a.id));}
    return structuredClone(status);
  }
  if(command==='assign_items'){const c=args.changes;items.forEach(item=>{if(c.ids.includes(item.id)){if(c.folderId!==null)item.folderId=c.folderId;item.tagIds=[...new Set([...(item.tagIds??[]).filter((id:string)=>!c.removeTags.includes(id)),...c.addTags])];}});return;}
  if(command==='delete_item'){items=items.filter(i=>i.id!==args.id);return;}
  if(command==='copy_secret'||command==='clear_clipboard')return true;
  throw new Error(`Unimplemented fixture command: ${command}`);
}};
function Harness(){
  const {selectedItem,setSelectedItem}=useApp();
  const [,refresh]=useState(0);const [editing,setEditing]=useState<Record<string,any>|null|undefined>();
  const reload=()=>{refresh(n=>n+1);if(selectedItem){const item=items.find(i=>i.id===selectedItem.id);setSelectedItem(item?fromBackendItem(item):null);}};
  return <main className="h-screen flex flex-col bg-surface text-on-surface"><p className="p-2 text-sm">Synthetic UI fixture · no real vault or server</p>
    {selectedItem?<ItemDetail item={selectedItem} onEdit={()=>setEditing(selectedItem)} paused={editing!==undefined}/>:<VaultBrowser items={items.map(fromBackendItem)} onRefresh={reload} onAddItem={()=>setEditing(null)}/>}
    {editing!==undefined&&<AddItemModal editItem={editing?fromBackendItem({...editing,...items.find(i=>i.id===editing.id)}):null} onSave={reload} onClose={()=>setEditing(undefined)}/>}
  </main>;
}
createRoot(document.getElementById('root')!).render(<AppProvider><Harness/></AppProvider>);
