import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import type { VaultItem, CustomField, AdditionalUrl, IdentityDetails, PostalAddress } from '../context/AppContext';
import { folderPaths, OrganizationStatus } from '../lib/organization';

const input = 'w-full rounded-lg p-2 bg-surface-container-highest text-on-surface min-w-0';
const button = 'rounded-lg px-3 py-2 bg-surface-container-highest text-on-surface disabled:opacity-40';
export default function RichFieldsEditor({value, onChange}: {value: Partial<VaultItem>; onChange: (patch: Partial<VaultItem>) => void}) {
  const [status, setStatus] = useState<OrganizationStatus | null>(null);
  const [error, setError] = useState('');
  const [revealed, setRevealed] = useState<string[]>([]);
  useEffect(() => { invoke<OrganizationStatus>('get_organization').then(setStatus).catch(e => setError(String(e))); }, []);
  if (error) return <p role="alert">{error}</p>;
  if (!status?.enabled) return <p className="text-sm text-on-surface-variant">Enable folders and richer items in the vault to organize this item and add custom fields.</p>;
  const fields = value.customFields ?? [];
  const urls = value.additionalUrls ?? [];
  const identity = value.identityDetails ?? {addresses:[]};
  const updateField = (index: number, patch: Partial<CustomField>) => onChange({customFields:fields.map((f,i) => i === index ? {...f,...patch} : f)});
  const updateUrl = (index: number, patch: Partial<AdditionalUrl>) => onChange({additionalUrls:urls.map((u,i) => i === index ? {...u,...patch} : u)});
  const updateIdentity = (patch: Partial<IdentityDetails>) => onChange({identityDetails:{...identity,...patch}});
  const paths = folderPaths(status.organization);
  return <div className="space-y-6 border-t border-outline-variant/20 pt-4">
    <fieldset className="space-y-3"><legend className="font-bold mb-2">Organization</legend>
      <label className="block">Folder<select aria-label="Item folder" className={input} value={value.folderId ?? ''} onChange={e => onChange({folderId:e.target.value})}><option value="">Unfiled</option>{paths.map(f => <option key={f.id} value={f.id}>{f.path}</option>)}</select></label>
      <details className="rounded-lg bg-surface-container-highest p-3"><summary className="cursor-pointer text-sm">{(value.tagIds ?? []).length ? `${(value.tagIds ?? []).length} tags selected` : 'Add tags…'}</summary><div className="flex flex-col gap-3 pt-3 max-h-48 overflow-y-auto" role="group" aria-label="Tags">{status.organization.tags.map(t => <label key={t.id}><input type="checkbox" checked={(value.tagIds ?? []).includes(t.id)} onChange={e => onChange({tagIds:e.target.checked ? [...(value.tagIds ?? []),t.id] : (value.tagIds ?? []).filter(id => id !== t.id)})}/> {t.name}</label>)}{!status.organization.tags.length && <span className="text-sm text-on-surface-variant">Create tags in Manage collections.</span>}</div></details>
    </fieldset>
    <fieldset className="space-y-3"><legend className="font-bold mb-2">Custom fields</legend>
      {fields.map((field,index) => {
        const supported = ['text','concealed','boolean'].includes(field.type);
        return <div key={field.id} className="rounded-xl p-3 bg-surface-container space-y-2">
          <div className="flex flex-wrap gap-2">
            <input aria-label={`Custom field ${index+1} label`} className={`${input} flex-1`} disabled={!supported} value={field.label} onChange={e => updateField(index,{label:e.target.value})} placeholder="Field label"/>
            <select aria-label={`Custom field ${index+1} type`} className={button} disabled={!supported} value={field.type} onChange={e => updateField(index,{type:e.target.value,value:e.target.value === 'boolean' ? false : typeof field.value === 'string' ? field.value : ''})}><option value="text">Text</option><option value="concealed">Concealed</option><option value="boolean">Boolean</option>{!supported && <option value={field.type}>Unsupported (preserved)</option>}</select>
          </div>
          {supported && (field.type === 'boolean' ? <label><input type="checkbox" checked={field.value === true} onChange={e => updateField(index,{value:e.target.checked})}/> Enabled</label> : <div className="flex gap-2"><input aria-label={`Custom field ${index+1} value`} className={input} type={field.type === 'concealed' && !revealed.includes(field.id) ? 'password' : 'text'} autoComplete="off" spellCheck={false} value={String(field.value ?? '')} onChange={e => updateField(index,{value:e.target.value})}/>{field.type === 'concealed' && <button type="button" className={button} onClick={() => setRevealed(r => r.includes(field.id) ? r.filter(id => id !== field.id) : [...r,field.id])}>{revealed.includes(field.id) ? 'Hide' : 'Reveal'}</button>}</div>)}
          <details className="text-sm"><summary className="cursor-pointer text-on-surface-variant py-1">Field options</summary><div className="flex flex-wrap gap-2 pt-2">
            <button type="button" className={button} disabled={!index} onClick={() => {const next=[...fields];[next[index-1],next[index]]=[next[index],next[index-1]];onChange({customFields:next});}}>Move up</button>
            <button type="button" className={button} disabled={index === fields.length-1} onClick={() => {const next=[...fields];[next[index+1],next[index]]=[next[index],next[index+1]];onChange({customFields:next});}}>Move down</button>
            <button type="button" className={button} disabled={!supported} onClick={() => onChange({customFields:fields.filter(f => f.id !== field.id)})}>Remove field</button>
          </div></details>
        </div>;
      })}
      <button type="button" className={button} disabled={fields.length >= 128} onClick={() => onChange({customFields:[...fields,{id:crypto.randomUUID(),label:'',type:'concealed',value:''}]})}>Add custom field</button>
    </fieldset>
    {value.item_type === 'login' && <fieldset className="space-y-3"><legend className="font-bold mb-2">Additional sites</legend>
      <p className="text-sm text-on-surface-variant">Stored with this login. Autofill continues to use the primary URL until alternate-site approval is supported.</p>
      {urls.map((url,index) => <div key={url.id} className="flex flex-wrap gap-2"><input aria-label={`Additional URL ${index+1}`} className={`${input} flex-1`} type="url" value={url.url} onChange={e => updateUrl(index,{url:e.target.value})} placeholder="https://example.com"/><select aria-label={`URL ${index+1} match rule`} className={button} value={url.match} onChange={e => updateUrl(index,{match:e.target.value})}><option value="origin">Origin</option><option value="exact">Exact URL</option></select><button type="button" className={button} onClick={() => onChange({additionalUrls:urls.filter(u => u.id !== url.id)})}>Remove URL</button></div>)}
      <button type="button" className={button} disabled={urls.length >= 32} onClick={() => onChange({additionalUrls:[...urls,{id:crypto.randomUUID(),url:'',match:'origin'}]})}>Add site</button>
    </fieldset>}
    {value.item_type === 'identity' && <fieldset className="space-y-3"><legend className="font-bold mb-2">Contact and addresses</legend>
      {(['middleName','preferredName','email','phone','company','jobTitle'] as const).map(key => <label className="block" key={key}>{key.replace(/([A-Z])/g,' $1')}<input className={input} value={identity[key] ?? ''} onChange={e => updateIdentity({[key]:e.target.value})}/></label>)}
      {identity.addresses.map((address,index) => <div key={address.id} className="space-y-2 rounded-xl bg-surface-container p-3"><h4>Address {index+1}</h4>{(['label','line1','line2','city','region','postalCode','countryCode'] as const).map(key => <label className="block" key={key}>{key.replace(/([A-Z])/g,' $1')}<input className={input} value={address[key] ?? ''} onChange={e => updateIdentity({addresses:identity.addresses.map((a,i) => i === index ? {...a,[key]:e.target.value} : a)})}/></label>)}<button type="button" className={button} onClick={() => updateIdentity({addresses:identity.addresses.filter(a => a.id !== address.id)})}>Remove address</button></div>)}
      <button type="button" className={button} disabled={identity.addresses.length >= 16} onClick={() => updateIdentity({addresses:[...identity.addresses,{id:crypto.randomUUID()} as PostalAddress]})}>Add address</button>
    </fieldset>}
  </div>;
}
