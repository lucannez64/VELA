import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { VaultItem } from '../context/AppContext';
import { useClipboard } from '../hooks/useClipboard';
import { OrganizationStatus, folderPaths } from '../lib/organization';

export default function RichItemDetails({item}: {item: VaultItem}) {
  const [status,setStatus] = useState<OrganizationStatus | null>(null);
  const [revealed,setRevealed] = useState<string[]>([]);
  const {copyToClipboard} = useClipboard();
  useEffect(() => {setRevealed([]); void invoke<OrganizationStatus>('get_organization').then(setStatus).catch(() => {});},[item.id]);
  const row = (id:string,label:string,value:string,concealed=false) => <div key={id} className="rounded-xl bg-surface-container-low p-4 space-y-2">
    <h4 className="text-xs text-on-surface-variant">{label}</h4>
    <div className="flex gap-3 items-center"><span className="flex-1 min-w-0 whitespace-pre-wrap break-words">{concealed && !revealed.includes(id) ? '••••••••' : value}</span>
      {concealed && <button onClick={() => setRevealed(r => r.includes(id) ? r.filter(x => x !== id) : [...r,id])}>{revealed.includes(id) ? 'Hide' : 'Reveal'}</button>}
      <button aria-label={`Copy ${label}`} onClick={() => copyToClipboard(value,label)}>Copy</button>
    </div>
  </div>;
  const folder = status && folderPaths(status.organization).find(f => f.id === item.folderId);
  const tags = status?.organization.tags.filter(t => item.tagIds?.includes(t.id)) ?? [];
  const details = item.identityDetails;
  return <div className="space-y-3 my-6">
    {(folder || tags.length > 0) && <div className="flex flex-wrap gap-2 text-sm">{folder && <span className="rounded-lg bg-primary/10 px-3 py-2">Folder: {folder.path}</span>}{tags.map(t => <span key={t.id} className="rounded-lg bg-primary/10 px-3 py-2">#{t.name}</span>)}</div>}
    {item.item_type === 'identity' && <>{row('identity-name','Name',[item.firstName,item.lastName].filter(Boolean).join(' '))}{item.ssn && row('identity-number','Identity number / SSN',item.ssn,true)}</>}
    {item.customFields?.map(f => ['text','concealed','boolean'].includes(f.type) ? row(f.id,f.label,String(f.value ?? ''),f.type === 'concealed') : <p key={f.id}>{f.label} — unsupported field preserved</p>)}
    {item.additionalUrls?.map(u => row(u.id,`Additional site (${u.match})`,u.url))}
    {details && <>{(['middleName','preferredName','email','phone','company','jobTitle'] as const).map(key => details[key] ? row(key,key.replace(/([A-Z])/g,' $1'),details[key]!) : null)}
      {details.addresses.map(a => row(a.id,a.label || 'Address',[a.line1,a.line2,a.city,a.region,a.postalCode,a.countryCode].filter(Boolean).join('\n')))}</>}
  </div>;
}
