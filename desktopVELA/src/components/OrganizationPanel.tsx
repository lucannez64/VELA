import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { invoke } from '@tauri-apps/api/core';
import { folderPaths, OrganizationStatus } from '../lib/organization';

const control = 'w-full rounded-lg border border-outline-variant/20 bg-surface-container-highest text-on-surface px-3 py-2 min-w-0';
const button = 'rounded-lg px-3 py-2 text-sm hover:bg-primary/10 disabled:opacity-50';
const primary = `${button} bg-primary text-on-primary`;
interface Props {
  status: OrganizationStatus | null; reload: () => Promise<void>;
  folder: string; setFolder: (id: string) => void; tag: string; setTag: (id: string) => void;
  descendants: boolean; setDescendants: (value: boolean) => void;
  selected: string[]; clearSelection: () => void;
}
type Dialog = 'setup' | 'manage' | 'move' | 'tags';
export default function OrganizationPanel(p: Props) {
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [kind, setKind] = useState<'folder' | 'tag'>('folder');
  const [record, setRecord] = useState('');
  const [name, setName] = useState('');
  const [parent, setParent] = useState('');
  const [bulkFolder, setBulkFolder] = useState('');
  const [bulkTag, setBulkTag] = useState('');
  const [deleting, setDeleting] = useState(false);
  useEffect(() => {
    if (!dialog) return;
    const previous = document.activeElement as HTMLElement | null;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = overflow; previous?.focus(); };
  }, [dialog]);
  const paths = p.status ? folderPaths(p.status.organization) : [];
  const tags = p.status?.organization.tags ?? [];
  const open = (value: Dialog) => { setDialog(value); setError(''); setDeleting(false); setRecord(''); setName(''); setParent(''); setBulkFolder(''); setBulkTag(''); };
  const close = () => { if (!busy) { setDialog(null); setError(''); } };
  const run = async (task: () => Promise<unknown>, after?: () => void) => {
    if (busy) return;
    setBusy(true); setError('');
    try { await task(); await p.reload(); after?.(); setDialog(null); }
    catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  };
  const save = () => run(() => invoke('mutate_organization', { action: {
    operation: record ? (kind === 'folder' ? 'updateFolder' : 'renameTag') : (kind === 'folder' ? 'createFolder' : 'createTag'),
    id: record, name, parentId: parent || null,
  }}));
  const assign = (remove = false) => run(() => invoke('assign_items', { changes: {
    ids: p.selected, folderId: dialog === 'move' ? bulkFolder : null,
    addTags: dialog === 'tags' && !remove ? [bulkTag] : [],
    removeTags: dialog === 'tags' && remove ? [bulkTag] : [],
  }}), p.clearSelection);
  if (!p.status) return null;
  return <section className="mb-4 text-on-surface" aria-label="Vault organization">
    <div className="flex flex-wrap items-center gap-2 text-sm">
      {p.status.enabled ? <>
        <select aria-label="Folder filter" className={`${control} !w-auto max-w-64`} value={p.folder} onChange={e => p.setFolder(e.target.value)}>
          <option value="all">All items</option><option value="unfiled">Unfiled</option>{paths.map(f => <option key={f.id} value={f.id}>{f.path}</option>)}
        </select>
        <select aria-label="Tag filter" className={`${control} !w-auto max-w-48`} value={p.tag} onChange={e => p.setTag(e.target.value)}>
          <option value="">Any tag</option>{tags.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
        </select>
        {p.folder !== 'all' && p.folder !== 'unfiled' && <label className="flex items-center gap-2"><input type="checkbox" checked={p.descendants} onChange={e => p.setDescendants(e.target.checked)}/> Include subfolders</label>}
        <button className={`${button} ml-auto text-on-surface-variant`} onClick={() => open('manage')}>Manage collections…</button>
      </> : <button className={`${button} text-on-surface-variant`} onClick={() => open('setup')}>Set up collections…</button>}
    </div>
    {!!p.selected.length && <div className="mt-3 flex flex-wrap items-center gap-2 rounded-xl bg-primary/10 p-2">
      <strong className="mr-auto px-2 text-sm">{p.selected.length} selected</strong>
      <button className={button} onClick={() => open('move')}>Move…</button>
      <button className={button} onClick={() => open('tags')}>Tags…</button>
      <button className={button} onClick={p.clearSelection}>Cancel selection</button>
    </div>}
    {dialog && createPortal(<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-3" onKeyDown={e => {if (e.key === 'Escape') {e.stopPropagation(); close();}
      if (e.key === 'Tab') {
        const controls = [...e.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled)')].filter(el => el.getClientRects().length > 0);
        const first = controls[0], last = controls[controls.length - 1];
        if (e.shiftKey && document.activeElement === first) {e.preventDefault();last?.focus();}
        else if (!e.shiftKey && document.activeElement === last) {e.preventDefault();first?.focus();}
      }}}>
      <div role="dialog" aria-modal="true" aria-labelledby="collections-title" className="flex max-h-[calc(100dvh-2rem)] w-full max-w-lg flex-col overflow-hidden rounded-2xl border border-outline-variant/20 bg-surface-container text-on-surface shadow-2xl">
        <header className="flex shrink-0 items-center justify-between border-b border-outline-variant/20 px-5 py-4">
          <h2 id="collections-title" className="text-xl font-bold">{{setup:'Set up collections',manage:'Manage collections',move:'Move items',tags:'Edit tags'}[dialog]}</h2>
          <button autoFocus aria-label="Close collections" disabled={busy} className={button} onClick={close}>✕</button>
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto"><fieldset disabled={busy} className="space-y-4 p-5">
          {dialog === 'setup' && <><h3 className="text-lg font-semibold">A place for everything</h3><p>Organize your vault with folders and tags, and add custom fields, extra websites and identity details.</p><p className="text-sm text-on-surface-variant">An encrypted safety copy is saved on this device before activation. Mobile and browser access becomes read-only during rollout. Older desktop apps must upgrade before syncing changes.</p></>}
          {dialog === 'manage' && <>
            <div className="flex gap-2">{(['folder','tag'] as const).map(value => <button key={value} aria-pressed={kind === value} className={kind === value ? primary : button} onClick={() => {setKind(value);setRecord('');setName('');setParent('');setDeleting(false);}}>{value === 'folder' ? 'Folders' : 'Tags'}</button>)}</div>
            <label className="block space-y-2"><span className="text-sm text-on-surface-variant">Collection</span><select aria-label="Folder or tag to manage" className={control} value={record} onChange={e => {setRecord(e.target.value);setName((kind === 'folder' ? paths : tags).find(r => r.id === e.target.value)?.name ?? '');setParent(kind === 'folder' ? p.status!.organization.folders.find(f => f.id === e.target.value)?.parentId ?? '' : '');setDeleting(false);}}><option value="">+ Create new {kind}</option>{(kind === 'folder' ? paths.map(f => ({...f,name:f.path})) : tags).map(r => <option key={r.id} value={r.id}>{r.name}</option>)}</select></label>
            <label className="block space-y-2"><span className="text-sm text-on-surface-variant">Name</span><input aria-label="Folder or tag name" className={control} value={name} onChange={e => setName(e.target.value)} placeholder={kind === 'folder' ? 'e.g. Personal' : 'e.g. Important'} maxLength={128}/></label>
            {kind === 'folder' && <label className="block space-y-2"><span className="text-sm text-on-surface-variant">Parent folder</span><select aria-label="Parent folder" className={control} value={parent} onChange={e => setParent(e.target.value)}><option value="">Top level</option>{paths.filter(f => f.id !== record).map(f => <option key={f.id} value={f.id}>{f.path}</option>)}</select></label>}
            {record && <div className="border-t border-outline-variant/20 pt-3"><button className={`${button} text-error`} onClick={() => setDeleting(!deleting)}>Delete collection…</button>{deleting && <div className="mt-2 space-y-2 rounded-lg bg-error/10 p-3 text-sm"><p>No items will be deleted. Folder items become unfiled and subfolders move up. A deleted tag is removed from all items.</p><button className={`${button} text-error`} onClick={() => void run(() => invoke('mutate_organization', {action:{operation:kind === 'folder' ? 'deleteFolder' : 'deleteTag',id:record}}), () => {p.setFolder('all');p.setTag('');})}>Delete permanently</button></div>}</div>}
          </>}
          {dialog === 'move' && <><p className="text-sm text-on-surface-variant">Choose a destination for {p.selected.length} selected items.</p><label className="block space-y-2"><span>Destination</span><select aria-label="Bulk move destination" className={control} value={bulkFolder} onChange={e => setBulkFolder(e.target.value)}><option value="">Unfiled</option>{paths.map(f => <option key={f.id} value={f.id}>{f.path}</option>)}</select></label></>}
          {dialog === 'tags' && <><p className="text-sm text-on-surface-variant">Choose a tag for {p.selected.length} selected items.</p><select aria-label="Bulk tag" className={control} value={bulkTag} onChange={e => setBulkTag(e.target.value)}><option value="">Choose tag…</option>{tags.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}</select>{!tags.length && <p className="text-sm">Create a tag in Manage collections first.</p>}</>}
          {error && <p role="alert" className="text-sm text-error">{error}</p>}
        </fieldset></div>
        <footer className="flex shrink-0 flex-wrap justify-end gap-2 border-t border-outline-variant/20 px-5 py-4">
          <button disabled={busy} className={button} onClick={close}>Cancel</button>
          {dialog === 'setup' && <button disabled={busy} className={primary} onClick={() => void run(() => invoke('activate_rich_items'))}>{busy ? 'Enabling…' : 'Enable collections'}</button>}
          {dialog === 'manage' && <button disabled={busy || !name.trim()} className={primary} onClick={() => void save()}>{busy ? 'Saving…' : record ? 'Save changes' : 'Create'}</button>}
          {dialog === 'move' && <button disabled={busy} className={primary} onClick={() => void assign()}>{busy ? 'Moving…' : 'Move here'}</button>}
          {dialog === 'tags' && <><button disabled={busy || !bulkTag} className={button} onClick={() => void assign(true)}>Remove tag</button><button disabled={busy || !bulkTag} className={primary} onClick={() => void assign()}>Add tag</button></>}
        </footer>
      </div>
    </div>, document.body)}
  </section>;
}
