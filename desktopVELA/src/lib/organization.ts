export interface Folder { id: string; name: string; parentId: string | null }
export interface Tag { id: string; name: string }
export interface Organization { folders: Folder[]; tags: Tag[]; organizationTombstones: { kind: string; id: string }[] }
export interface OrganizationStatus { enabled: boolean; organization: Organization }
export const emptyOrganization: Organization = { folders: [], tags: [], organizationTombstones: [] };

export function folderPaths(org: Organization): { id: string; name: string; path: string }[] {
  const deleted = new Set(org.organizationTombstones.filter(t => t.kind === 'folder').map(t => t.id));
  const records = new Map(org.folders.filter(f => !deleted.has(f.id)).map(f => [f.id, f]));
  const parents = new Map([...records.values()].map(f => [f.id, f.parentId && records.has(f.parentId) ? f.parentId : null]));
  for (const id of records.keys()) {
    const chain: string[] = [];
    let cursor: string | null = id;
    while (cursor) {
      const index = chain.indexOf(cursor);
      if (index >= 0) { const cycle = chain.slice(index).sort(); parents.set(cycle[cycle.length - 1], null); break; }
      chain.push(cursor); cursor = parents.get(cursor) ?? null;
    }
  }
  return [...records.values()].map(f => {
    const names = [f.name]; let cursor = parents.get(f.id);
    while (cursor) { names.unshift(records.get(cursor)!.name); cursor = parents.get(cursor); }
    return { id: f.id, name: f.name, path: names.join(' / ') };
  }).sort((a, b) => a.path.localeCompare(b.path));
}

export function matchesOrganization(item: {folderId?: string; tagIds?: string[]}, org: Organization, folder: string, tag: string, descendants: boolean): boolean {
  const paths = folderPaths(org);
  const assigned = paths.find(f => f.id === item.folderId);
  if (folder === 'unfiled' && assigned) return false;
  if (folder !== 'all' && folder !== 'unfiled') {
    const target = paths.find(f => f.id === folder);
    // IDs determine membership; path strings are presentation only.
    let cursor = assigned?.id;
    const visited = new Set<string>();
    while (cursor && cursor !== folder && descendants && !visited.has(cursor)) {
      visited.add(cursor); cursor = org.folders.find(f => f.id === cursor)?.parentId ?? undefined;
    }
    if (!target || cursor !== folder) return false;
  }
  return !tag || (item.tagIds ?? []).includes(tag);
}
