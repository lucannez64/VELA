import { describe, expect, it } from 'vitest';
import { folderPaths, matchesOrganization, Organization } from './organization';
import { fromBackendItem, toBackendItem } from '../context/AppContext';

describe('organization and item conversion', () => {
  it('keeps same-name folders distinct and breaks concurrent cycles deterministically', () => {
    const org: Organization = {folders:[{id:'a',name:'Same',parentId:'b'},{id:'b',name:'Same',parentId:'a'}],tags:[],organizationTombstones:[]};
    expect(folderPaths(org)).toEqual([{id:'b',name:'Same',path:'Same'},{id:'a',name:'Same',path:'Same / Same'}]);
    expect(matchesOrganization({folderId:'a'},org,'b','',true)).toBe(true);
    expect(matchesOrganization({folderId:'a'},org,'b','',false)).toBe(false);
    org.organizationTombstones.push({kind:'folder',id:'a'});
    expect(matchesOrganization({folderId:'a'},org,'unfiled','',true)).toBe(true);
  });
  it('retains richer metadata and original timestamps through the renderer', () => {
    const backend={id:'login',name:'Test',item_type:'login',url:'https://example.com',username:'u',password:'p',createdAt:'2026-01-01T00:00:00Z',updatedAt:'2026-10-20T00:00:00Z',folderId:'folder',tagIds:['tag'],customFields:[{id:'field',label:'Recovery',type:'future-type',value:{secret:'opaque'}}],additionalUrls:[{id:'url',url:'https://other.example',match:'origin'}]};
    const renderer=fromBackendItem(backend);
    expect(renderer.created_at).toBe(backend.createdAt);
    const roundtrip=toBackendItem(renderer);
    expect(roundtrip).toMatchObject({folderId:'folder',tagIds:['tag'],customFields:backend.customFields,additionalUrls:backend.additionalUrls,created_at:backend.createdAt});
  });
});
