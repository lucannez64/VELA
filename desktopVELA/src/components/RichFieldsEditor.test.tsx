import { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import RichFieldsEditor from './RichFieldsEditor';
import { VaultItem } from '../context/AppContext';

vi.mock('@tauri-apps/api/core', () => ({invoke:vi.fn(async () => ({enabled:true,organization:{folders:[],tags:[],organizationTombstones:[]}}))}));

function Editor({initial}:{initial:Partial<VaultItem>}) {
  const [value,setValue]=useState(initial);
  return <><RichFieldsEditor value={value} onChange={patch => setValue(old => ({...old,...patch}))}/><output data-testid="state">{JSON.stringify(value)}</output></>;
}
describe('richer item editor', () => {
  it('masks concealed values, preserves unknown fields, and explicitly clears removed fields', async () => {
    render(<Editor initial={{item_type:'login',customFields:[{id:'known',label:'Recovery',type:'concealed',value:'fixture-secret'},{id:'future',label:'Future',type:'future',value:{opaque:'keep'}}]}}/>);
    const input=await screen.findByLabelText('Custom field 1 value');
    expect(input).toHaveAttribute('type','password');
    fireEvent.click(screen.getByRole('button',{name:'Reveal'}));
    expect(input).toHaveAttribute('type','text');
    fireEvent.click(screen.getAllByText('Field options')[0]);
    fireEvent.click(screen.getAllByRole('button',{name:'Remove field'})[0]);
    expect(JSON.parse(screen.getByTestId('state').textContent!).customFields).toEqual([{id:'future',label:'Future',type:'future',value:{opaque:'keep'}}]);
    fireEvent.click(screen.getByText('Field options'));
    expect(screen.getByRole('button',{name:'Remove field'})).toBeDisabled();
  });
  it('creates identity addresses without requiring a country and retains the richer contact fields',async()=>{
    render(<Editor initial={{item_type:'identity'}}/>);
    fireEvent.click(await screen.findByRole('button',{name:'Add address'}));
    fireEvent.change(screen.getByLabelText('line1'),{target:{value:'Fixture street'}});
    const state=JSON.parse(screen.getByTestId('state').textContent!);
    expect(state.identityDetails.addresses[0]).toMatchObject({line1:'Fixture street'});
    expect(state.identityDetails.addresses[0].id).toBeTruthy();
  });
});
