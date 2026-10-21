import { act, fireEvent, render, screen, waitFor, cleanup } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import { AppProvider } from '../context/AppContext';
import AddItemModal from './AddItemModal';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));

afterEach(() => { cleanup(); vi.restoreAllMocks(); });
const legacyOrganization = {enabled:false,organization:{folders:[],tags:[],organizationTombstones:[]}};
beforeEach(() => { vi.clearAllMocks(); vi.mocked(invoke).mockImplementation(async command => command === 'get_organization' ? legacyOrganization : undefined); });

describe('item editor interactions', () => {
  it('focuses the name field and lets Escape close the editor', () => {
    const onClose = vi.fn();
    render(<AppProvider><AddItemModal onClose={onClose} onSave={vi.fn()} /></AppProvider>);
    const name = screen.getByPlaceholderText('Item name');
    expect(name).toHaveFocus();
    fireEvent.keyDown(name, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('keeps an in-flight save open and submits only once', async () => {
    let finish!: () => void;
    vi.mocked(invoke).mockImplementation(command => command === 'get_organization' ? Promise.resolve(legacyOrganization) : new Promise<void>(resolve => { finish = resolve; }));
    const onClose = vi.fn();
    const onSave = vi.fn();
    render(<AppProvider><AddItemModal onClose={onClose} onSave={onSave} /></AppProvider>);
    fireEvent.change(screen.getByPlaceholderText('Item name'), { target: { value: 'Example login' } });
    const submit = screen.getByRole('button', { name: 'Create Item' });
    fireEvent.click(submit);
    fireEvent.click(submit);
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
    expect(vi.mocked(invoke).mock.calls.filter(([command]) => command === 'add_item')).toHaveLength(1);
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();
    await act(async () => finish());
    await waitFor(() => expect(onSave).toHaveBeenCalledOnce());
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('leaves entered values available for retry after a failed save', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const save=vi.fn().mockRejectedValueOnce(new Error('Unavailable')).mockResolvedValueOnce(undefined);
    vi.mocked(invoke).mockImplementation(command => command === 'get_organization' ? Promise.resolve(legacyOrganization) : save());
    const onClose = vi.fn();
    render(<AppProvider><AddItemModal onClose={onClose} onSave={vi.fn()} /></AppProvider>);
    fireEvent.change(screen.getByPlaceholderText('Item name'), { target: { value: 'Keep this draft' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create Item' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create Item' })).toBeEnabled());
    expect(screen.getByPlaceholderText('Item name')).toHaveValue('Keep this draft');
    expect(onClose).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Create Item' }));
    await waitFor(() => expect(onClose).toHaveBeenCalledOnce());
    expect(save).toHaveBeenCalledTimes(2);
  });
});
