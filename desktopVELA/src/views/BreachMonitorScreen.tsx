import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp, BreachEntry, isBreachMonitorItem, VaultItem } from '../context/AppContext';

interface BreachMonitorItem {
  id: string;
  email: string;
  checked_at: string | null;
  breach_count: number;
  breaches: BreachEntry[];
}

interface PasswordBreachResult {
  breached: boolean;
  count: number;
  description: string;
}

export default function BreachMonitorScreen() {
  const { items, showToast, session } = useApp();
  const [email, setEmail] = useState('');
  const [checking, setChecking] = useState(false);
  const [passwordChecking, setPasswordChecking] = useState(false);
  const [showAddEmail, setShowAddEmail] = useState(false);
  const [passwordResults, setPasswordResults] = useState<PasswordBreachResult[]>([]);

  const breachMonitorItems = items.filter(isBreachMonitorItem) as (VaultItem & { email: string; checked_at: string | null; breach_count: number; breaches: BreachEntry[] })[];

  const handleAddEmail = async () => {
    if (!email.trim() || !email.includes('@')) {
      showToast('Please enter a valid email address', 'error');
      return;
    }

    try {
      const result = await invoke<BreachEntry[]>('check_email_breach', { email: email.trim() });
      
      const now = new Date().toISOString();
      const newMonitorItem = {
        id: crypto.randomUUID(),
        name: email.trim(),
        item_type: 'breachMonitor' as const,
        email: email.trim(),
        checked_at: now,
        breach_count: result.length,
        breaches: result,
        created_at: now,
        updated_at: now,
        favorite: false,
        shared: false,
      };

      await invoke('add_item', { item: newMonitorItem });
      showToast(`Added ${email}. Found ${result.length} breaches.`, result.length > 0 ? 'error' : 'success');
      setEmail('');
      setShowAddEmail(false);
    } catch (e) {
      showToast('Failed to check email: ' + String(e), 'error');
    }
  };

  const handleCheckAll = async () => {
    if (!session?.active) {
      showToast('Session not active', 'error');
      return;
    }
    setChecking(true);
    try {
      const total = await invoke<number>('check_all_vault_emails');
      showToast(`Found ${total} total breaches across all vault emails`, total > 0 ? 'error' : 'info');
    } catch (e) {
      showToast('Check failed: ' + String(e), 'error');
    } finally {
      setChecking(false);
    }
  };

  const handleRefresh = async (item: BreachMonitorItem) => {
    try {
      const result = await invoke<BreachEntry[]>('check_email_breach', { email: item.email });
      showToast(`Found ${result.length} breaches for ${item.email}`, result.length > 0 ? 'error' : 'info');
    } catch (e) {
      showToast('Refresh failed: ' + String(e), 'error');
    }
  };

  const handleCheckAllPasswords = async () => {
    if (!session?.active) {
      showToast('Session not active', 'error');
      return;
    }
    setPasswordChecking(true);
    setPasswordResults([]);
    try {
      const results = await invoke<PasswordBreachResult[]>('check_all_vault_passwords');
      setPasswordResults(results);
      const breached = results.filter(r => r.breached).length;
      if (breached > 0) {
        showToast(`${breached} passwords found in data breaches!`, 'error');
      } else {
        showToast('All vault passwords are safe', 'success');
      }
    } catch (e) {
      showToast('Check failed: ' + String(e), 'error');
    } finally {
      setPasswordChecking(false);
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'Never';
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
    });
  };

  return (
    <div className="flex-1 p-8 overflow-y-auto">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-8">
        <div>
          <h1 className="font-headline text-3xl font-bold text-on-surface">Breach Monitor</h1>
          <p className="text-on-surface-variant mt-1">Monitor your emails for data breaches</p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={handleCheckAll}
            disabled={checking || !session?.active}
            className="px-4 py-2 bg-primary/10 text-primary rounded-xl font-label text-sm hover:bg-primary/20 transition-colors disabled:opacity-50"
          >
            {checking ? 'Checking...' : 'Check All Vault Emails'}
          </button>
          <button
            onClick={() => setShowAddEmail(true)}
            className="px-4 py-2 bg-primary text-white rounded-xl font-label text-sm hover:bg-primary/90 transition-colors"
          >
            + Add Email
          </button>
        </div>
      </div>

      {showAddEmail && (
        <div className="bg-surface-container rounded-xl p-6 mb-6 border border-outline-variant/20">
          <h3 className="font-body font-medium text-on-surface mb-4">Add email to monitor</h3>
          <div className="flex gap-3">
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="email@example.com"
              className="flex-1 px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface outline-none focus:ring-2 focus:ring-primary/40"
              onKeyDown={e => e.key === 'Enter' && handleAddEmail()}
            />
            <button
              onClick={handleAddEmail}
              className="px-6 py-3 bg-primary text-white rounded-xl font-label text-sm hover:bg-primary/90"
            >
              Check & Add
            </button>
            <button
              onClick={() => { setShowAddEmail(false); setEmail(''); }}
              className="px-6 py-3 bg-surface-container-highest text-on-surface rounded-xl font-label text-sm hover:bg-surface-bright"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {breachMonitorItems.length === 0 ? (
        <div className="text-center py-16">
          <div className="w-16 h-16 bg-surface-container rounded-full flex items-center justify-center mx-auto mb-4">
            <span className="material-symbols-outlined text-3xl text-on-surface-variant">security</span>
          </div>
          <h3 className="font-body text-lg font-medium text-on-surface mb-2">No emails monitored</h3>
          <p className="text-on-surface-variant text-sm mb-6">Add an email to start monitoring for breaches</p>
        </div>
      ) : (
        <div className="space-y-4">
          {breachMonitorItems.map(item => (
            <div key={item.id} className="bg-surface-container rounded-xl p-6 border border-outline-variant/10">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="font-body font-medium text-on-surface text-lg">{item.email}</h3>
                  <p className="text-sm text-on-surface-variant">
                    Last checked: {formatDate(item.checked_at)}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {item.breach_count > 0 ? (
                    <span className="px-3 py-1 bg-red-500/10 text-red-400 rounded-full text-xs font-label font-bold">
                      {item.breach_count} BREACH{item.breach_count > 1 ? 'ES' : ''}
                    </span>
                  ) : (
                    <span className="px-3 py-1 bg-green-500/10 text-green-400 rounded-full text-xs font-label font-bold">
                      NO BREACHES
                    </span>
                  )}
                  <button
                    onClick={() => handleRefresh(item)}
                    className="p-2 hover:bg-surface-container-highest rounded-lg transition-colors"
                    title="Refresh"
                  >
                    <span className="material-symbols-outlined text-xl text-on-surface-variant">refresh</span>
                  </button>
                </div>
              </div>

              {item.breaches.length > 0 && (
                <div className="space-y-2">
                  <h4 className="font-label text-xs uppercase tracking-widest text-slate-500">Breached Sites</h4>
                  {item.breaches.map((breach, idx) => (
                    <div key={idx} className="bg-surface-container-highest rounded-lg p-4">
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <span className="font-body font-medium text-on-surface">{breach.title}</span>
                          <span className="text-xs text-on-surface-variant ml-2">({breach.domain})</span>
                        </div>
                        <span className="text-xs text-on-surface-variant">{breach.breach_date}</span>
                      </div>
                      <p className="text-xs text-on-surface-variant line-clamp-2 mb-2">{breach.description.replace(/<[^>]*>/g, '')}</p>
                      <div className="flex flex-wrap gap-1">
                        {breach.data_classes.map((dataClass, i) => (
                          <span key={i} className="px-2 py-0.5 bg-surface-bright rounded text-[10px] text-on-surface-variant">
                            {dataClass}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="mt-8 pt-8 border-t border-outline-variant/10">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-6">
          <div>
            <h2 className="font-headline text-2xl font-bold text-on-surface">Password Breach Check</h2>
            <p className="text-on-surface-variant mt-1">Check if your vault passwords have been exposed in data breaches</p>
          </div>
          <button
            onClick={handleCheckAllPasswords}
            disabled={passwordChecking || !session?.active}
            className="px-4 py-2 bg-orange-500/10 text-orange-400 rounded-xl font-label text-sm hover:bg-orange-500/20 transition-colors disabled:opacity-50"
          >
            {passwordChecking ? 'Checking...' : 'Check All Vault Passwords'}
          </button>
        </div>

        {passwordResults.length > 0 && passwordResults.filter(r => r.breached).length > 0 && (
          <div className="space-y-3">
            {passwordResults.filter(r => r.breached).map((result, idx) => (
              <div key={idx} className="p-4 rounded-xl border bg-red-500/5 border-red-500/20">
                <div className="flex items-start gap-3">
                  <span className="material-symbols-outlined text-xl mt-0.5 text-red-400">
                    warning
                  </span>
                  <div className="flex-1">
                    <p className="font-body font-medium text-red-400">
                      Exposed {result.count.toLocaleString()} times
                    </p>
                    <p className="text-sm text-on-surface-variant mt-1">{result.description}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {passwordResults.length > 0 && passwordResults.every(r => !r.breached) && (
          <div className="mt-4 p-4 bg-green-500/10 rounded-xl border border-green-500/20">
            <div className="flex items-center gap-3">
              <span className="material-symbols-outlined text-2xl text-green-400">verified_user</span>
              <div>
                <p className="font-body font-medium text-green-400">All passwords are secure!</p>
                <p className="text-sm text-on-surface-variant">None of your vault passwords have been found in known data breaches.</p>
              </div>
            </div>
          </div>
        )}

        {passwordResults.filter(r => r.breached).length > 0 && (
          <div className="mt-4 p-4 bg-red-500/10 rounded-xl border border-red-500/20">
            <div className="flex items-center gap-3">
              <span className="material-symbols-outlined text-2xl text-red-400">gpp_bad</span>
              <div>
                <p className="font-body font-medium text-red-400">Warning: Compromised passwords detected!</p>
                <p className="text-sm text-on-surface-variant mt-1">
                  {passwordResults.filter(r => r.breached).length} password(s) in your vault have been exposed in data breaches. 
                  Consider changing them immediately.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="mt-8 p-4 bg-surface-container rounded-xl border border-outline-variant/10">
        <h4 className="font-label text-xs uppercase tracking-widest text-slate-500 mb-3">How it works</h4>
        <ul className="text-sm text-on-surface-variant space-y-1">
          <li>• <strong>Email monitoring:</strong> Add emails to check against HaveIBeenPwned for breach data</li>
          <li>• <strong>Password checking:</strong> Uses k-anonymity — only the first 5 chars of the password hash leave your device</li>
          <li>• <strong>Privacy:</strong> Passwords are hashed with SHA-1 locally; no plaintext passwords are ever sent</li>
          <li>• <strong>No API key needed:</strong> Uses the free Pwned Passwords API (rate-limited to 1 req/sec)</li>
        </ul>
      </div>
    </div>
  );
}
