import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';

interface Props {
  onSelect: (password: string) => void;
  onClose: () => void;
}

interface PasswordResult {
  password: string;
  strength: {
    entropy: number;
    score: string;
    crack_time: string;
  };
}

export default function PasswordGenerator({ onSelect, onClose }: Props) {
  const [password, setPassword] = useState('');
  const [, setStrength] = useState({ entropy: 0, score: '', crack_time: '' });
  const [options, setOptions] = useState({
    length: 20,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
    easyToType: false,
    pronounceable: false,
  });

  useEffect(() => {
    generatePassword();
  }, [options]);

  const generatePassword = async () => {
    try {
      const result = await invoke<PasswordResult>('generate_password', { 
        options: {
          length: options.length,
          uppercase: options.uppercase,
          lowercase: options.lowercase,
          numbers: options.numbers,
          symbols: options.symbols,
          easy_to_type: options.easyToType,
          pronounceable: options.pronounceable,
        }
      });
      setPassword(result.password);
      setStrength(result.strength);
    } catch (e) {
      console.error('Failed to generate password:', e);
    }
  };

  const handleUse = () => {
    onSelect(password);
    onClose();
  };

  return (
    <div className="absolute top-full left-0 mt-2 w-96 bg-surface-container rounded-xl shadow-2xl border border-outline-variant/20 p-4 z-50">
      <div className="flex items-center justify-between mb-4">
        <span className="text-sm font-label text-on-surface-variant">Generated</span>
        <button onClick={onClose} className="p-1 hover:bg-surface-container-high rounded">
          <span className="material-symbols-outlined text-sm">close</span>
        </button>
      </div>

      <div className="flex items-center gap-2 mb-4">
        <div className="flex-1 px-4 py-3 bg-surface-container-highest rounded-lg font-mono text-lg text-primary truncate">
          {password}
        </div>
        <button 
          onClick={generatePassword}
          className="p-2 hover:bg-surface-container-high rounded-lg text-on-surface-variant hover:text-primary transition-colors"
          title="Regenerate"
        >
          <span className="material-symbols-outlined">refresh</span>
        </button>
      </div>

      <div className="mb-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-label text-on-surface-variant">Length</span>
          <span className="text-xs font-mono text-primary">{options.length}</span>
        </div>
        <input
          type="range"
          min={8}
          max={64}
          value={options.length}
          onChange={e => setOptions(prev => ({ ...prev, length: Number(e.target.value) }))}
          className="w-full h-2 bg-surface-container-highest rounded-full appearance-none cursor-pointer accent-primary"
        />
      </div>

      <div className="space-y-2 mb-4">
        {[
          { key: 'uppercase', label: 'Uppercase (A-Z)' },
          { key: 'lowercase', label: 'Lowercase (a-z)' },
          { key: 'numbers', label: 'Numbers (0-9)' },
          { key: 'symbols', label: 'Symbols (!@#$...)' },
        ].map(({ key, label }) => (
          <label key={key} className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={options[key as keyof typeof options] as boolean}
              onChange={e => setOptions(prev => ({ ...prev, [key]: e.target.checked }))}
              className="w-4 h-4 accent-primary rounded"
            />
            <span className="text-sm text-on-surface">{label}</span>
          </label>
        ))}
      </div>

      <button
        onClick={handleUse}
        className="w-full py-3 bg-primary text-on-primary font-bold rounded-xl hover:bg-primary/90 transition-colors"
      >
        Use this password
      </button>
    </div>
  );
}
