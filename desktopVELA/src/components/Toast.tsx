interface ToastProps {
  message: string;
  type: 'success' | 'error' | 'info';
}

export default function Toast({ message, type }: ToastProps) {
  const bgColor = {
    success: 'bg-primary/20 border-primary',
    error: 'bg-red-500/20 border-red-500',
    info: 'bg-secondary/20 border-secondary',
  }[type];

  const textColor = {
    success: 'text-primary',
    error: 'text-red-400',
    info: 'text-secondary',
  }[type];

  const icon = {
    success: 'check_circle',
    error: 'error',
    info: 'info',
  }[type];

  return (
    <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50">
      <div className={`glass-panel px-6 py-3 rounded-xl border ${bgColor} flex items-center gap-3`}>
        <span className={`material-symbols-outlined text-lg ${textColor}`}>{icon}</span>
        <span className="font-body text-sm text-on-surface">{message}</span>
      </div>
    </div>
  );
}
