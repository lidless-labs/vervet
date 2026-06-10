/**
 * NotificationToast: renders stacked toast notifications.
 */
import React from 'react';
import { X, CheckCircle, AlertTriangle, AlertCircle, Info, type LucideIcon } from 'lucide-react';
import { useNotifications, NotificationType } from '../stores/notificationStore';

const iconMap: Record<NotificationType, LucideIcon> = {
  success: CheckCircle,
  error: AlertCircle,
  warning: AlertTriangle,
  info: Info,
};

const colorMap: Record<NotificationType, string> = {
  success: 'border-green-500/40 bg-green-500/10 text-green-400',
  error: 'border-red-500/40 bg-red-500/10 text-red-400',
  warning: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400',
  info: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-400',
};

const NotificationToast: React.FC = () => {
  const { notifications, dismiss } = useNotifications();

  if (notifications.length === 0) return null;

  return (
    <div
      style={{
        position: 'fixed',
        top: 16,
        right: 16,
        zIndex: 9999,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        maxWidth: 380,
        pointerEvents: 'none',
      }}
    >
      {notifications.map((n) => {
        const Icon = iconMap[n.type];
        return (
          <div
            key={n.id}
            className={`border rounded-lg px-4 py-3 shadow-lg ${colorMap[n.type]}`}
            style={{
              pointerEvents: 'auto',
              animation: 'fadeInSlide 0.2s ease-out',
              backdropFilter: 'blur(8px)',
            }}
            role="alert"
          >
            <div className="flex items-start gap-3">
              <Icon size={18} className="mt-0.5 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="font-medium text-sm">{n.title}</div>
                {n.message && (
                  <div className="text-xs opacity-80 mt-0.5">{n.message}</div>
                )}
              </div>
              <button
                onClick={() => dismiss(n.id)}
                className="opacity-60 hover:opacity-100 transition-opacity flex-shrink-0"
                aria-label="Dismiss notification"
              >
                <X size={14} />
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default NotificationToast;
