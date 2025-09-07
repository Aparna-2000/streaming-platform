import { useEffect, useState } from 'react';

type Props = {
  open: boolean;
  onConfirm: () => void;
};

export default function SecurityAlertModal({ open, onConfirm }: Props) {
  const [countdown, setCountdown] = useState(3);

  useEffect(() => {
    if (!open) {
      setCountdown(3);
      return;
    }

    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          onConfirm();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [open, onConfirm]);

  if (!open) return null;
  
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-white rounded-2xl shadow-xl p-6 max-w-md w-full mx-4">
        <div className="text-center">
          <div className="text-4xl mb-4">🚨</div>
          <h2 className="text-xl font-semibold mb-2 text-gray-900">Security Alert</h2>
          <p className="text-sm mb-4 text-gray-600">
            Suspicious activity was detected on your account. For your protection, all sessions have been terminated.
          </p>
          <p className="text-sm mb-6 text-gray-500">
            Redirecting to login in {countdown} seconds...
          </p>
          <div className="w-full bg-gray-200 rounded-full h-2 mb-4">
            <div 
              className="bg-red-600 h-2 rounded-full transition-all duration-1000"
              style={{ width: `${((3 - countdown) / 3) * 100}%` }}
            ></div>
          </div>
          <button
            onClick={onConfirm}
            className="w-full rounded-xl px-4 py-3 bg-red-600 text-white font-medium hover:bg-red-700 transition-colors"
          >
            Login Now
          </button>
        </div>
      </div>
    </div>
  );
}
