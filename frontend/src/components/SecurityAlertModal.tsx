type Props = {
  open: boolean;
  onConfirm: () => void;
};

export default function SecurityAlertModal({ open, onConfirm }: Props) {
  if (!open) return null;
  
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-white rounded-2xl shadow-xl p-6 max-w-md w-full mx-4">
        <div className="text-center">
          <div className="text-4xl mb-4">🚨</div>
          <h2 className="text-xl font-semibold mb-2 text-gray-900">Security Alert</h2>
          <p className="text-sm mb-6 text-gray-600">
            Suspicious activity was detected on your account. For your protection, all sessions have been terminated.
          </p>
          <button
            onClick={onConfirm}
            className="w-full rounded-xl px-4 py-3 bg-red-600 text-white font-medium hover:bg-red-700 transition-colors"
          >
            Re-login
          </button>
        </div>
      </div>
    </div>
  );
}
