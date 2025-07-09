import { useTranslation } from "react-i18next";
import { I18nKey } from "#/i18n/declaration";

interface StopButtonProps {
  isDisabled?: boolean;
  onClick?: () => void;
}

export function StopButton({ isDisabled, onClick }: StopButtonProps) {
  const { t } = useTranslation();
  return (
    <button
      data-testid="stop-button"
      aria-label={t(I18nKey.BUTTON$STOP)}
      disabled={isDisabled}
      onClick={onClick}
      type="button"
      className="border border-white rounded-lg w-6 h-6 flex items-center justify-center cursor-pointer apple-transition 
                 hover:bg-danger/20 hover:border-danger hover:scale-105
                 focus:bg-danger/20 focus:border-danger focus:ring-2 focus:ring-danger/40 focus:outline-none
                 active:scale-95
                 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:bg-transparent disabled:hover:border-white disabled:hover:scale-100"
    >
      <div className="w-[10px] h-[10px] bg-white transition-colors duration-200" />
    </button>
  );
}
