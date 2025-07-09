import { useTranslation } from "react-i18next";
import ArrowSendIcon from "#/icons/arrow-send.svg?react";
import { I18nKey } from "#/i18n/declaration";

interface SubmitButtonProps {
  isDisabled?: boolean;
  onClick: () => void;
}

export function SubmitButton({ isDisabled, onClick }: SubmitButtonProps) {
  const { t } = useTranslation();
  return (
    <button
      aria-label={t(I18nKey.BUTTON$SEND)}
      disabled={isDisabled}
      onClick={onClick}
      type="submit"
      className="border border-white rounded-lg w-6 h-6 flex items-center justify-center cursor-pointer apple-transition 
                 hover:bg-neutral-500 hover:border-neutral-300 hover:scale-105
                 focus:bg-primary/20 focus:border-primary focus:ring-2 focus:ring-primary/40 focus:outline-none
                 active:scale-95
                 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:bg-transparent disabled:hover:border-white disabled:hover:scale-100"
    >
      <ArrowSendIcon className="transition-transform duration-200" />
    </button>
  );
}
