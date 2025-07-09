import React from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { useTranslation } from "react-i18next";
import { code } from "../markdown/code";
import { ol, ul } from "../markdown/list";
import ArrowDown from "#/icons/angle-down-solid.svg?react";
import ArrowUp from "#/icons/angle-up-solid.svg?react";
import i18n from "#/i18n";

interface ErrorMessageProps {
  errorId?: string;
  defaultMessage: string;
}

export function ErrorMessage({ errorId, defaultMessage }: ErrorMessageProps) {
  const { t } = useTranslation();
  const [showDetails, setShowDetails] = React.useState(false);

  const hasValidTranslationId = !!errorId && i18n.exists(errorId);
  const errorKey = hasValidTranslationId
    ? errorId
    : "CHAT_INTERFACE$AGENT_ERROR_MESSAGE";
  const detailsId = `error-details-${errorId || "default"}`;

  return (
    <div
      className="flex flex-col gap-2 border-l-2 pl-2 my-2 py-2 border-danger text-sm w-full"
      role="alert"
      aria-live="polite"
    >
      <div className="font-bold text-danger flex items-center">
        <span className="text-danger mr-2" aria-hidden="true">
          ⚠️
        </span>
        {t(errorKey)}
        <button
          type="button"
          onClick={() => setShowDetails((prev) => !prev)}
          className="cursor-pointer text-left ml-2 hover:bg-danger/10 rounded-md p-1 apple-transition"
          aria-expanded={showDetails}
          aria-controls={detailsId}
          aria-label={
            showDetails
              ? t("ERROR$HIDE_DETAILS", "Hide error details")
              : t("ERROR$SHOW_DETAILS", "Show error details")
          }
        >
          {showDetails ? (
            <ArrowUp className="h-4 w-4 inline fill-danger" />
          ) : (
            <ArrowDown className="h-4 w-4 inline fill-danger" />
          )}
        </button>
      </div>

      {showDetails && (
        <div id={detailsId} className="mt-2">
          <Markdown
            components={{
              code,
              ul,
              ol,
            }}
            remarkPlugins={[remarkGfm]}
          >
            {defaultMessage}
          </Markdown>
        </div>
      )}
    </div>
  );
}
