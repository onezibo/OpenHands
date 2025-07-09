import { useTranslation } from "react-i18next";
import LoadingSpinnerOuter from "#/icons/loading-outer.svg?react";
import { cn } from "#/utils/utils";

interface LoadingSpinnerProps {
  size: "small" | "large";
  label?: string;
}

export function LoadingSpinner({ size, label }: LoadingSpinnerProps) {
  const { t } = useTranslation();
  const sizeStyle =
    size === "small" ? "w-[25px] h-[25px]" : "w-[50px] h-[50px]";

  return (
    <div
      data-testid="loading-spinner"
      className={cn("relative", sizeStyle)}
      role="status"
      aria-label={label || t("LOADING$SPINNER_ARIA_LABEL", "Loading...")}
    >
      <div
        className={cn(
          "rounded-full border-4 border-[#525252] absolute",
          sizeStyle,
        )}
      />
      <LoadingSpinnerOuter
        className={cn(
          "absolute",
          sizeStyle,
          "motion-safe:animate-spin motion-reduce:animate-none", // 考虑动画偏好
        )}
      />
      <span className="sr-only">
        {label || t("LOADING$SPINNER_ARIA_LABEL", "Loading...")}
      </span>
    </div>
  );
}
