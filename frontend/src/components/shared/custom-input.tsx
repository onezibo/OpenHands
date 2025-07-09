import React from "react";
import { useTranslation } from "react-i18next";
import { I18nKey } from "#/i18n/declaration";
import { cn } from "#/utils/utils";

interface CustomInputProps {
  name: string;
  label: string;
  required?: boolean;
  defaultValue?: string;
  type?: "text" | "password";
  placeholder?: string;
  error?: string;
  isValid?: boolean;
  onValidate?: (value: string) => string | undefined;
  onChange?: (value: string) => void;
}

export function CustomInput({
  name,
  label,
  required,
  defaultValue,
  type = "text",
  placeholder,
  error,
  isValid,
  onValidate,
  onChange,
}: CustomInputProps) {
  const { t } = useTranslation();
  const [value, setValue] = React.useState(defaultValue || "");
  const [validationError, setValidationError] = React.useState<
    string | undefined
  >();
  const [touched, setTouched] = React.useState(false);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newValue = e.target.value;
    setValue(newValue);
    onChange?.(newValue);

    if (onValidate && touched) {
      const errorMessage = onValidate(newValue);
      setValidationError(errorMessage);
    }
  };

  const handleBlur = () => {
    setTouched(true);
    if (onValidate) {
      const errorMessage = onValidate(value);
      setValidationError(errorMessage);
    }
  };

  const currentError = error || validationError;
  const showError = touched && currentError;
  const inputValid = isValid !== undefined ? isValid : !currentError;

  return (
    <div className="flex flex-col gap-2">
      <label htmlFor={name} className="flex flex-col gap-2">
        <span className="text-[11px] leading-4 tracking-[0.5px] font-[500] text-neutral-400">
          {label}
          {required && <span className="text-danger ml-1">*</span>}
          {!required && (
            <span className="text-neutral-500">
              {" "}
              {t(I18nKey.CUSTOM_INPUT$OPTIONAL_LABEL)}
            </span>
          )}
        </span>
        <input
          id={name}
          name={name}
          required={required}
          value={value}
          onChange={handleChange}
          onBlur={handleBlur}
          type={type}
          placeholder={placeholder}
          aria-invalid={showError ? "true" : "false"}
          aria-describedby={showError ? `${name}-error` : undefined}
          className={cn(
            "bg-surface-secondary text-xs py-[10px] px-3 rounded-lg border apple-transition",
            "focus:outline-none focus:ring-2 focus:ring-primary/40",
            inputValid && !showError
              ? "border-neutral-600 focus:border-primary"
              : "border-neutral-600 focus:border-primary",
            showError &&
              "border-danger focus:border-danger focus:ring-danger/40",
            touched &&
              inputValid &&
              !showError &&
              "border-success focus:border-success focus:ring-success/40",
          )}
        />
      </label>

      {showError && (
        <div
          id={`${name}-error`}
          className="text-xs text-danger flex items-center gap-1"
          role="alert"
          aria-live="polite"
        >
          <span aria-hidden="true">⚠️</span>
          {currentError}
        </div>
      )}

      {touched && inputValid && !showError && (
        <div
          className="text-xs text-success flex items-center gap-1"
          role="status"
          aria-live="polite"
        >
          <span aria-hidden="true">✓</span>
          {t("CUSTOM_INPUT$VALID", "Valid")}
        </div>
      )}
    </div>
  );
}
