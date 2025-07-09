import { cn } from "#/utils/utils";

interface BrandButtonProps {
  testId?: string;
  name?: string;
  variant: "primary" | "secondary" | "danger";
  type: React.ButtonHTMLAttributes<HTMLButtonElement>["type"];
  isDisabled?: boolean;
  className?: string;
  onClick?: () => void;
  startContent?: React.ReactNode;
}

export function BrandButton({
  testId,
  name,
  children,
  variant,
  type,
  isDisabled,
  className,
  onClick,
  startContent,
}: React.PropsWithChildren<BrandButtonProps>) {
  return (
    <button
      name={name}
      data-testid={testId}
      disabled={isDisabled}
      // The type is alreadt passed as a prop to the button component
      // eslint-disable-next-line react/button-has-type
      type={type}
      onClick={onClick}
      className={cn(
        "w-fit p-2 text-sm rounded-lg cursor-pointer apple-transition",
        "focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-background-primary",
        "disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:opacity-50",
        variant === "primary" && [
          "bg-primary text-white font-medium",
          "hover:bg-primary/90 hover:shadow-glow",
          "focus:ring-primary/40",
          "active:bg-primary/80 active:scale-95",
        ],
        variant === "secondary" && [
          "border border-primary text-primary bg-transparent",
          "hover:bg-primary/10 hover:border-primary/80",
          "focus:ring-primary/40",
          "active:bg-primary/20 active:scale-95",
        ],
        variant === "danger" && [
          "bg-danger text-white font-medium",
          "hover:bg-danger/90 hover:shadow-lg",
          "focus:ring-danger/40",
          "active:bg-danger/80 active:scale-95",
        ],
        startContent && "flex items-center justify-center gap-2",
        className,
      )}
    >
      {startContent}
      {children}
    </button>
  );
}
