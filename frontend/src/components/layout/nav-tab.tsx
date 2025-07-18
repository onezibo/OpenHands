import { NavLink } from "react-router";
import { cn } from "#/utils/utils";
import { BetaBadge } from "./beta-badge";
import { LoadingSpinner } from "../shared/loading-spinner";

interface NavTabProps {
  to: string;
  label: string | React.ReactNode;
  icon: React.ReactNode;
  isBeta?: boolean;
  isLoading?: boolean;
  rightContent?: React.ReactNode;
}

export function NavTab({
  to,
  label,
  icon,
  isBeta,
  isLoading,
  rightContent,
}: NavTabProps) {
  return (
    <NavLink
      end
      key={to}
      to={to}
      className={cn(
        "px-2 border-b border-r border-gray-700 glass-apple-light backdrop-blur-lg flex-1",
        "first-of-type:rounded-tl-xl last-of-type:rounded-tr-xl last-of-type:border-r-0",
        "flex items-center gap-2 h-full min-h-[36px] apple-transition",
        "hover:bg-white/10 hover:border-gray-600",
      )}
    >
      {({ isActive }) => (
        <div className="flex items-center justify-between w-full">
          <div className="flex items-center gap-2">
            <div className={cn(isActive && "text-primary")}>{icon}</div>
            <span
              className={cn(
                isActive && "text-primary font-semibold",
                "text-gray-200 font-medium",
              )}
            >
              {label}
            </span>
            {isBeta && <BetaBadge />}
          </div>
          <div className="flex items-center gap-2">
            {rightContent}
            {isLoading && <LoadingSpinner size="small" />}
          </div>
        </div>
      )}
    </NavLink>
  );
}
