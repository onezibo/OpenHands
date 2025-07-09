import clsx from "clsx";
import React from "react";
import { NavTab } from "./nav-tab";

interface ContainerProps {
  label?: React.ReactNode;
  labels?: {
    label: string | React.ReactNode;
    to: string;
    icon?: React.ReactNode;
    isBeta?: boolean;
    isLoading?: boolean;
    rightContent?: React.ReactNode;
  }[];
  children: React.ReactNode;
  className?: React.HTMLAttributes<HTMLDivElement>["className"];
}

export function Container({
  label,
  labels,
  children,
  className,
}: ContainerProps) {
  return (
    <div
      className={clsx(
        "glass-apple flex flex-col h-full apple-transition",
        "rounded-xl overflow-hidden backdrop-blur-xl",
        className,
      )}
    >
      {labels && (
        <div className="flex text-xs h-[36px] overflow-x-auto scrollbar-hide">
          {labels.map(
            ({ label: l, to, icon, isBeta, isLoading, rightContent }) => (
              <NavTab
                key={to}
                to={to}
                label={l}
                icon={icon}
                isBeta={isBeta}
                isLoading={isLoading}
                rightContent={rightContent}
              />
            ),
          )}
        </div>
      )}
      {!labels && label && (
        <div className="px-2 h-[36px] border-b border-glass-dark text-xs flex items-center text-neutral-200 font-medium">
          {label}
        </div>
      )}
      <div className="overflow-hidden flex-grow rounded-b-xl">
        <div className="h-full w-full">{children}</div>
      </div>
    </div>
  );
}
