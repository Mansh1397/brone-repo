import React from "react";

interface DashboardGridProps {
  children: React.ReactNode;
}

export const DashboardGrid: React.FC<DashboardGridProps> = ({ children }) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 w-full max-w-7xl mx-auto p-4 md:p-6">
      {children}
    </div>
  );
};
