import React from "react";

export type TabId = "feed" | "report" | "jury" | "stats";

interface TabItem {
  id: TabId;
  label: string;
}

interface WorkspaceNavProps {
  activeTab: TabId;
  setActiveTab: (tab: TabId) => void;
}

const TABS: TabItem[] = [
  { id: "feed", label: "Home Feed" },
  { id: "report", label: "Secure Report" },
  { id: "jury", label: "Jury Duties" },
  { id: "stats", label: "Capital Stats" },
];

export const WorkspaceNav: React.FC<WorkspaceNavProps> = ({
  activeTab,
  setActiveTab,
}) => {
  return (
    <nav className="w-full bg-[#121826]/80 backdrop-blur-md border-b border-[#1F2937] flex justify-center">
      <div className="flex space-x-1 p-2 max-w-7xl w-full">
        {TABS.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex-1 md:flex-initial px-6 py-3 font-mono text-sm font-semibold transition-all duration-200 select-none border-b-2 rounded-t-md ${
                isActive
                  ? "border-[#00E5FF] text-[#00E5FF] bg-[#1a2336]/60"
                  : "border-transparent text-gray-400 hover:text-gray-200 hover:bg-[#1a2336]/20"
              }`}
            >
              {tab.label}
            </button>
          );
        })}
      </div>
    </nav>
  );
};
