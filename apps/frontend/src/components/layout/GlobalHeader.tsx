import React, { useEffect, useState } from "react";
import { clockOffsetMs } from "../../api/apiClient";

export const GlobalHeader: React.FC = () => {
  const [offset, setOffset] = useState(clockOffsetMs);

  useEffect(() => {
    const timer = setInterval(() => {
      setOffset(clockOffsetMs);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <header className="h-16 w-full bg-[#121826] border-b border-[#1F2937] px-6 flex items-center justify-between select-none">
      {/* Branding */}
      <div className="flex items-center space-x-3">
        <span className="text-white font-mono font-extrabold tracking-wider text-lg">
          BRONE
        </span>
      </div>

      {/* Telemetry Group */}
      <div className="flex items-center space-x-6">
        {/* Network sync telemetry */}
        <div className="flex items-center space-x-2 bg-[#1b2336] px-3 py-1.5 rounded-md border border-[#2b354a]">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00F5A0] opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-[#00F5A0]"></span>
          </span>

        </div>

        {/* Clock Skew Indicator */}
        <div className="flex items-center bg-[#1b2336] px-3 py-1.5 rounded-md border border-[#2b354a]">
          <span className="text-xs text-gray-400 font-mono">
            CLOCK SKEW:{" "}
            <span className="text-[#00E5FF] font-semibold">
              {offset >= 0 ? "+" : ""}
              {offset}ms
            </span>
          </span>
        </div>
      </div>
    </header>
  );
};