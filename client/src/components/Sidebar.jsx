import React, { useRef, useState } from "react";
import { NavLink } from "react-router-dom";
import {
  motion,
  useMotionValue,
  useSpring,
  useTransform,
  AnimatePresence,
} from "framer-motion";
import {
  LayoutDashboard,
  FileText,
  Crosshair,
  Sliders,
  ShieldCheck,
  Zap,
  X,
} from "lucide-react";

const NAV_ITEMS = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/logs", icon: FileText, label: "Log Analysis" },
  { to: "/threats-intelligence", icon: Crosshair, label: "Threats Intelligence" },
  { to: "/settings", icon: Sliders, label: "Setting" },
];

const SPRING_CONFIG = {
  stiffness: 400,
  damping: 25,
  mass: 0.35,
};

/**
 * Animated Sidebar Nav Item with continuous Gaussian magnification & spring physics.
 * Directly transforms pre-existing sidebar buttons without creating duplicate navigation bars.
 */
function SidebarNavItem({
  to,
  icon: Icon,
  label,
  count,
  alert,
  collapsed,
  mobileOpen,
  mouseY,
  onCloseMobile,
}) {
  const itemRef = useRef(null);
  const [hovered, setHovered] = useState(false);

  // Vertical distance calculation for dock magnification effect
  const distanceFromMouse = useTransform(mouseY, (val) => {
    const el = itemRef.current;
    if (!el || val === Infinity) return 1000;
    const rect = el.getBoundingClientRect();
    return Math.abs(val - (rect.top + rect.height / 2));
  });

  // Gaussian magnification curve (peak scale ~1.3x within 75px radius)
  const magnification = 1.32;
  const distanceRadius = 75;
  const gaussian = (d) =>
    (magnification - 1) * Math.exp(-(d * d) / (2 * distanceRadius * distanceRadius)) + 1;

  const scaleRaw = useTransform(distanceFromMouse, (d) => gaussian(d));
  const scale = useSpring(scaleRaw, SPRING_CONFIG);

  const isCollapsedIconMode = collapsed && !mobileOpen;

  return (
    <div
      ref={itemRef}
      className="relative flex items-center justify-center w-full"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <NavLink
        to={to}
        end={to === "/"}
        onClick={() => onCloseMobile && onCloseMobile()}
        className={({ isActive }) =>
          `relative flex items-center rounded-xl transition-colors duration-150 group select-none ${
            isCollapsedIconMode
              ? "justify-center w-10 h-10 my-0.5"
              : "justify-between w-full px-3 py-2.5 my-0.5 text-xs font-medium"
          } ${
            isActive
              ? "bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 shadow-[0_0_12px_rgba(6,182,212,0.25)] font-medium"
              : "text-slate-400 hover:text-slate-100 hover:bg-white/[0.06] border border-transparent"
          }`
        }
      >
        {({ isActive }) => (
          <>
            {isCollapsedIconMode ? (
              // Collapsed dock mode with Gaussian spring physics
              <motion.div
                style={{ scale }}
                className="flex items-center justify-center relative"
              >
                <Icon
                  size={19}
                  className={`transition-colors duration-150 ${
                    isActive ? "text-cyan-400" : "text-slate-400 group-hover:text-white"
                  }`}
                />

                {/* Subtle active indicator dot */}
                {isActive && (
                  <span className="absolute -bottom-1.5 w-1 h-1 rounded-full bg-cyan-400 shadow-[0_0_6px_#22d3ee]" />
                )}

                {/* Alert badge */}
                {alert && (
                  <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-red-500 animate-pulse border border-black" />
                )}
              </motion.div>
            ) : (
              // Expanded sidebar mode with smooth hover motion
              <>
                <div className="flex items-center gap-3 min-w-0">
                  <motion.div
                    whileHover={{ scale: 1.15, rotate: 2 }}
                    transition={{ type: "spring", stiffness: 400, damping: 20 }}
                  >
                    <Icon
                      size={17}
                      className={`flex-shrink-0 transition-colors duration-150 ${
                        isActive ? "text-cyan-400" : "text-slate-400 group-hover:text-white"
                      }`}
                    />
                  </motion.div>
                  <span className="truncate">{label}</span>
                </div>

                {count !== undefined && (
                  <span
                    className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded ${
                      alert
                        ? "bg-red-500/20 text-red-400 border border-red-500/30"
                        : "bg-slate-800 text-slate-400"
                    }`}
                  >
                    {count}
                  </span>
                )}
              </>
            )}
          </>
        )}
      </NavLink>

      {/* Floating dock-style tooltip when in collapsed mode */}
      <AnimatePresence>
        {isCollapsedIconMode && hovered && (
          <motion.div
            initial={{ opacity: 0, x: -6, scale: 0.94 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: -6, scale: 0.94 }}
            transition={{ duration: 0.12, ease: "easeOut" }}
            className="absolute left-full ml-3.5 z-50 pointer-events-none flex items-center"
          >
            {/* Pointer arrow pointing left */}
            <div className="w-1.5 h-1.5 bg-slate-900 border-l border-b border-slate-700/80 -rotate-45 -mr-1 z-10" />

            <div className="flex items-center gap-2 px-2.5 py-1 rounded-lg bg-slate-900/95 border border-slate-700/80 shadow-2xl backdrop-blur-md whitespace-nowrap">
              <span className="text-xs font-semibold text-white tracking-wide">
                {label}
              </span>
              {alert && count && (
                <span className="bg-red-500/20 text-red-400 border border-red-500/30 text-[9px] px-1.5 py-0.2 rounded font-mono font-bold">
                  {count}
                </span>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default function Sidebar({ collapsed, mobileOpen, onCloseMobile }) {
  const mouseY = useMotionValue(Infinity);

  return (
    <>
      {/* Mobile Backdrop Overlay */}
      {mobileOpen && (
        <div
          onClick={onCloseMobile}
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 md:hidden animate-fade-in"
          aria-hidden="true"
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`
          fixed md:static inset-y-0 left-0 z-50 md:z-20
          flex flex-col bg-navy-950 border-r border-white/[0.06]
          transition-all duration-300 ease-in-out select-none
          ${mobileOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"}
          ${collapsed ? "md:w-16" : "md:w-60"}
          w-64
        `}
      >
        {/* Brand Header */}
        <div className="flex items-center justify-between px-4 h-14 border-b border-white/[0.06]">
          <div className="flex items-center gap-2.5 overflow-hidden">
            <motion.div
              whileHover={{ scale: 1.1, rotate: 5 }}
              transition={{ type: "spring", stiffness: 400, damping: 20 }}
              className="flex-shrink-0 w-7 h-7 rounded-lg bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-sm border border-cyan-400/30 cursor-pointer"
            >
              <ShieldCheck size={16} className="text-white" />
            </motion.div>
            {(!collapsed || mobileOpen) && (
              <div className="overflow-hidden">
                <div className="flex items-center gap-1.5">
                  <span className="text-white font-semibold text-sm tracking-wide">Aegis</span>
                  <span className="text-cyan-400 font-semibold text-sm">AI</span>
                  <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                    EDR
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Close button for mobile */}
          {mobileOpen && (
            <button
              onClick={onCloseMobile}
              className="p-1 rounded-lg text-slate-400 hover:text-white md:hidden"
              aria-label="Close Sidebar"
            >
              <X size={18} />
            </button>
          )}
        </div>

        {/* Navigation List - Pre-existing 4 Core Features with Dock Effect */}
        <nav
          className="flex-1 py-4 px-2 space-y-2 overflow-y-auto overflow-x-visible"
          onMouseMove={(e) => mouseY.set(e.clientY)}
          onMouseLeave={() => mouseY.set(Infinity)}
        >
          {(!collapsed || mobileOpen) && (
            <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-medium px-2.5 mb-2">
              Platform Modules
            </p>
          )}

          {NAV_ITEMS.map((item) => (
            <SidebarNavItem
              key={item.to}
              {...item}
              collapsed={collapsed}
              mobileOpen={mobileOpen}
              mouseY={mouseY}
              onCloseMobile={onCloseMobile}
            />
          ))}
        </nav>

        {/* Sensor Status Footer */}
        <div className="p-3 border-t border-white/[0.06] bg-navy-900/60">
          <motion.div
            whileHover={{ scale: 1.05 }}
            transition={{ type: "spring", stiffness: 400, damping: 20 }}
            className={`flex items-center gap-2.5 cursor-pointer ${
              collapsed && !mobileOpen ? "justify-center" : ""
            }`}
          >
            <div className="relative flex-shrink-0">
              <div className="w-6 h-6 rounded-md bg-emerald-500/10 border border-emerald-500/25 flex items-center justify-center">
                <Zap size={13} className="text-emerald-400" />
              </div>
              <span className="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 bg-emerald-400 rounded-full animate-subtle-pulse" />
            </div>

            {(!collapsed || mobileOpen) && (
              <div className="overflow-hidden min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="text-emerald-400 text-[11px] font-medium truncate">
                    Local Sensor Nominal
                  </span>
                </div>
                <p className="text-slate-400 text-[10px] font-mono truncate">
                  Zero Egress • eBPF
                </p>
              </div>
            )}
          </motion.div>
        </div>
      </aside>
    </>
  );
}
