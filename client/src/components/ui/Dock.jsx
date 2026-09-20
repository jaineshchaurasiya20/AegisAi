import * as React from "react";
import {
  motion,
  useMotionValue,
  useSpring,
  useTransform,
  AnimatePresence,
} from "framer-motion";
import { cn } from "@/lib/utils";

const DEFAULT_SPRING = {
  stiffness: 400,
  damping: 25,
  mass: 0.4,
};

function DockSeparator() {
  return (
    <div className="mx-1.5 flex items-center self-stretch">
      <div className="h-6 w-px bg-white/10" />
    </div>
  );
}

function DockIcon({
  item,
  mouseX,
  magnification,
  distance,
  iconSize,
  borderRadius,
  alwaysShowLabels,
  springOptions,
  onHover,
  iconRef: externalIconRef,
}) {
  const wrapperRef = React.useRef(null);

  const distanceFromMouse = useTransform(mouseX, (val) => {
    const el = wrapperRef.current;
    if (!el) return distance * 100;
    const rect = el.getBoundingClientRect();
    return Math.abs(val - (rect.left + rect.width / 2));
  });

  const gaussian = (d) =>
    (magnification - 1) * Math.exp(-(d * d) / (2 * distance * distance)) + 1;

  const widthRaw = useTransform(
    distanceFromMouse,
    (d) => iconSize * gaussian(d),
  );
  const heightRaw = useTransform(
    distanceFromMouse,
    (d) => iconSize * gaussian(d),
  );

  const width = useSpring(widthRaw, springOptions);
  const height = useSpring(heightRaw, springOptions);

  const Tag = item.href ? "a" : "button";

  return (
    <motion.div
      ref={wrapperRef}
      className="relative flex items-end justify-center"
      style={{ width, height: iconSize }}
    >
      <motion.div
        ref={externalIconRef}
        style={{ width, height, bottom: 0 }}
        className="absolute flex flex-col items-center justify-center"
      >
        <Tag
          href={item.href}
          onClick={item.onClick}
          onMouseEnter={() => onHover(externalIconRef)}
          onMouseLeave={() => onHover(null)}
          aria-label={item.label}
          style={{ borderRadius }}
          className={cn(
            "relative flex h-full w-full items-center justify-center rounded-xl",
            "transition-colors duration-150 select-none",
            item.active
              ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-[0_0_12px_rgba(6,182,212,0.3)]"
              : "text-slate-400 hover:bg-white/[0.08] hover:text-white border border-transparent",
            "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400/40",
            "[&_svg]:size-[52%]",
          )}
        >
          {item.icon}

          {/* Active dot indicator */}
          {item.active && (
            <span className="absolute -bottom-1 w-1 h-1 rounded-full bg-cyan-400 shadow-[0_0_6px_#22d3ee]" />
          )}

          {/* Alert badge if specified */}
          {item.badge && (
            <span className="absolute top-0 right-0 w-2 h-2 rounded-full bg-red-500 animate-pulse border border-black" />
          )}
        </Tag>
      </motion.div>

      {alwaysShowLabels && (
        <span className="mt-1 text-[10px] font-medium tracking-tight text-slate-400 whitespace-nowrap pointer-events-none select-none leading-none">
          {item.label}
        </span>
      )}
    </motion.div>
  );
}

export function Dock({
  items,
  magnification = 1.7,
  distance = 120,
  iconSize = 40,
  gap = 6,
  borderRadius = 16,
  alwaysShowLabels = false,
  springOptions = DEFAULT_SPRING,
  className,
}) {
  const mouseX = useMotionValue(Infinity);
  const dockRef = React.useRef(null);

  const iconRefs = React.useRef(
    items.map(() => React.createRef()),
  );

  // Keep refs array in sync with items length
  if (iconRefs.current.length !== items.length) {
    iconRefs.current = items.map((_, i) => iconRefs.current[i] || React.createRef());
  }

  const [hoveredIndex, setHoveredIndex] = React.useState(null);
  const [tooltipX, setTooltipX] = React.useState(0);
  const [tooltipBottomOffset, setTooltipBottomOffset] = React.useState(0);

  React.useEffect(() => {
    if (hoveredIndex === null) return;

    let raf;
    const update = () => {
      const iconEl = iconRefs.current[hoveredIndex]?.current;
      const dockEl = dockRef.current;
      if (iconEl && dockEl) {
        const iconRect = iconEl.getBoundingClientRect();
        const dockRect = dockEl.getBoundingClientRect();
        setTooltipX(iconRect.left - dockRect.left + iconRect.width / 2);
        setTooltipBottomOffset(dockRect.bottom - iconRect.top);
      }
      raf = requestAnimationFrame(update);
    };
    raf = requestAnimationFrame(update);
    return () => cancelAnimationFrame(raf);
  }, [hoveredIndex]);

  const handleHover = React.useCallback(
    (ref) => {
      if (ref === null) {
        setHoveredIndex(null);
        return;
      }
      const idx = iconRefs.current.findIndex((r) => r === ref);
      setHoveredIndex(idx >= 0 ? idx : null);
    },
    [],
  );

  return (
    <motion.div
      ref={dockRef}
      className={cn(
        "relative flex items-end overflow-visible",
        "border border-white/[0.1] bg-slate-950/80 px-3 py-2",
        "shadow-[0_8px_32px_rgba(0,0,0,0.6),0_0_0_1px_rgba(255,255,255,0.05)]",
        "hover:shadow-[0_12px_40px_rgba(0,0,0,0.7),0_0_16px_rgba(6,182,212,0.15)]",
        "transition-shadow duration-200 backdrop-blur-xl",
        className,
      )}
      style={{ gap, borderRadius }}
      onMouseMove={(e) => mouseX.set(e.clientX)}
      onMouseLeave={() => mouseX.set(Infinity)}
    >
      {items.map((item, i) => (
        <React.Fragment key={i}>
          <DockIcon
            item={item}
            mouseX={mouseX}
            magnification={magnification}
            distance={distance}
            iconSize={iconSize}
            borderRadius={borderRadius}
            alwaysShowLabels={alwaysShowLabels}
            springOptions={springOptions}
            onHover={handleHover}
            iconRef={iconRefs.current[i]}
          />
          {item.separator && <DockSeparator />}
        </React.Fragment>
      ))}

      {!alwaysShowLabels && (
        <AnimatePresence>
          {hoveredIndex !== null && items[hoveredIndex] && (
            <motion.div
              key="dock-tooltip"
              layoutId="dock-tooltip"
              className="pointer-events-none absolute flex flex-col items-center z-50"
              style={{
                left: tooltipX,
                bottom: tooltipBottomOffset + 8,
                x: "-50%",
              }}
              initial={{ opacity: 0, y: 6, scale: 0.94 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 6, scale: 0.94 }}
              transition={{ duration: 0.13, ease: "easeOut" }}
            >
              <span className="rounded-lg border border-slate-700/80 bg-slate-900/95 px-2.5 py-1 text-xs font-semibold text-white shadow-xl whitespace-nowrap backdrop-blur-md">
                {items[hoveredIndex].label}
              </span>
              <svg
                width="8"
                height="4"
                viewBox="0 0 8 4"
                className="-mt-px text-slate-900/95"
                aria-hidden
              >
                <path d="M0 0L4 4L8 0" fill="currentColor" />
              </svg>
            </motion.div>
          )}
        </AnimatePresence>
      )}
    </motion.div>
  );
}

export default Dock;
