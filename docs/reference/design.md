# UI/UX Design System & Style Guide

## 1. Visual Theme & Color Palette
AegisAI employs a modern, dark-mode-first "Cybersecurity Operations" aesthetic featuring deep slate backgrounds, vibrant teal primary accents, and distinct status indicators.

### Color Swatches
* **Background Primary:** `#0b0f19` (Deep Obsidian / Slate 950)
* **Background Secondary:** `#111827` (Dark Charcoal / Slate 900)
* **Card & Surface Fill:** `#1f2937` (Muted Steel / Slate 800)
* **Primary Accent (Brand):** `#06b6d4` (Cyber Cyan) / `#3b82f6` (Tech Blue)
* **Success Status:** `#10b981` (Emerald Green)
* **Warning Status:** `#f59e0b` (Amber)
* **Critical / Threat Alert:** `#ef4444` (Crimson Red)
* **Text Primary:** `#f9fafb` (Off-white / Slate 50)
* **Text Secondary:** `#9ca3af` (Cool Grey / Slate 400)

---

## 2. Typography
* **Primary Font Family:** Inter, system-ui, sans-serif (Clean readability for dashboard data)
* **Monospace Font Family:** JetBrains Mono, Fira Code, monospace (For raw logs, Process IDs, IP addresses, and code snippets)

### Type Scale
* **Header 1 (Page Titles):** `24pt` / Bold
* **Header 2 (Section Titles):** `18pt` / Semi-Bold
* **Header 3 (Card Titles):** `14pt` / Medium
* **Body Text:** `10.5pt` / Regular
* **Captions & Metadata:** `9pt` / Muted

---

## 3. UI Component Principles
* **Card Containers:** Dark background with subtle 1px border (`border-slate-800`), slight rounded corners (`rounded-lg`), and subtle drop shadow.
* **Status Badges:** Pill-shaped badges with soft background tint (e.g., green fill at 10% opacity with solid emerald text).
* **Data Visualization:** Clean Recharts graphs with neon-tinted line strokes and muted grid lines.
