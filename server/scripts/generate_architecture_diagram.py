import matplotlib.pyplot as plt
import matplotlib.patches as patches

def generate_architecture_diagram(output_path):
    fig, ax = plt.subplots(figsize=(12, 7.5), dpi=300)
    ax.set_facecolor("#0B0F19")
    fig.patch.set_facecolor("#0B0F19")

    # Layer Boxes
    layers = [
        {"title": "1. Telemetry & Ingestion Layer", "color": "#1E293B", "border": "#38BDF8", "box": [0.05, 0.72, 0.9, 0.22]},
        {"title": "2. Intelligence & Detection Core (Edge AI & Deception)", "color": "#1E293B", "border": "#818CF8", "box": [0.05, 0.38, 0.9, 0.28]},
        {"title": "3. Autonomous Response & SOC Visualization Layer", "color": "#1E293B", "border": "#34D399", "box": [0.05, 0.05, 0.9, 0.27]}
    ]

    for l in layers:
        rect = patches.FancyBboxPatch(
            (l["box"][0], l["box"][1]), l["box"][2], l["box"][3],
            boxstyle="round,pad=0.015,rounding_size=0.02",
            linewidth=1.5, edgecolor=l["border"], facecolor=l["color"], alpha=0.9
        )
        ax.add_patch(rect)
        ax.text(l["box"][0] + 0.02, l["box"][1] + l["box"][3] - 0.04, l["title"],
                fontsize=11, fontweight="bold", color=l["border"], va="top")

    # Sub-components
    components = [
        # Layer 1
        {"name": "Kernel ETW / eBPF\nProcess Monitor", "x": 0.08, "y": 0.74, "w": 0.25, "h": 0.12, "color": "#0F172A", "text_color": "#E2E8F0"},
        {"name": "Async Network Sniffer\n(Scapy / PCAP Stream)", "x": 0.375, "y": 0.74, "w": 0.25, "h": 0.12, "color": "#0F172A", "text_color": "#E2E8F0"},
        {"name": "Live Event Streamer\n(FastAPI WebSockets 1s)", "x": 0.67, "y": 0.74, "w": 0.25, "h": 0.12, "color": "#0F172A", "text_color": "#E2E8F0"},

        # Layer 2
        {"name": "ONNX INT8 Edge Engine\n(Quantized Tree Inference <5ms)", "x": 0.08, "y": 0.45, "w": 0.26, "h": 0.14, "color": "#1E1B4B", "text_color": "#A5B4FC"},
        {"name": "Explainable AI (XAI)\nTreeSHAP Attribution Matrix", "x": 0.37, "y": 0.45, "w": 0.26, "h": 0.14, "color": "#1E1B4B", "text_color": "#A5B4FC"},
        {"name": "Active Honeyport Traps\nDeception & Recon Redirection", "x": 0.66, "y": 0.45, "w": 0.26, "h": 0.14, "color": "#1E1B4B", "text_color": "#A5B4FC"},

        # Layer 3
        {"name": "Autonomous Remediation\n(PID Kill, Netsh Firewall, Quarantine)", "x": 0.08, "y": 0.08, "w": 0.26, "h": 0.16, "color": "#064E3B", "text_color": "#6EE7B7"},
        {"name": "AI Agent Reasoning Engine\n(Contextual Investigation & Steps)", "x": 0.37, "y": 0.08, "w": 0.26, "h": 0.16, "color": "#064E3B", "text_color": "#6EE7B7"},
        {"name": "Cyber SOC Dashboard\n(React 19 + Tailwind + Lucide)", "x": 0.66, "y": 0.08, "w": 0.26, "h": 0.16, "color": "#064E3B", "text_color": "#6EE7B7"}
    ]

    for c in components:
        box = patches.FancyBboxPatch(
            (c["x"], c["y"]), c["w"], c["h"],
            boxstyle="round,pad=0.01,rounding_size=0.015",
            linewidth=1.2, edgecolor="#475569", facecolor=c["color"]
        )
        ax.add_patch(box)
        ax.text(c["x"] + c["w"]/2, c["y"] + c["h"]/2, c["name"],
                fontsize=9.5, fontweight="semibold", color=c["text_color"], ha="center", va="center")

    # Arrows
    arrow_props = dict(arrowstyle="->,head_width=0.4,head_length=0.6", lw=2, color="#38BDF8")
    
    # Layer 1 to Layer 2 arrows
    ax.annotate("", xy=(0.20, 0.60), xytext=(0.20, 0.73), arrowprops=arrow_props)
    ax.annotate("", xy=(0.50, 0.60), xytext=(0.50, 0.73), arrowprops=arrow_props)
    ax.annotate("", xy=(0.80, 0.60), xytext=(0.80, 0.73), arrowprops=arrow_props)

    # Layer 2 inter-flow
    ax.annotate("", xy=(0.36, 0.52), xytext=(0.345, 0.52), arrowprops=dict(arrowstyle="->", lw=1.5, color="#818CF8"))
    ax.annotate("", xy=(0.65, 0.52), xytext=(0.635, 0.52), arrowprops=dict(arrowstyle="<->", lw=1.5, color="#818CF8"))

    # Layer 2 to Layer 3 arrows
    arrow_props_down = dict(arrowstyle="->,head_width=0.4,head_length=0.6", lw=2, color="#34D399")
    ax.annotate("", xy=(0.21, 0.25), xytext=(0.21, 0.44), arrowprops=arrow_props_down)
    ax.annotate("", xy=(0.50, 0.25), xytext=(0.50, 0.44), arrowprops=arrow_props_down)
    ax.annotate("", xy=(0.79, 0.25), xytext=(0.79, 0.44), arrowprops=arrow_props_down)

    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close()
    print(f"Architecture diagram successfully saved to {output_path}")

if __name__ == "__main__":
    generate_architecture_diagram("d:/Desktop/aegis-ai/docs/media/screenshots/00_aegis_architecture_diagram.png")
