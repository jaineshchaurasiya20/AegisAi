"""
Format AegisAI Synopsis Document according to strict academic submission rules:
- Page Size: A4 (210mm x 297mm)
- Margins: Top 32mm, Bottom 27mm, Left 37mm, Right 22mm
- Typography: Times New Roman throughout
- Headings: Font Size 14, Bold
- Subheadings: Font Size 12, Bold & Italic
- Body Content: Font Size 12, Justified Alignment, Single Line Spacing (1.0)
- Page Numbering:
  - Section 1 (Cover + TOC): Roman numerals (Cover unnumbered, TOC page 'ii')
  - Section 2 (Chapters 1-7): Arabic numerals at footer centered, starting from Page 1 on Chapter 1
- Table of Contents updated with final aligned page numbers.
"""
import os
import shutil
# pyrefly: ignore [missing-import]
import docx
# pyrefly: ignore [missing-import]
from docx.shared import Pt, Inches, Mm, RGBColor
# pyrefly: ignore [missing-import]
from docx.enum.text import WD_ALIGN_PARAGRAPH
# pyrefly: ignore [missing-import]
from docx.enum.section import WD_SECTION
# pyrefly: ignore [missing-import]
from docx.oxml import parse_xml, OxmlElement
# pyrefly: ignore [missing-import]
from docx.oxml.ns import nsdecls, qn

SCREENSHOTS_DIR = r"d:\Desktop\aegis-ai\docs\media\screenshots"

def set_run_font(run, font_name="Times New Roman", size_pt=12, bold=False, italic=False, color_rgb=(0, 0, 0)):
    run.font.name = font_name
    if size_pt:
        run.font.size = Pt(size_pt)
    run.bold = bold
    run.italic = italic
    if color_rgb:
        run.font.color.rgb = RGBColor(*color_rgb)
    else:
        run.font.color.rgb = RGBColor(0, 0, 0)

def add_heading_1(doc, text, page_break_before=True):
    p = doc.add_paragraph()
    p.style = 'Heading 1'
    p.paragraph_format.page_break_before = page_break_before
    p.paragraph_format.space_before = Pt(12)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.line_spacing = 1.0
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    run = p.add_run(text)
    set_run_font(run, font_name="Times New Roman", size_pt=14, bold=True, color_rgb=(0, 0, 0))
    return p

def add_normal_paragraph(doc, text, bold_italic_prefix=None, italic=False):
    p = doc.add_paragraph()
    p.style = 'Normal'
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.line_spacing = 1.0
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    
    if bold_italic_prefix:
        r_prefix = p.add_run(bold_italic_prefix)
        set_run_font(r_prefix, font_name="Times New Roman", size_pt=12, bold=True, italic=True, color_rgb=(0, 0, 0))
        
    run = p.add_run(text)
    set_run_font(run, font_name="Times New Roman", size_pt=12, bold=False, italic=italic, color_rgb=(0, 0, 0))
    return p

def add_list_item(doc, bold_italic_label, text):
    p = doc.add_paragraph()
    p.style = 'List Paragraph'
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.line_spacing = 1.0
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    
    r_bullet = p.add_run("\u2022  ")
    set_run_font(r_bullet, font_name="Times New Roman", size_pt=12, bold=True, color_rgb=(0, 0, 0))
    
    if bold_italic_label:
        r_label = p.add_run(bold_italic_label + ": ")
        set_run_font(r_label, font_name="Times New Roman", size_pt=12, bold=True, italic=True, color_rgb=(0, 0, 0))
        
    run = p.add_run(text)
    set_run_font(run, font_name="Times New Roman", size_pt=12, bold=False, color_rgb=(0, 0, 0))
    return p

def add_figure_image(doc, image_filename, caption_text, width_inches=5.4):
    image_path = os.path.join(SCREENSHOTS_DIR, image_filename)
    if not os.path.exists(image_path):
        print(f"[!] Warning: Image not found: {image_path}")
        return None
    
    # Image paragraph
    p_img = doc.add_paragraph()
    p_img.paragraph_format.space_before = Pt(6)
    p_img.paragraph_format.space_after = Pt(4)
    p_img.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_img = p_img.add_run()
    run_img.add_picture(image_path, width=Inches(width_inches))
    
    # Caption paragraph
    p_cap = doc.add_paragraph()
    p_cap.paragraph_format.space_before = Pt(2)
    p_cap.paragraph_format.space_after = Pt(8)
    p_cap.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_cap = p_cap.add_run(caption_text)
    set_run_font(run_cap, font_name="Times New Roman", size_pt=10.5, bold=False, italic=True, color_rgb=(40, 40, 40))
    return p_img

def add_page_number_to_section(section, fmt="decimal", start=1):
    """
    Configures page numbering for a given section using OpenXML.
    """
    sectPr = section._sectPr
    
    # Remove existing pgNumType if any
    for child in list(sectPr):
        if child.tag.endswith('pgNumType'):
            sectPr.remove(child)
            
    # Add new pgNumType
    pgNumType = parse_xml(f'<w:pgNumType {nsdecls("w")} w:fmt="{fmt}" w:start="{start}"/>')
    sectPr.append(pgNumType)
    
    # Setup footer
    footer = section.footer
    footer.is_linked_to_previous = False
    
    # Clean footer paragraphs
    for p in list(footer.paragraphs):
        p_elem = p._element
        p_elem.getparent().remove(p_elem)
        
    p_foot = footer.add_paragraph()
    p_foot.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_foot.paragraph_format.space_before = Pt(4)
    p_foot.paragraph_format.space_after = Pt(0)
    
    # Add page number field XML
    run = p_foot.add_run()
    set_run_font(run, font_name="Times New Roman", size_pt=11, color_rgb=(0, 0, 0))
    fldSimple = parse_xml(r'<w:fldSimple %s w:instr="PAGE"/>' % nsdecls('w'))
    run._r.append(fldSimple)

def apply_page_setup(section):
    """
    Applies A4 size and requested margins:
    Top: 32mm, Bottom: 27mm, Left: 37mm, Right: 22mm
    """
    section.page_width = Mm(210)
    section.page_height = Mm(297)
    section.top_margin = Mm(32)
    section.bottom_margin = Mm(27)
    section.left_margin = Mm(37)
    section.right_margin = Mm(22)

def update_table_of_contents(doc):
    """
    Updates the Table of Contents in Section 1 with exact page numbers starting from 1 on Chapter 1.
    """
    toc_data = [
        ("1.   Problem Statement", "1"),
        ("2.   Purpose", "2"),
        ("3.   Objective and Scope of the Project", "3"),
        ("4.   Feasibility Study", "4"),
        ("5.   Methodology", "5"),
        ("6.   Requirement Analysis", "8"),
        ("7.   Industry Impact", "10"),
    ]
    
    if len(doc.paragraphs) > 20:
        doc.paragraphs[19].text = "TABLE OF CONTENT"
        if doc.paragraphs[19].runs:
            set_run_font(doc.paragraphs[19].runs[0], font_name="Times New Roman", size_pt=14, bold=True, color_rgb=(0, 0, 0))
            
        doc.paragraphs[20].text = "Chapters\t\t\t\t\t\t\t\tPage No"
        if doc.paragraphs[20].runs:
            set_run_font(doc.paragraphs[20].runs[0], font_name="Times New Roman", size_pt=12, bold=True, italic=True, color_rgb=(0, 0, 0))
            
        for i, (chap, page) in enumerate(toc_data):
            p_idx = 21 + i
            if p_idx < len(doc.paragraphs):
                p = doc.paragraphs[p_idx]
                p.text = f"{chap}\t{page}"
                if p.runs:
                    set_run_font(p.runs[0], font_name="Times New Roman", size_pt=12, color_rgb=(0, 0, 0))

def format_aegis_synopsis(input_docx_path, output_docx_path):
    print(f"[*] Processing document: {input_docx_path}")
    doc = docx.Document(input_docx_path)
    
    # Section 1 Setup (Cover Page + TOC)
    sec1 = doc.sections[0]
    apply_page_setup(sec1)
    sec1.different_first_page_header_footer = True
    add_page_number_to_section(sec1, fmt="lowerRoman", start=1)
    
    # Ensure Cover Page runs have Times New Roman
    for i in range(min(19, len(doc.paragraphs))):
        p = doc.paragraphs[i]
        for r in p.runs:
            s_pt = r.font.size.pt if r.font.size else 12
            is_b = r.bold
            set_run_font(r, font_name="Times New Roman", size_pt=s_pt, bold=is_b, color_rgb=(0, 0, 0))
            
    # Set Project Title on Cover Page (Paragraph 1)
    if len(doc.paragraphs) > 1:
        doc.paragraphs[1].text = "AegisAI"
        if doc.paragraphs[1].runs:
            set_run_font(doc.paragraphs[1].runs[0], font_name="Times New Roman", size_pt=24, bold=True, color_rgb=(0, 0, 0))

    # Update TOC entries
    update_table_of_contents(doc)

    # Delete existing paragraphs from index 29 onwards
    total_p = len(doc.paragraphs)
    for _ in range(total_p - 29):
        p_element = doc.paragraphs[29]._element
        p_element.getparent().remove(p_element)
        
    # --- Create Section 2 for Chapters 1-7 ---
    sec2 = doc.add_section(WD_SECTION.NEW_PAGE)
    apply_page_setup(sec2)
    sec2.different_first_page_header_footer = False
    add_page_number_to_section(sec2, fmt="decimal", start=1)
    
    # --- CHAPTER 1: PROBLEM STATEMENT ---
    add_heading_1(doc, "1.  Problem Statement", page_break_before=False)
    add_normal_paragraph(
        doc,
        "Modern enterprise infrastructures and edge networks face an escalating surge in advanced persistent threats (APTs), polymorphic malware, volumetric distributed denial-of-service (DDoS) floods, credential brute-forcing, lateral movement probes, and stealthy command-and-control (C2) beaconing loops. Traditional intrusion detection systems (IDS) and Security Information and Event Management (SIEM) architectures rely heavily on centralized cloud log aggregation, introducing an ingestion latency gap of 15 to 30+ seconds. In high-speed cyberattack scenarios, an adversary can execute unauthorized process injections, pivot across internal subnets, and initiate data exfiltration within milliseconds—long before cloud alerts reach human analysts."
    )
    add_normal_paragraph(
        doc,
        "The core technical challenge lies in the triad of cloud dwell time, black-box machine learning models, and passive alert mechanisms. First, centralized telemetry processing creates bandwidth bottlenecks and vulnerability during network partitions. Second, contemporary machine learning classifiers often function as opaque black-boxes, providing raw probability scores without explaining which anomalous features contributed to the classification, thereby inducing alert fatigue and analyst skepticism. Third, conventional security platforms remain purely reactive—flagging suspicious events without providing verified, self-healing host isolation or process containment at the OS kernel level."
    )
    add_normal_paragraph(
        doc,
        "A practical attack vector underscores this urgency: an obfuscated PowerShell execution launching reflective DLL memory injection with anomalous Shannon entropy might go unnoticed by signature databases while actively opening unauthorized outbound sockets. Without local edge scoring, transparent feature attribution, and autonomous containment, critical endpoints remain defenseless during the initial attack window."
    )
    add_normal_paragraph(
        doc,
        "AegisAI is engineered to bridge these critical operational gaps. It is proposed as an edge-native, sub-second cyber threat detection and autonomous self-healing containment platform. Deploying quantized ONNX machine learning runtimes directly at the host edge, AegisAI couples real-time telemetry inference with game-theoretic Explainable AI (TreeSHAP feature attribution), active deception honeypots for zero-day diversion, and verified OS kernel containment actions."
    )
    add_normal_paragraph(
        doc,
        "To engineer, train, and deploy an edge-native cyber defense engine that continuously analyzes host and network telemetry in real time, delivers sub-50ms threat classification using quantized machine learning, provides transparent TreeSHAP feature attributions, actively traps unclassified zero-day anomalies in synthetic honeypot decoys, and executes kernel-verified containment actions—preserving transparency, security auditability, and human-in-the-loop governance.",
        bold_italic_prefix="Problem Definition: "
    )
    
    # --- CHAPTER 2: PURPOSE ---
    add_heading_1(doc, "2.  Purpose", page_break_before=True)
    add_normal_paragraph(
        doc,
        "The primary purpose of AegisAI is to furnish enterprise security operations centers (SOC) and critical edge computing environments with an intelligent, self-healing defense shield. Operating as an autonomous endpoint detection and response (EDR/XDR) layer, AegisAI combines real-time edge intelligence with actionable explainability, bridging the gap between raw telemetry ingestion and immediate threat neutralization."
    )
    add_normal_paragraph(
        doc,
        "Rather than forcing analysts to manually triage thousands of ambiguous alerts, AegisAI evaluates streaming network flows and host process telemetry against quantized ONNX models with sub-50ms inference latency. When anomalous activity is detected, the engine calculates the exact mathematical risk contribution of each behavioral feature, automatically categorizes the threat severity, and either alerts the SOC analyst or triggers self-healing containment based on the operational policy."
    )
    add_normal_paragraph(
        doc,
        "Artificial intelligence is utilized systematically across multiple defensive tiers: quantized tree ensembles (XGBoost/Random Forest) classify complex multi-dimensional network anomalies; TreeSHAP engines compute signed feature impact scores to explain the risk factors; synthetic honeypot emulators actively deceive and trap zero-day exploits; and autonomous Agentic AI engines stream turn-by-turn incident response reasoning and synthesize tailored remediation patches."
    )
    
    # Add Figure: Live SOC Telemetry Dashboard
    add_figure_image(
        doc,
        "01_dashboard_live_telemetry.png",
        "Figure 1: AegisAI Real-Time SOC Telemetry Dashboard & Streaming Threat Ingestion (1.0s WebSockets)",
        width_inches=5.4
    )
    
    add_normal_paragraph(
        doc,
        "Crucially, AegisAI maintains a dual-mode operational architecture: in Manual Approval Mode, the engine proposes detailed evidence-backed remediations requiring authorized analyst confirmation; in Autonomous Self-Healing Mode, the engine immediately terminates malicious PIDs via OS kernel hooks, applies dynamic firewall host isolation rules, and isolates binaries into cryptographic quarantine environments."
    )
    add_normal_paragraph(
        doc,
        "Beyond individual features, AegisAI demonstrates a unified integration of modern computer science disciplines—edge machine learning, asynchronous high-concurrency backend engineering, Explainable AI (XAI), kernel-level OS process management, active cyber deception, real-time WebSocket communication, and responsive cybersecurity visualization."
    )

    # --- CHAPTER 3: OBJECTIVE AND SCOPE OF THE PROJECT ---
    add_heading_1(doc, "3.  Objective and Scope of the Project", page_break_before=True)
    add_normal_paragraph(doc, "", bold_italic_prefix="Objective:")
    add_list_item(doc, "Sub-50ms Edge Inference", "Deploy quantized ONNX machine learning models trained on the benchmark CICIDS2017 dataset to classify network flows and telemetry in real time directly on edge nodes.")
    add_list_item(doc, "Explainable AI (XAI) Attribution", "Implement game-theoretic SHAP/LIME attribution modules that decompose risk scores into intuitive Risk Multipliers and Safety Indicators with human-readable cybersecurity context.")
    add_list_item(doc, "Active Deception & Honeypot Trapping", "Deploy dynamic synthetic socket emulators (FTP on port 2121, SSH on port 2222, Registry listeners) to divert, entrap, and neutralize unclassified zero-day anomaly probes.")
    add_list_item(doc, "Dual-Mode Containment Engine", "Provide configurable Manual SOC Analyst Approval and Autonomous Self-Healing containment postures with real-time policy threshold adjustments.")
    add_list_item(doc, "OS Kernel Containment Verification", "Execute and verify process terminations (psutil/taskkill), dynamic network host isolation (netsh advfirewall), and file sandboxing (server/quarantine/<hash>.bin).")
    add_list_item(doc, "Autonomous AI Agent Remediation", "Stream turn-by-turn LLM reasoning logs via Server-Sent Events (SSE) to generate root-cause analyses and downloadable firewall containment patches.")
    add_list_item(doc, "High-Frequency WebSocket Streaming", "Broadcast live system CPU%, RAM%, network throughput, and threat alerts every 1.0 second to connected SOC dashboard clients.")
    add_list_item(doc, "Immutable Audit Trail", "Log all detection events, XAI attributions, user confirmations, and kernel containment outcomes with cryptographic timestamps.")
    
    add_normal_paragraph(doc, "", bold_italic_prefix="Scope:")
    add_normal_paragraph(
        doc,
        "The project scope encompasses a complete, production-ready full-stack software system comprising an asynchronous FastAPI backend, a high-performance React 18/Vite/Tailwind CSS web dashboard, an embedded ONNX Runtime inference engine, SQLite/aiosqlite audit database storage, synthetic honeypot socket listeners, and a Windows taskbar daemon agent."
    )
    add_normal_paragraph(
        doc,
        "For empirical validation, the system is tested against curated attack scenarios from the Canadian Institute for Cybersecurity CICIDS2017 dataset (LOIC HTTP Floods, SYN Stealth Scans, Cobalt Strike C2 Beaconing, SQL Injection, SSH Brute Force, and Zero-Day Memory Injection) streamed via an automated live attack replay engine."
    )

    # --- CHAPTER 4: FEASIBILITY STUDY ---
    add_heading_1(doc, "4.  Feasibility Study", page_break_before=True)
    add_normal_paragraph(doc, "", bold_italic_prefix="Technical Feasibility:")
    add_normal_paragraph(
        doc,
        "The project is technically feasible through the integration of proven, high-performance open-source technologies. Python 3.10+ provides the core data science and systems engineering foundation; FastAPI and Uvicorn deliver high-throughput asynchronous request handling and WebSocket broadcasting; ONNX Runtime enables hardware-optimized edge inference without cloud dependency; Scikit-Learn and XGBoost provide robust tabular anomaly modeling; and SHAP delivers mathematically rigorous feature attributions. Host monitoring and containment utilize native OS facilities (psutil, subprocess, netsh advfirewall, and iptables). The entire architecture operates with microsecond-level internal latency, proving fully capable of processing sustained multi-thousand event-per-second streams on standard hardware."
    )
    add_normal_paragraph(doc, "", bold_italic_prefix="Economic Feasibility:")
    add_normal_paragraph(
        doc,
        "AegisAI is economically feasible because its core architecture is built entirely upon open-source software libraries, eliminating costly proprietary SIEM per-gigabyte ingestion fees and expensive recurring cloud inference licenses. Edge-native quantization allows the entire engine to run efficiently on commodity desktop and server hardware, making it exceptionally cost-effective for academic demonstration, small-to-medium enterprises, and critical distributed infrastructure."
    )
    add_normal_paragraph(doc, "", bold_italic_prefix="Operational Feasibility:")
    add_normal_paragraph(
        doc,
        "In operational practice, the system offers zero disruption to legitimate host workloads. In Manual Mode, security analysts gain instant visual telemetry, XAI explanations, and one-click remediation controls. In Autonomous Mode, the engine automatically mitigates high-confidence threats (risk score >= 85%) within milliseconds. The modular service architecture allows effortless scaling across additional host nodes."
    )
    add_normal_paragraph(doc, "", bold_italic_prefix="Legal, Privacy and Security Feasibility:")
    add_normal_paragraph(
        doc,
        "Because AegisAI processes network packet metadata and host process identifiers locally at the edge, private corporate data and user communications are never exfiltrated to external cloud servers. The platform incorporates strict JSON Web Token (JWT) authentication, role-based access control, local encrypted credential storage, immutable audit logs, and air-gapped operational compliance."
    )

    # --- CHAPTER 5: METHODOLOGY ---
    add_heading_1(doc, "5.  Methodology", page_break_before=True)
    add_normal_paragraph(
        doc,
        "AegisAI operates on an end-to-end, sub-second telemetry processing and self-healing containment pipeline. The engine continuously ingests host telemetry, evaluates threat probabilities via quantized edge models, computes XAI feature attributions, diverts zero-days to active honeypots, and enforces kernel-level containment."
    )
    
    # 1. Architecture Diagram Image
    add_figure_image(
        doc,
        "00_aegis_architecture_diagram.png",
        "Figure 2: Proposed AegisAI Edge Architecture & Autonomous Remediation Pipeline",
        width_inches=5.4
    )
    
    add_normal_paragraph(doc, "", bold_italic_prefix="Execution Steps:")
    add_list_item(doc, "1. Real-Time Telemetry Harvesting", "The engine polls host CPU, memory, network socket bindings, and process telemetry at 1.0-second intervals using psutil and native socket hooks.")
    add_list_item(doc, "2. Feature Extraction & Normalization", "Raw flow telemetry is converted into normalized multi-dimensional feature vectors matching CICIDS2017 schema attributes (port entropy, byte ratios, duration, flag counts).")
    add_list_item(doc, "3. Quantized ONNX Edge Inference", "The normalized vector is evaluated by the quantized ONNX tree ensemble, yielding a continuous threat score (0.0 to 1.0) and severity classification (Critical, High, Medium, Low).")
    add_list_item(doc, "4. Active Honeypot Deception Routing", "Unclassified anomalies and zero-day exploit probes are automatically redirected to synthetic decoy listeners (FTP on port 2121, SSH on port 2222) to safely isolate and fingerprint attacker payloads.")
    add_list_item(doc, "5. TreeSHAP Feature Attribution", "The XAI engine executes TreeSHAP to calculate exact signed Shapley contribution values for every input anomaly feature.")
    
    # 2. XAI Attribution Screenshot
    add_figure_image(
        doc,
        "02_threat_modal_xai_attribution.png",
        "Figure 3: Explainable AI (XAI) Modal — TreeSHAP Risk Multipliers, Safety Indicators & Mathematical Attribution",
        width_inches=5.4
    )
    
    add_list_item(doc, "6. Cybersecurity Term Translation", "Raw mathematical feature keys are mapped to contextual cybersecurity terminology (e.g., process_cpu_anomaly -> 'High CPU Burst', payload_shannon_entropy -> 'High Entropy').")
    add_list_item(doc, "7. Dual-Mode Containment Evaluation", "The engine checks the active containment policy: if Autonomous Mode is active and risk score >= threshold (0.85), containment executes automatically; otherwise, an analyst confirmation workflow is staged.")
    add_list_item(doc, "8. Kernel Containment Verification", "The responder executes process termination (psutil kill / taskkill /F), network host isolation (netsh advfirewall block rule), or binary quarantine (server/quarantine/<hash>.bin) and verifies OS table removal.")
    
    # 3. Kernel Containment Screenshot
    add_figure_image(
        doc,
        "05_containment_kernel_verified.png",
        "Figure 4: Kernel-Verified Host Containment (Process Termination & Live OS Verification Status)",
        width_inches=5.4
    )
    
    add_list_item(doc, "9. Real-Time WebSocket Broadcasting", "Telemetry snapshots, newly detected threat alerts, and containment verification statuses are broadcast instantaneously to all connected SOC clients.")
    add_list_item(doc, "10. Autonomous AI Agent Reasoning", "For complex high-severity incidents, the LLM agent streams turn-by-turn incident investigation steps and synthesizes downloadable firewall policy patches.")

    # --- CHAPTER 6: REQUIREMENT ANALYSIS ---
    add_heading_1(doc, "6.  Requirement Analysis", page_break_before=True)
    add_normal_paragraph(doc, "", bold_italic_prefix="Hardware Requirements:")
    add_list_item(doc, "Processor", "Intel Core i5 / AMD Ryzen 5 or equivalent (multi-core architecture recommended for parallel asynchronous socket listeners and ML inference).")
    add_list_item(doc, "RAM", "Minimum 8 GB; 16 GB recommended for high-volume attack replay simulations.")
    add_list_item(doc, "Storage", "Minimum 512 GB SSD for dataset handling, SQLite audit logging, and quarantine sandboxing.")
    add_list_item(doc, "Network", "Standard 1 Gbps Ethernet or Wi-Fi interface for live network socket monitoring.")
    
    add_normal_paragraph(doc, "", bold_italic_prefix="Software Requirements:")
    add_list_item(doc, "Programming Stack", "Python 3.10+ (Backend Engine) and JavaScript / React 18 (Frontend Dashboard).")
    add_list_item(doc, "Core Backend Frameworks", "FastAPI, Uvicorn, Pydantic, SQLAlchemy, aiosqlite, and WebSockets.")
    add_list_item(doc, "Machine Learning & XAI", "ONNX Runtime, Scikit-Learn, XGBoost, SHAP, and NumPy.")
    add_list_item(doc, "OS & Systems Engineering", "psutil, Windows netsh advfirewall, and POSIX iptables.")
    add_list_item(doc, "Frontend UI Stack", "React 18, Vite, Tailwind CSS, Lucide React, and Recharts.")
    add_list_item(doc, "Development Tools", "VS Code / Antigravity IDE, Git, and PowerShell 7.")

    # AI Agent Remediation Screenshot
    add_figure_image(
        doc,
        "06_ai_agent_remediation_drawer.png",
        "Figure 5: Autonomous AI Agent Remediation Stream — Turn-by-Turn Investigation & Downloadable Patch Synthesis",
        width_inches=5.4
    )

    add_normal_paragraph(doc, "", bold_italic_prefix="Dataset Requirements:")
    add_list_item(doc, "Benchmark Intrusion Dataset", "Canadian Institute for Cybersecurity CICIDS2017 dataset containing labeled multi-class attack records (DDoS LOIC, SYN Scans, Botnet C2, SQLi, SSH Brute Force, Infiltration).")
    add_list_item(doc, "Live Telemetry Feeds", "Real-time host process telemetry and synthetic socket streaming records.")

    # Threat Audit Logs Screenshot
    add_figure_image(
        doc,
        "07_threat_logs_audit_table.png",
        "Figure 6: Immutable Threat Logs & Multi-Vector Forensic Audit Trail",
        width_inches=5.4
    )

    add_normal_paragraph(doc, "", bold_italic_prefix="Functional Requirements:")
    add_list_item(doc, "User Authentication", "Secure JWT-based analyst login with role-based session protection.")
    add_list_item(doc, "Live Dashboard Monitoring", "Real-time visualization of host CPU, memory, network throughput, and recent threats via WebSockets.")
    add_list_item(doc, "On-Demand ML Scanning", "Interactive scan trigger evaluating live telemetry and streaming attack records.")
    add_list_item(doc, "Explainable AI (XAI) Attribution", "Slide-over modal displaying Risk Multipliers, Safety Indicators, and Decision Tree attribution notes.")
    add_list_item(doc, "Kernel-Verified Containment", "Interactive controls for Process Termination, Host Isolation, and File Quarantine with verified kernel confirmation.")
    add_list_item(doc, "Autonomous AI Agent Reasoning", "Live SSE streaming drawer generating root-cause incident analyses and patch downloads.")
    add_list_item(doc, "Threat Logs & Analytics", "Multi-filtered searchable audit table with CSV/JSON export and 24-hour vulnerability trend charts.")
    add_list_item(doc, "Policy Management", "Dynamic toggles for Autonomous vs. Manual containment modes and threshold sliders.")

    add_normal_paragraph(doc, "", bold_italic_prefix="Non-Functional Requirements:")
    add_list_item(doc, "Sub-50ms Latency", "Edge ML inference and XAI attribution executed with minimal computational delay.")
    add_list_item(doc, "High Throughput", "Asynchronous WebSocket architecture supporting sustained telemetry streams.")
    add_list_item(doc, "Security & Privacy", "Local-first edge execution ensuring zero external exfiltration of sensitive payload data.")
    add_list_item(doc, "Reliability & Resilience", "Background daemon resilience with graceful error handling and automated fallback.")
    add_list_item(doc, "Explainability & Trust", "100% transparent mathematical justifications for all risk scoring and remediation actions.")

    # --- CHAPTER 7: INDUSTRY IMPACT ---
    add_heading_1(doc, "7.  Industry Impact", page_break_before=True)
    add_normal_paragraph(
        doc,
        "Enterprise cybersecurity currently faces a critical operational bottleneck: traditional Security Operations Centers (SOCs) are overwhelmed by millions of daily alerts, while centralized SIEM architectures suffer from substantial ingestion and processing latency. During sophisticated ransomware outbreaks, lateral movement exploits, or zero-day memory injections, an attacker can compromise critical infrastructure in seconds—rendering passive, delayed cloud notifications ineffective."
    )
    add_normal_paragraph(
        doc,
        "AegisAI fundamentally transforms enterprise defense by shifting from passive cloud-centric log monitoring to proactive, edge-native self-healing. By deploying quantized machine learning directly onto host edge nodes, AegisAI reduces threat detection and containment latency from minutes or hours to less than 50 milliseconds. The integration of Explainable AI (TreeSHAP) eliminates the pervasive 'black-box' dilemma, providing security analysts with intuitive, evidence-backed explanations that decompose complex ML probability scores into transparent Risk Multipliers and Safety Indicators."
    )
    
    # Settings & Policy Controls Screenshot
    add_figure_image(
        doc,
        "09_policy_settings_controls.png",
        "Figure 7: AegisAI Edge Policy Configuration & Real-Time Autonomous Sensitivity Controls",
        width_inches=5.4
    )
    
    add_normal_paragraph(
        doc,
        "Furthermore, AegisAI's active deception subsystem introduces proactive cyber defense into endpoint security: rather than merely dropping unclassified zero-day anomaly probes, the engine deceives attackers into synthetic sandbox honeypots, neutralizing threats while capturing invaluable threat intelligence. The autonomous Agentic AI layer further accelerates incident response by synthesizing automated firewall patches in real time."
    )
    add_normal_paragraph(doc, "", bold_italic_prefix="Expected Impact:")
    add_list_item(doc, "Elimination of Cloud Ingestion Latency", "Sub-second edge threat detection preventing rapid lateral movement and data exfiltration.")
    add_list_item(doc, "Reduction of SOC Alert Fatigue", "Transparent XAI feature attributions enabling analysts to rapidly validate and triage high-priority anomalies.")
    add_list_item(doc, "Autonomous Self-Healing Containment", "Immediate OS kernel-level process termination and firewall isolation neutralizing active threats without human delay.")
    add_list_item(doc, "Active Zero-Day Neutralization", "Dynamic synthetic honeypots trapping unclassified exploit probes and safely isolating payloads.")
    add_list_item(doc, "Human-in-the-Loop Governance", "Configurable dual-mode policy ensuring high operational trust and institutional control.")
    add_list_item(doc, "Cost-Effective Edge Deployment", "Open-source architecture operating on commodity hardware without recurring cloud ingestion fees.")
    add_list_item(doc, "Foundation for Next-Generation XDR", "A robust, scalable reference architecture for explainable, autonomous endpoint cyber defense.")
    
    add_normal_paragraph(
        doc,
        "In summary, AegisAI delivers an end-to-end, edge-native cyber defense platform that unites quantized ONNX machine learning, game-theoretic Explainable AI, active honeypot deception, and autonomous kernel containment. Its primary innovation is not merely detecting anomalies—it is the unified, self-healing operational pipeline that identifies, explains, traps, and mitigates cyber threats in real time at the edge.",
        bold_italic_prefix="Conclusion: "
    )

    try:
        doc.save(output_docx_path)
        print(f"[+] Successfully generated formatted synopsis at: {output_docx_path}")
    except PermissionError:
        fallback_path = output_docx_path.replace(".docx", "_Final.docx")
        doc.save(fallback_path)
        print(f"[!] Target file was locked by Word. Successfully saved as: {fallback_path}")

if __name__ == "__main__":
    target_docx = r"D:\Desktop\aegis-ai\AegisAI_Synopsis_Formatted.docx"
    format_aegis_synopsis(target_docx, target_docx)
