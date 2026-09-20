import React, { useState, useEffect, useRef } from "react";
import {
  Shield, Eye, EyeOff, Loader2, Lock, User, ArrowRight,
  ShieldCheck, AlertCircle
} from "lucide-react";
import * as THREE from "three";
import { api, setToken } from "../services/api";

// Fallback mock credentials for standalone demonstration
const mockApi = {
  login: async (username, password) => {
    return new Promise((resolve) => {
      setTimeout(() => {
        if (username === "admin" && password === "aegis2024") {
          resolve({ access_token: "mock-jwt-token-aegis-2026-xyz" });
        } else {
          resolve({ detail: "Invalid credentials or unauthorized access" });
        }
      }, 1000);
    });
  }
};

export default function Login({ onLogin = () => {} }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [demoActive, setDemoActive] = useState(false);
  const [activeInput, setActiveInput] = useState(null);

  const mouseRef = useRef({ x: 0, y: 0 });
  const smoothMouseRef = useRef({ x: 0, y: 0 });
  const cardHoverRef = useRef(false);

  const cardRef = useRef(null);
  const bgCanvasRef = useRef(null);
  const shieldCanvasRef = useRef(null);

  // Load Typography
  useEffect(() => {
    const link = document.createElement("link");
    link.href = "https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800&family=Space+Grotesk:wght@500;700&display=swap";
    link.rel = "stylesheet";
    document.head.appendChild(link);
    return () => {
      if (document.head.contains(link)) document.head.removeChild(link);
    };
  }, []);

  const handleGlobalMouseMove = (e) => {
    mouseRef.current.x = (e.clientX / window.innerWidth) * 2 - 1;
    mouseRef.current.y = (e.clientY / window.innerHeight) * 2 - 1;
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. THREE.JS SCENE: DARK BLUISH SHIELD WITH EDGE GLOW & EDGE-ONLY LOGO
  // ═══════════════════════════════════════════════════════════════════════════
  useEffect(() => {
    const container = shieldCanvasRef.current;
    if (!container) return;

    const width = container.clientWidth || 280;
    const height = container.clientHeight || 160;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 0.2, 5.2);

    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: "high-performance" });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.4;
    container.appendChild(renderer.domElement);

    const mainGroup = new THREE.Group();
    scene.add(mainGroup);

    // ── A. Outer Dark Bluish Shield ─────────────────────────────────────────
    const shieldShape = new THREE.Shape();
    const w = 0.5, h = 0.6;
    shieldShape.moveTo(0, h);
    shieldShape.bezierCurveTo(w * 0.75, h, w, h * 0.75, w, h * 0.15);
    shieldShape.bezierCurveTo(w, -h * 0.45, w * 0.45, -h * 0.95, 0, -h);
    shieldShape.bezierCurveTo(-w * 0.45, -h * 0.95, -w, -h * 0.45, -w, h * 0.15);
    shieldShape.bezierCurveTo(-w, h * 0.75, -w * 0.75, h, 0, h);

    const extrudeSettings = { depth: 0.18, bevelEnabled: true, bevelSegments: 4, steps: 1, bevelSize: 0.08, bevelThickness: 0.08 };
    const shieldGeo = new THREE.ExtrudeGeometry(shieldShape, extrudeSettings);
    shieldGeo.center();

    // Dark bluish type base material
    const shieldMat = new THREE.MeshPhysicalMaterial({
      color: 0x091428, 
      emissive: 0x020614, 
      metalness: 1.0, 
      roughness: 0.05, 
      clearcoat: 1.0, 
      clearcoatRoughness: 0.1, 
      reflectivity: 1.0
    });
    const shieldMesh = new THREE.Mesh(shieldGeo, shieldMat);
    mainGroup.add(shieldMesh);

    // Glowing Edge for the outer shield
    const edgesGeo = new THREE.EdgesGeometry(shieldGeo, 24);
    const edgesMat = new THREE.LineBasicMaterial({ color: 0x00f0ff, transparent: true, opacity: 0.85 });
    const edgesMesh = new THREE.LineSegments(edgesGeo, edgesMat);
    shieldMesh.add(edgesMesh);

    // ── B. Inner Cinematic Glowing Shield Logo (Edge Only) ──────────────────
    const innerShieldShape = new THREE.Shape();
    const iw = 0.35, ih = 0.45;
    innerShieldShape.moveTo(0, ih);
    innerShieldShape.bezierCurveTo(iw * 0.75, ih, iw, ih * 0.75, iw, ih * 0.15);
    innerShieldShape.bezierCurveTo(iw, -ih * 0.45, iw * 0.45, -ih * 0.95, 0, -ih * 1.1);
    innerShieldShape.bezierCurveTo(-iw * 0.45, -ih * 0.95, -iw, -ih * 0.45, -iw, ih * 0.15);
    innerShieldShape.bezierCurveTo(-iw, ih * 0.75, -iw * 0.75, ih, 0, ih);

    const innerShieldGeo = new THREE.ExtrudeGeometry(innerShieldShape, {
      depth: 0.08, bevelEnabled: true, bevelSegments: 2, bevelSize: 0.02, bevelThickness: 0.02
    });
    innerShieldGeo.center();

    // Inner shield fill with blue tint
const innerShieldMat = new THREE.MeshStandardMaterial({
  color: 0x0055ff,      // Blue color (0x00f0ff for cyan, 0x0000ff for pure blue)
  transparent: true, 
  opacity: 0.5,         // Changed from 0.0 to 0.2 so the blue tint is visible
  depthWrite: false
});
    const innerShieldMesh = new THREE.Mesh(innerShieldGeo, innerShieldMat);
    innerShieldMesh.position.z = 0.14;
    shieldMesh.add(innerShieldMesh);

    // Base glowing wireframe outline (Edge representation)
    const innerEdgesGeo = new THREE.EdgesGeometry(innerShieldGeo);
    const innerEdgesMat = new THREE.LineBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.9 });
    const innerEdgesMesh = new THREE.LineSegments(innerEdgesGeo, innerEdgesMat);
    innerShieldMesh.add(innerEdgesMesh);

    // Dynamic Advance Aura Line 1 (Cyan)
    const auraMat1 = new THREE.LineBasicMaterial({ color: 0x00f0ff, transparent: true, opacity: 0.8 });
    const auraMesh1 = new THREE.LineSegments(innerEdgesGeo, auraMat1);
    innerShieldMesh.add(auraMesh1);

    // Dynamic Advance Aura Line 2 (Violet)
    const auraMat2 = new THREE.LineBasicMaterial({ color: 0xa855f7, transparent: true, opacity: 0.8 });
    const auraMesh2 = new THREE.LineSegments(innerEdgesGeo, auraMat2);
    innerShieldMesh.add(auraMesh2);

    // ── C. Holographic Orbital Rings ─────────────────────────────────────────
    const ringGeo1 = new THREE.RingGeometry(1.85, 1.88, 64);
    const ringMat1 = new THREE.MeshBasicMaterial({ color: 0x00f0ff, side: THREE.DoubleSide, transparent: true, opacity: 0.65 });
    const ringMesh1 = new THREE.Mesh(ringGeo1, ringMat1);
    ringMesh1.rotation.set(Math.PI * 0.38, Math.PI * 0.12, 0);
    mainGroup.add(ringMesh1);

    const ringGeo2 = new THREE.RingGeometry(2.1, 2.12, 64);
    const ringMat2 = new THREE.MeshBasicMaterial({ color: 0xa855f7, side: THREE.DoubleSide, transparent: true, opacity: 0.45 });
    const ringMesh2 = new THREE.Mesh(ringGeo2, ringMat2);
    ringMesh2.rotation.set(Math.PI * 0.42, -Math.PI * 0.18, 0);
    mainGroup.add(ringMesh2);

    // ── D. Orbiting Holographic Data Cubes ──────────────────────────────────
    const cubeCount = 7;
    const cubes = [];
    const cubeGeo = new THREE.BoxGeometry(0.14, 0.14, 0.14);
    const cubeEdgesGeo = new THREE.EdgesGeometry(cubeGeo);
    const cubeEdgeMat = new THREE.LineBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.6 });

    for (let i = 0; i < cubeCount; i++) {
      const cubeMat = new THREE.MeshStandardMaterial({
        color: i % 2 === 0 ? 0x06b6d4 : 0x8b5cf6, emissive: i % 2 === 0 ? 0x38bdf8 : 0xa855f7, emissiveIntensity: 1.6, transparent: true, opacity: 0.75
      });
      const cubeMesh = new THREE.Mesh(cubeGeo, cubeMat);
      cubeMesh.add(new THREE.LineSegments(cubeEdgesGeo, cubeEdgeMat));
      mainGroup.add(cubeMesh);
      cubes.push({ mesh: cubeMesh, angle: (i / cubeCount) * Math.PI * 2, radius: 1.95 + (i % 2) * 0.2, speed: 0.45 + (i % 3) * 0.15, rotSpeed: 1.2 + i * 0.4 });
    }

    // ── E. Holographic Pedestal Energy Discs ────────────────────────────────
    const discGroup = new THREE.Group();
    discGroup.position.set(0, -1.6, 0);
    discGroup.rotation.x = Math.PI * 0.48;
    mainGroup.add(discGroup);
    
    const discGeos = [];
    const discMats = [];
    [1.4, 1.0, 0.6, 0.25].forEach((radius, idx) => {
      const geo = new THREE.RingGeometry(radius, radius + 0.03, 32);
      const mat = new THREE.MeshBasicMaterial({ color: idx % 2 === 0 ? 0x00f0ff : 0x6366f1, side: THREE.DoubleSide, transparent: true, opacity: 0.7 - idx * 0.12 });
      discGeos.push(geo); discMats.push(mat);
      discGroup.add(new THREE.Mesh(geo, mat));
    });

    // ── F. Lighting ────────────────────────────────────────────────────────
    const ambientLight = new THREE.AmbientLight(0xffffff, 1.8);
    scene.add(ambientLight);
    const cyanPoint = new THREE.PointLight(0x00f0ff, 9, 14);
    cyanPoint.position.set(3.5, 2.5, 4.5);
    scene.add(cyanPoint);
    const purplePoint = new THREE.PointLight(0xa855f7, 8, 14);
    purplePoint.position.set(-3.5, -1.5, 3.5);
    scene.add(purplePoint);

    // Animation Loop
    let animId;
    const clock = new THREE.Clock();

    const animate = () => {
      animId = requestAnimationFrame(animate);
      const t = clock.getElapsedTime();

      smoothMouseRef.current.x += (mouseRef.current.x - smoothMouseRef.current.x) * 0.06;
      smoothMouseRef.current.y += (mouseRef.current.y - smoothMouseRef.current.y) * 0.06;

      shieldMesh.position.y = Math.sin(t * 1.5) * 0.08;
      shieldMesh.rotation.y = Math.sin(t * 0.7) * 0.25 + smoothMouseRef.current.x * 0.35;
      shieldMesh.rotation.x = Math.cos(t * 0.6) * 0.06 - smoothMouseRef.current.y * 0.2;

      if (cardRef.current) {
        cardRef.current.style.transform = cardHoverRef.current 
          ? `perspective(1000px) rotateX(${-smoothMouseRef.current.y * 3.5}deg) rotateY(${smoothMouseRef.current.x * 3.5}deg)` 
          : "perspective(1000px) rotateX(0deg) rotateY(0deg)";
      }

      // ── CINEMATIC DYNAMIC AURA ANIMATION ──
      const expand1 = 1.0 + Math.sin(t * 3.0) * 0.12;
      auraMesh1.scale.setScalar(expand1);
      auraMat1.opacity = 1.0 - (expand1 - 1.0) * 12;
      
      const expand2 = 1.0 + Math.cos(t * 2.0) * 0.18;
      auraMesh2.scale.setScalar(expand2);
      auraMat2.opacity = 0.8 - (expand2 - 1.0) * 5;

      ringMesh1.rotation.z = t * 0.2;
      ringMesh2.rotation.z = -t * 0.16;

      cubes.forEach((c) => {
        const a = c.angle + t * c.speed;
        const rx = Math.cos(a) * c.radius;
        const rz = Math.sin(a) * c.radius;
        c.mesh.position.set(rx, rz * Math.sin(0.38) + Math.sin(t * 2 + c.radius) * 0.05, rz * Math.cos(0.38));
        c.mesh.rotation.set(t * c.rotSpeed, t * c.rotSpeed, 0);
      });

      discGroup.rotation.z = t * 0.12;
      renderer.render(scene, camera);
    };

    animate();

    return () => {
      cancelAnimationFrame(animId);
      if (container.contains(renderer.domElement)) container.removeChild(renderer.domElement);
      
      [shieldGeo, shieldMat, edgesGeo, edgesMat, innerShieldGeo, innerShieldMat, 
       innerEdgesGeo, innerEdgesMat, auraMat1, auraMat2, ringGeo1, ringMat1, 
       ringGeo2, ringMat2, cubeGeo, cubeEdgeMat].forEach(item => item.dispose());
      cubes.forEach(c => c.mesh.material.dispose());
      discGeos.forEach(g => g.dispose());
      discMats.forEach(m => m.dispose());
      renderer.dispose();
    };
  }, []);

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. 3D EXPANDED CYBERNETIC NEURAL MESH
  // ═══════════════════════════════════════════════════════════════════════════
  useEffect(() => {
    const canvas = bgCanvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d", { alpha: false });
    let animId;

    const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    resize();
    window.addEventListener("resize", resize);

    // Expanded grid dimensions for full background coverage
    const cols = 80; 
    const rows = 65; 
    const gridNodes = [];
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        gridNodes.push({
          gridX: (c / (cols - 1) - 0.5) * 9.0, // Expanded width multiplier
          gridZ: 0.5 + (r / (rows - 1)) * 8.0, // Expanded depth
          yOffset: (Math.sin(c * 0.8) + Math.cos(r * 0.6)) * 0.15,
          pulse: Math.random() * Math.PI * 2,
          isSpecial: Math.random() > 0.88,
        });
      }
    }

    let time = 0;
    const renderGrid = () => {
      time += 0.012;
      ctx.fillStyle = "#020c25d8";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      const cx = canvas.width * 0.5, cy = canvas.height * 0.45, fov = 400;
      const projected = gridNodes.map((n) => {
        const yWorld = 1.0 + n.yOffset + Math.sin(time * 1.5 + n.gridX * 2 + n.gridZ) * 0.15 + mouseRef.current.y * 0.08;
        const xWorld = n.gridX + mouseRef.current.x * 0.12;
        const scale = fov / (fov + n.gridZ * 180);
        return { px: cx + xWorld * scale * (canvas.width * 0.8), py: cy + yWorld * scale * (canvas.height * 0.8), scale, isSpecial: n.isSpecial, pulse: n.pulse };
      });

      for (let r = 0; r < rows; r++) {
        ctx.beginPath();
        for (let c = 0; c < cols; c++) {
          const p = projected[r * cols + c];
          c === 0 ? ctx.moveTo(p.px, p.py) : ctx.lineTo(p.px, p.py);
        }
        ctx.strokeStyle = `rgba(56, 189, 248, ${Math.max(0.02, 0.25 - (r / rows) * 0.22)})`;
        ctx.lineWidth = 0.9; ctx.stroke();
      }

      for (let c = 0; c < cols; c += 2) {
        ctx.beginPath();
        for (let r = 0; r < rows; r++) {
          const p = projected[r * cols + c];
          r === 0 ? ctx.moveTo(p.px, p.py) : ctx.lineTo(p.px, p.py);
        }
        ctx.strokeStyle = `rgba(139, 92, 246, 0.1)`;
        ctx.lineWidth = 0.7; ctx.stroke();
      }

      projected.forEach((p) => {
        const glow = Math.sin(time * 2.5 + p.pulse) * 0.5 + 0.5;
        const radius = (p.isSpecial ? 2.5 : 1.2) * p.scale;
        
        // Culling out-of-bounds rendering for performance
        if(p.px < -20 || p.px > canvas.width + 20 || p.py < -20 || p.py > canvas.height + 20) return;

        ctx.beginPath(); ctx.arc(p.px, p.py, Math.max(0.5, radius), 0, Math.PI * 2);
        ctx.fillStyle = p.isSpecial ? `rgba(0, 240, 255, ${0.4 + glow * 0.5})` : `rgba(168, 85, 247, ${0.2 + glow * 0.3})`;
        ctx.fill();

        if (p.isSpecial && glow > 0.4) {
          ctx.beginPath(); ctx.arc(p.px, p.py, radius * 3.5, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(56, 189, 248, ${glow * 0.1})`; ctx.fill();
        }
      });
      animId = requestAnimationFrame(renderGrid);
    };

    renderGrid();
    return () => { window.removeEventListener("resize", resize); cancelAnimationFrame(animId); };
  }, []);

  const handleSubmit = async (e) => {
    if (e) e.preventDefault();
    setLoading(true); setError("");

    try {
      let data;
      try {
        data = await api.login(username, password);
      } catch (backendErr) {
        if (backendErr.message && !backendErr.message.includes("Failed to fetch") && !backendErr.message.includes("NetworkError")) throw backendErr;
        console.warn("FastAPI backend unreachable, fallback to demo mode:", backendErr);
        data = await mockApi.login(username, password);
      }
      if (data && data.access_token) {
        setToken(data.access_token); onLogin(data);
      } else {
        setError(data?.detail || "Invalid credentials or unauthorized access.");
      }
    } catch (err) { setError(err.message || "Aegis Security Gateway unreachable."); }
    finally { setLoading(false); }
  };

  const handleUseDemo = () => {
    setUsername("admin"); setPassword("aegis2024"); setDemoActive(true);
    setTimeout(() => { setDemoActive(false); handleSubmit(); }, 450);
  };

  return (
    <div onMouseMove={handleGlobalMouseMove} className="relative min-h-screen bg-[#030712] text-slate-100 flex flex-col justify-between overflow-x-hidden select-none" style={{ fontFamily: "'Poppins', sans-serif" }}>
      <canvas ref={bgCanvasRef} className="fixed inset-0 pointer-events-none z-0" />
      <div className="fixed top-12 left-1/2 -translate-x-1/2 w-[52rem] h-[34rem] bg-gradient-to-b from-blue-600/15 via-cyan-500/10 to-transparent rounded-full blur-[140px] pointer-events-none z-0" />
      <div className="fixed bottom-10 left-10 w-[30rem] h-[24rem] bg-purple-900/15 rounded-full blur-[120px] pointer-events-none z-0" />
      <div className="fixed bottom-10 right-10 w-[30rem] h-[24rem] bg-blue-900/15 rounded-full blur-[120px] pointer-events-none z-0" />

      <header className="relative z-30 w-full px-8 py-6 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 via-purple-600 to-cyan-500 p-[1.5px] shadow-[0_0_18px_rgba(99,102,241,0.4)] flex items-center justify-center">
            <div className="w-full h-full bg-[#070d1e] rounded-[10px] flex items-center justify-center">
              <Shield size={20} className="text-cyan-400 fill-cyan-400/20" />
            </div>
          </div>
          <div>
            <div className="flex items-center"><span className="text-white font-bold text-lg tracking-tight">Aegis</span><span className="font-bold text-lg tracking-tight bg-gradient-to-r from-purple-400 to-indigo-300 bg-clip-text text-transparent ml-1">AI</span></div>
            <p className="text-slate-400 text-[11px] font-normal tracking-wide">Local EDR & Threat Intelligence</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-xs font-medium shadow-[0_0_12px_rgba(16,185,129,0.2)]">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" /><span>System Online</span>
          </div>
          <span className="text-slate-600 text-sm">|</span><span className="mono text-slate-400 text-xs tracking-wider">v1.0.0</span>
        </div>
      </header>

      <main className="relative z-20 flex-1 flex flex-col items-center justify-center px-4 py-2">
        <div className="relative w-full max-w-4xl flex flex-col items-center justify-center">
          
          <div className="relative w-[380px] h-[260px] flex items-center justify-center -mb-4">
            <div ref={shieldCanvasRef} className="w-full h-full cursor-grab active:cursor-grabbing" />
          </div>

          <div ref={cardRef} onMouseEnter={() => cardHoverRef.current = true} onMouseLeave={() => { cardHoverRef.current = false; if (cardRef.current) cardRef.current.style.transform = "perspective(1000px) rotateX(0deg) rotateY(0deg)"; }} className="w-full max-w-[440px] relative z-20 transition-transform duration-500">
            <div className="relative rounded-[28px] p-[1.5px] bg-gradient-to-br from-cyan-500/40 via-blue-600/20 to-purple-600/40 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.9),0_0_40px_rgba(6,182,212,0.12)]">
              <div className="rounded-[26px] bg-[#091024]/85 backdrop-blur-2xl p-7 md:p-8 border border-white/[0.04] relative overflow-hidden">
                <div className="absolute inset-x-0 top-0 h-[1.5px] bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent pointer-events-none" />

                <div className="mb-6">
                  <p className="text-cyan-400 text-[10px] font-semibold tracking-[0.2em] uppercase mb-1">WELCOME BACK</p>
                  <h2 className="text-white text-2xl font-bold tracking-tight">Sign in to <span className="bg-gradient-to-r from-purple-400 via-indigo-300 to-cyan-400 bg-clip-text text-transparent">Aegis AI</span></h2>
                  <p className="text-slate-400 text-xs mt-1">Secure access to your threat intelligence platform</p>
                </div>

                {error && (
                  <div className="mb-4 flex items-center gap-2 p-3 rounded-xl bg-red-950/50 border border-red-500/40 text-red-300 text-xs animate-fade-in"><AlertCircle size={15} className="text-red-400 flex-shrink-0" /><span>{error}</span></div>
                )}

                <form id="login-form" onSubmit={handleSubmit} className="space-y-4">
                  <div>
                    <div className="relative group">
                      <div className={`absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none transition-colors ${activeInput === "username" ? "text-cyan-400" : "text-slate-400"}`}><User size={15} /></div>
                      <input id="login-username" type="text" value={username} onFocus={() => setActiveInput("username")} onBlur={() => setActiveInput(null)} onChange={(e) => setUsername(e.target.value)} required placeholder="Username or Email" className={`w-full bg-[#050b18]/90 border rounded-xl pl-10 pr-4 py-3 text-white text-xs placeholder-slate-500 focus:outline-none transition-all duration-300 shadow-inner ${activeInput === "username" ? "border-cyan-400 shadow-[0_0_18px_rgba(6,182,212,0.25)] ring-1 ring-cyan-500/40" : "border-slate-800 hover:border-slate-700"} ${demoActive ? "ring-2 ring-cyan-400 bg-cyan-950/30" : ""}`} />
                    </div>
                  </div>

                  <div>
                    <div className="relative group">
                      <div className={`absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none transition-colors ${activeInput === "password" ? "text-cyan-400" : "text-slate-400"}`}><Lock size={15} /></div>
                      <input id="login-password" type={showPass ? "text" : "password"} value={password} onFocus={() => setActiveInput("password")} onBlur={() => setActiveInput(null)} onChange={(e) => setPassword(e.target.value)} required placeholder="Password" className={`w-full bg-[#050b18]/90 border rounded-xl pl-10 pr-10 py-3 text-white text-xs placeholder-slate-500 focus:outline-none transition-all duration-300 shadow-inner ${activeInput === "password" ? "border-cyan-400 shadow-[0_0_18px_rgba(6,182,212,0.25)] ring-1 ring-cyan-500/40" : "border-slate-800 hover:border-slate-700"} ${demoActive ? "ring-2 ring-cyan-400 bg-cyan-950/30" : ""}`} />
                      <button type="button" onClick={() => setShowPass(!showPass)} className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-500 hover:text-slate-300 transition" title={showPass ? "Hide password" : "Show password"}>{showPass ? <EyeOff size={15} /> : <Eye size={15} />}</button>
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-xs pt-0.5">
                    <label className="flex items-center gap-2 cursor-pointer text-slate-400 hover:text-slate-200 transition">
                      <input type="checkbox" checked={rememberMe} onChange={(e) => setRememberMe(e.target.checked)} className="w-3.5 h-3.5 rounded border-slate-700 bg-slate-900 text-indigo-500 focus:ring-0 focus:ring-offset-0 cursor-pointer" />
                      <span>Remember me</span>
                    </label>
                    <a href="#forgot" onClick={(e) => { e.preventDefault(); alert("Self-Service Password Reset: Contact your AegisAI Security Administrator."); }} className="text-cyan-400/90 hover:text-cyan-300 transition text-[11px]">Forgot password?</a>
                  </div>

                  <button id="login-submit-btn" type="submit" disabled={loading} className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-[#6366f1] via-[#4f46e5] to-[#0284c7] hover:from-[#4f46e5] hover:to-[#06b6d4] text-white font-semibold text-xs tracking-wide shadow-[0_0_24px_rgba(99,102,241,0.35)] hover:shadow-[0_0_32px_rgba(6,182,212,0.45)] transition-all duration-300 flex items-center justify-center gap-2 active:scale-[0.99] disabled:opacity-60">
                    {loading ? <><Loader2 size={15} className="animate-spin text-white" /><span>Authenticating...</span></> : <><ArrowRight size={15} /><span>Sign In</span></>}
                  </button>

                  <div className="relative flex items-center justify-center my-3">
                    <div className="border-t border-slate-800 w-full" /><span className="bg-[#091024] px-3 text-[10px] text-slate-500 uppercase tracking-wider font-semibold">OR</span><div className="border-t border-slate-800 w-full" />
                  </div>

                  <button id="login-demo-btn" type="button" onClick={handleUseDemo} className="w-full py-2.5 px-4 rounded-xl bg-slate-900/60 hover:bg-slate-800/80 border border-slate-700/60 hover:border-cyan-500/40 text-slate-300 hover:text-white font-medium text-xs transition-all flex items-center justify-center gap-2 shadow-sm">
                    <Shield size={14} className="text-cyan-400" /><span>Use Demo Credentials</span>
                  </button>

                  <div className="pt-2 flex items-center justify-between text-[11px] text-slate-500 border-t border-white/[0.04]">
                    <div className="flex items-center gap-1.5"><ShieldCheck size={23} className="text-cyan-400 flex-shrink-0" /><span>Your data is protected with local encryption</span></div>
                    <Lock size={12} className="text-slate-600 flex-shrink-0" />
                  </div>
                </form>
              </div>
            </div>
          </div>
        </div>
      </main>

      <footer className="relative z-30 w-full px-8 py-5 flex items-center justify-between text-[11px] text-slate-500 border-t border-white/[0.03]">
        <div className="flex items-center gap-2 mono tracking-wider"><span className="text-cyan-500 font-bold">—</span><span>DETECT</span><span className="text-slate-700">/</span><span>ANALYZE</span><span className="text-slate-700">/</span><span>RESPOND</span></div>
        <div><span>Powered by AI • Built for a safer tomorrow</span></div>
      </footer>
    </div>
  );
}