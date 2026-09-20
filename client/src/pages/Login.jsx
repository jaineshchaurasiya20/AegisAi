import React, { useState, useEffect, useRef } from "react";
import { Shield, Eye, EyeOff, Loader2, Lock, User, Sparkles, AlertCircle, CheckCircle2 } from "lucide-react";
import * as THREE from "three";

// Fallback / mock implementation for standalone preview
const mockApi = {
  login: async (username, password) => {
    return new Promise((resolve) => {
      setTimeout(() => {
        if (username === "admin" && password === "aegis2024") {
          resolve({ access_token: "aegis_jwt_token_oceanic_blue_89012" });
        } else {
          resolve({ detail: "Invalid security credentials or unauthorized agent access level" });
        }
      }, 1200);
    });
  }
};

const mockSetToken = (token) => {
  if (typeof window !== "undefined") {
    localStorage.setItem("aegis_token", token);
  }
};

export default function Login({ onLogin = () => {} }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  
  // Focused Input tracking for subtle scale expansion
  const [activeInput, setActiveInput] = useState(null);

  // Mouse position state with smooth dampening for glass tilt
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });
  const [smoothMousePos, setSmoothMousePos] = useState({ x: 0, y: 0 });
  const [isHovered, setIsHovered] = useState(false);

  const cardRef = useRef(null);
  const bgCanvasRef = useRef(null);
  const shieldCanvasRef = useRef(null);

  useEffect(() => {
    const link = document.createElement("link");
    link.href = "https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800&display=swap";
    link.rel = "stylesheet";
    document.head.appendChild(link);
    return () => {
      if (document.head.contains(link)) {
        document.head.removeChild(link);
      }
    };
  }, []);

  useEffect(() => {
    let animationFrameId;
    const lerp = (start, end, factor) => start + (end - start) * factor;

    const updateSmoothMouse = () => {
      setSmoothMousePos((prev) => ({
        x: lerp(prev.x, mousePos.x, 0.05),
        y: lerp(prev.y, mousePos.y, 0.05),
      }));
      animationFrameId = requestAnimationFrame(updateSmoothMouse);
    };

    animationFrameId = requestAnimationFrame(updateSmoothMouse);
    return () => cancelAnimationFrame(animationFrameId);
  }, [mousePos]);

  useEffect(() => {
    const container = shieldCanvasRef.current;
    if (!container) return;

    const width = container.clientWidth || 180;
    const height = container.clientHeight || 180;

    // Scene setup
    const scene = new THREE.Scene();

    // Perspective Camera
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 0, 5.2);

    // WebGL Renderer
    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.3;

    container.appendChild(renderer.domElement);

    // Custom 2D Shield Shape
    const shieldShape = new THREE.Shape();
    const w = 1.0, h = 1.25;
    shieldShape.moveTo(0, h);
    shieldShape.bezierCurveTo(w * 0.7, h, w, h * 0.7, w, h * 0.1);
    shieldShape.bezierCurveTo(w, -h * 0.5, w * 0.4, -h * 0.95, 0, -h);
    shieldShape.bezierCurveTo(-w * 0.4, -h * 0.95, -w, -h * 0.5, -w, h * 0.1);
    shieldShape.bezierCurveTo(-w, h * 0.7, -w * 0.7, h, 0, h);

    // Extrude settings for 3D depth
    const extrudeSettings = {
      depth: 0.22,
      bevelEnabled: true,
      bevelSegments: 8,
      steps: 2,
      bevelSize: 0.08,
      bevelThickness: 0.08,
    };

    const shieldGeo = new THREE.ExtrudeGeometry(shieldShape, extrudeSettings);
    shieldGeo.center();

    // Metallic Oceanic Blue Material
    const shieldMat = new THREE.MeshPhysicalMaterial({
      color: 0x0284c7, // Deep Sky / Oceanic Blue
      emissive: 0x0369a1,
      emissiveIntensity: 0.35,
      metalness: 0.85,
      roughness: 0.18,
      clearcoat: 1.0,
      clearcoatRoughness: 0.1,
      reflectivity: 0.9,
    });

    const shieldMesh = new THREE.Mesh(shieldGeo, shieldMat);
    scene.add(shieldMesh);

    // Inner Wireframe Core Emblem Inside Shield
    const wireGeo = new THREE.WireframeGeometry(shieldGeo);
    const wireMat = new THREE.LineBasicMaterial({
      color: 0x38bdf8, // Bright Cyan Wireframe
      transparent: true,
      opacity: 0.4,
    });
    const wireframeMesh = new THREE.LineSegments(wireGeo, wireMat);
    wireframeMesh.scale.set(1.02, 1.02, 1.02);
    shieldMesh.add(wireframeMesh);

    // Glowing Inner Orb Nucleus
    const orbGeo = new THREE.IcosahedronGeometry(0.35, 2);
    const orbMat = new THREE.MeshStandardMaterial({
      color: 0x06b6d4,
      emissive: 0x38bdf8,
      emissiveIntensity: 1.8,
      roughness: 0.2,
      wireframe: true,
    });
    const orbMesh = new THREE.Mesh(orbGeo, orbMat);
    shieldMesh.add(orbMesh);

    // Cinematic Ocean Lighting (Blue & Cyan contrast)
    const ambientLight = new THREE.AmbientLight(0x0f172a, 2.5);
    scene.add(ambientLight);

    const cyanLight = new THREE.PointLight(0x06b6d4, 8, 12);
    cyanLight.position.set(3, 3, 4);
    scene.add(cyanLight);

    const blueLight = new THREE.PointLight(0x2563eb, 7, 12);
    blueLight.position.set(-3, -2, -3);
    scene.add(blueLight);

    let targetRotY = 0;
    let targetRotX = 0;

    const handleMouseMove = (e) => {
      const rect = container.getBoundingClientRect();
      const x = ((e.clientX - rect.left) / width) * 2 - 1;
      const y = -((e.clientY - rect.top) / height) * 2 + 1;
      targetRotY = x * 0.4;
      targetRotX = -y * 0.3;
    };

    window.addEventListener("mousemove", handleMouseMove);

    // Animation Loop
    let animationFrameId;
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      // Soft Floating Motion
      shieldMesh.position.y = Math.sin(elapsedTime * 1.6) * 0.08;

      // Smooth Hover Rotation
      shieldMesh.rotation.y = elapsedTime * 0.3 + targetRotY;
      shieldMesh.rotation.x = Math.sin(elapsedTime * 0.8) * 0.05 + targetRotX;

      // Pulse Wireframe Core
      orbMesh.rotation.y = -elapsedTime * 0.8;
      orbMesh.rotation.x = elapsedTime * 0.5;

      renderer.render(scene, camera);
    };

    animate();

    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      cancelAnimationFrame(animationFrameId);
      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
      shieldGeo.dispose();
      shieldMat.dispose();
      wireGeo.dispose();
      wireMat.dispose();
      orbGeo.dispose();
      orbMat.dispose();
      renderer.dispose();
    };
  }, []);

  useEffect(() => {
    const canvas = bgCanvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let animationFrameId;

    const resizeCanvas = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };

    resizeCanvas();
    window.addEventListener("resize", resizeCanvas);

    // Floating Blue Floating Aura Nodes
    const nodeCount = 38;
    const nodes = Array.from({ length: nodeCount }, () => ({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      size: Math.random() * 1.8 + 0.6,
      vx: (Math.random() - 0.5) * 0.25,
      vy: (Math.random() - 0.5) * 0.25,
      alpha: Math.random() * 0.6 + 0.2,
      pulseSpeed: Math.random() * 0.015 + 0.005,
    }));

    const render = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      nodes.forEach((node) => {
        node.x += node.vx;
        node.y += node.vy;

        if (node.x < 0) node.x = canvas.width;
        if (node.x > canvas.width) node.x = 0;
        if (node.y < 0) node.y = canvas.height;
        if (node.y > canvas.height) node.y = 0;

        node.alpha += node.pulseSpeed;
        if (node.alpha > 0.85 || node.alpha < 0.2) {
          node.pulseSpeed = -node.pulseSpeed;
        }

        ctx.beginPath();
        ctx.arc(node.x, node.y, node.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(56, 189, 248, ${node.alpha})`; // Cyan/Sky Blue
        ctx.shadowBlur = 12;
        ctx.shadowColor = "#0284c7";
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener("resize", resizeCanvas);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  const handleCardMouseMove = (e) => {
    if (!cardRef.current) return;
    const rect = cardRef.current.getBoundingClientRect();
    setMousePos({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const apiModule = (typeof api !== "undefined" && api.login) ? api : mockApi;
      const setTokenFunc = (typeof setToken !== "undefined") ? setToken : mockSetToken;

      const data = await apiModule.login(username, password);

      if (data.access_token) {
        setTokenFunc(data.access_token);
        onLogin(data);
      } else {
        setError(data.detail || "Authentication failed. Invalid agent token.");
      }
    } catch (err) {
      setError(err.message || "Aegis Security Gateway unreachable");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div 
      className="relative min-h-screen bg-[#070d19] text-slate-100 flex items-center justify-center p-4 overflow-hidden select-none"
      style={{ fontFamily: "'Poppins', sans-serif" }}
    >
      {/* 1. Background Particle Canvas */}
      <canvas ref={bgCanvasRef} className="absolute inset-0 pointer-events-none z-0" />

      {/* 2. Cyber Blue Grid Overlay */}
      <div 
        className="fixed inset-0 pointer-events-none opacity-[0.04] z-0"
        style={{
          backgroundImage: "linear-gradient(#38bdf8 1px, transparent 1px), linear-gradient(90deg, #38bdf8 1px, transparent 1px)",
          backgroundSize: "44px 44px",
        }}
      />

      {/* 3. Oceanic Gradient Ambient Vignette Glows */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[38rem] h-[32rem] bg-gradient-to-tr from-cyan-600/20 via-blue-700/15 to-transparent rounded-full blur-[130px] pointer-events-none" />
      <div className="absolute bottom-12 right-12 w-80 h-80 bg-blue-900/20 rounded-full blur-[110px] pointer-events-none" />

      {/* Main Form Container */}
      <div className="w-full max-w-sm relative z-10 my-6">
        
        {/* Header with 3D Oceanic Shield */}
        <div className="text-center mb-5 flex flex-col items-center">
          <div className="relative w-36 h-36 flex items-center justify-center cursor-grab active:cursor-grabbing">
            <div ref={shieldCanvasRef} className="w-full h-full" />
          </div>

          <h1 className="mt-1 text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            Aegis<span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">AI</span>
            <span className="text-[10px] font-semibold tracking-widest uppercase px-2 py-0.5 rounded-full bg-cyan-500/15 border border-cyan-500/30 text-cyan-300 shadow-[0_0_12px_rgba(6,182,212,0.2)]">
              Edge
            </span>
          </h1>
          <p className="text-slate-400 text-xs mt-1 font-normal tracking-wide">
            Edge Threat Detection Engine
          </p>
        </div>

        {/* Liquid UI Glassmorphic Card */}
        <div
          ref={cardRef}
          onMouseMove={handleCardMouseMove}
          onMouseEnter={() => setIsHovered(true)}
          onMouseLeave={() => setIsHovered(false)}
          className="relative rounded-3xl p-[1.5px] transition-all duration-700 ease-out"
          style={{
            background: isHovered
              ? `radial-gradient(350px circle at ${smoothMousePos.x}px ${smoothMousePos.y}px, rgba(56, 189, 248, 0.45), rgba(37, 99, 235, 0.25), transparent 70%)`
              : "linear-gradient(135deg, rgba(255,255,255,0.12), rgba(255,255,255,0.02))",
          }}
        >
          {/* Frosted Glass Core Panel */}
          <div className="rounded-[22px] bg-[#0b1329]/80 backdrop-blur-2xl p-7 border border-cyan-500/15 shadow-[0_25px_60px_-15px_rgba(0,0,0,0.85)] relative overflow-hidden transition-all duration-700 ease-out">
            
            {/* Top Glass Edge Sheen Highlight */}
            <div className="absolute inset-x-0 top-0 h-[1.5px] bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent pointer-events-none" />

            <div className="flex items-center justify-between mb-5">
              <h2 className="text-white font-semibold text-sm tracking-wide">
                Sign In to Dashboard
              </h2>
              <Sparkles size={15} className="text-cyan-400 animate-pulse" />
            </div>

            {/* Form */}
            <form id="login-form" onSubmit={handleSubmit} className="space-y-4">
              
              {/* Username Input with Refined 1.02x Scale Elevation */}
              <div 
                className={`relative transition-all duration-300 ease-out ${
                  activeInput === "username" 
                    ? "scale-[1.02] z-20" 
                    : "scale-100 z-10"
                }`}
              >
                <label className="block text-[11px] font-medium text-slate-300 mb-1.5 tracking-wide" htmlFor="login-username">
                  Username
                </label>
                <div className="relative group">
                  <div className={`absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none transition-colors duration-300 ${
                    activeInput === "username" ? "text-cyan-400" : "text-slate-400"
                  }`}>
                    <User size={14} />
                  </div>
                  <input
                    id="login-username"
                    type="text"
                    value={username}
                    onFocus={() => setActiveInput("username")}
                    onBlur={() => setActiveInput(null)}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                    placeholder="Enter username"
                    className={`w-full bg-[#070e1e]/90 border rounded-xl pl-9 pr-3.5 py-2.5 text-white text-xs placeholder-slate-500 focus:outline-none transition-all duration-300 ${
                      activeInput === "username"
                        ? "border-cyan-400 shadow-[0_0_18px_rgba(6,182,212,0.3)] ring-1 ring-cyan-500/50"
                        : "border-slate-700/60 hover:border-slate-600"
                    }`}
                  />
                </div>
              </div>

              {/* Password Input with Refined 1.02x Scale Elevation */}
              <div 
                className={`relative transition-all duration-300 ease-out ${
                  activeInput === "password" 
                    ? "scale-[1.02] z-20" 
                    : "scale-100 z-10"
                }`}
              >
                <label className="block text-[11px] font-medium text-slate-300 mb-1.5 tracking-wide" htmlFor="login-password">
                  Password
                </label>
                <div className="relative group">
                  <div className={`absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none transition-colors duration-300 ${
                    activeInput === "password" ? "text-cyan-400" : "text-slate-400"
                  }`}>
                    <Lock size={14} />
                  </div>
                  <input
                    id="login-password"
                    type={showPass ? "text" : "password"}
                    value={password}
                    onFocus={() => setActiveInput("password")}
                    onBlur={() => setActiveInput(null)}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    placeholder="••••••••"
                    className={`w-full bg-[#070e1e]/90 border rounded-xl pl-9 pr-9 py-2.5 text-white text-xs placeholder-slate-500 focus:outline-none transition-all duration-300 ${
                      activeInput === "password"
                        ? "border-cyan-400 shadow-[0_0_18px_rgba(6,182,212,0.3)] ring-1 ring-cyan-500/50"
                        : "border-slate-700/60 hover:border-slate-600"
                    }`}
                  />
                  <button
                    type="button"
                    id="toggle-password-btn"
                    onClick={() => setShowPass(!showPass)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-300 transition-colors duration-200 p-1"
                    aria-label={showPass ? "Hide password" : "Show password"}
                  >
                    {showPass ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
              </div>

              {/* Error Alert Box */}
              {error && (
                <div className="bg-red-500/15 border border-red-500/30 text-red-300 text-xs rounded-xl p-2.5 flex items-start gap-2 transition-all duration-300">
                  <AlertCircle size={15} className="shrink-0 mt-0.5 text-red-400" />
                  <span>{error}</span>
                </div>
              )}

              {/* Submit Button */}
              <button
                id="login-submit-btn"
                type="submit"
                disabled={loading}
                className="relative w-full py-3 rounded-xl font-semibold text-xs text-white overflow-hidden group shadow-lg shadow-cyan-950/40 hover:shadow-cyan-600/30 transition-all duration-500 ease-out disabled:opacity-60 disabled:cursor-not-allowed mt-2"
              >
                <div className="absolute inset-0 bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 transition-all duration-500 ease-out group-hover:scale-105" />
                <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-cyan-400 opacity-0 group-hover:opacity-100 transition-opacity duration-500 ease-out" />
                
                <span className="relative z-10 flex items-center justify-center gap-2">
                  {loading ? (
                    <>
                      <Loader2 size={15} className="animate-spin text-white" />
                      <span>Authenticating...</span>
                    </>
                  ) : (
                    <>
                      <span>Sign In</span>
                      <Shield size={14} className="group-hover:translate-x-0.5 transition-transform duration-300" />
                    </>
                  )}
                </span>
              </button>
            </form>

            {/* Demo Credentials Pill */}
            <div className="mt-5 pt-4 border-t border-white/5 text-center">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#060c18]/80 border border-slate-800 text-[11px] text-slate-300">
                <CheckCircle2 size={12} className="text-cyan-400" />
                <span>Demo access:</span>
                <code className="font-mono text-cyan-300 font-medium bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-500/20">
                  admin / aegis2024
                </code>
              </div>
            </div>

          </div>
        </div>

      </div>
    </div>
  );
}