/**
 * NETWORK INTRUSION DETECTION — MACHINE LEARNING SECURITY SYSTEM
 * Three.js 3D Visualizer: Translucent Glass AI Core & Interactive Network Topology
 * Visual Palette: Pearl White, Electric Violet, Magenta & Warm Amber
 */

(function () {
    "use strict";

    // Global Visualizer Handles
    let heroScene, heroCamera, heroRenderer, aiCoreMesh, innerCoreMesh, ringMesh1, ringMesh2, heroParticleCloud;
    let topoScene, topoCamera, topoRenderer, packetParticles = [];
    let topoNodes = {};

    document.addEventListener("DOMContentLoaded", () => {
        initHero3DAICore();
        initTopology3DCanvas();
        setupWindowResizeHandler();
    });

    // ==========================================================================
    // 1. HERO 3D VISUAL: TRANSLUCENT GLASS AI INTELLIGENCE CORE
    // ==========================================================================
    function initHero3DAICore() {
        const container = document.getElementById("three-canvas-container");
        if (!container) return;

        const width = container.clientWidth || 600;
        const height = container.clientHeight || 540;

        // Scene & Camera
        heroScene = new THREE.Scene();
        heroScene.fog = new THREE.FogExp2(0x080808, 0.002);

        heroCamera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
        heroCamera.position.set(0, 0, 85);

        // Renderer
        heroRenderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
        heroRenderer.setSize(width, height);
        heroRenderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        container.appendChild(heroRenderer.domElement);

        // Lighting
        const ambientLight = new THREE.AmbientLight(0xf5f2ea, 0.8);
        heroScene.add(ambientLight);

        const pointLightViolet = new THREE.PointLight(0x8b5cf6, 2.5, 220);
        pointLightViolet.position.set(20, 25, 35);
        heroScene.add(pointLightViolet);

        const pointLightAmber = new THREE.PointLight(0xf59e0b, 2.0, 200);
        pointLightAmber.position.set(-20, -25, -35);
        heroScene.add(pointLightAmber);

        // --- A. TRANSLUCENT GLASS AI CORE ---
        // Outer Translucent Icosahedron Shell (Pearl White)
        const icoGeo = new THREE.IcosahedronGeometry(14, 2);
        const icoMat = new THREE.MeshBasicMaterial({
            color: 0xf5f2ea,
            wireframe: true,
            transparent: true,
            opacity: 0.35
        });
        aiCoreMesh = new THREE.Mesh(icoGeo, icoMat);
        heroScene.add(aiCoreMesh);

        // Inner Solid Octahedron Core (Electric Violet)
        const octGeo = new THREE.OctahedronGeometry(8, 0);
        const octMat = new THREE.MeshPhongMaterial({
            color: 0x8b5cf6,
            emissive: 0x9333ea,
            emissiveIntensity: 0.65,
            shininess: 90,
            flatShading: true
        });
        innerCoreMesh = new THREE.Mesh(octGeo, octMat);
        heroScene.add(innerCoreMesh);

        // Concentric Orbital Rings (Warm Amber & Magenta)
        const ringGeo1 = new THREE.TorusGeometry(21, 0.35, 16, 100);
        const ringMat1 = new THREE.MeshBasicMaterial({ color: 0xf59e0b, transparent: true, opacity: 0.6 });
        ringMesh1 = new THREE.Mesh(ringGeo1, ringMat1);
        ringMesh1.rotation.x = Math.PI / 3;
        heroScene.add(ringMesh1);

        const ringGeo2 = new THREE.TorusGeometry(27, 0.25, 16, 100);
        const ringMat2 = new THREE.MeshBasicMaterial({ color: 0xd946ef, transparent: true, opacity: 0.45 });
        ringMesh2 = new THREE.Mesh(ringGeo2, ringMat2);
        ringMesh2.rotation.y = Math.PI / 4;
        heroScene.add(ringMesh2);

        // --- B. ORBITING SATELLITE NODES ---
        const satelliteData = [
            { name: "Client", radius: 36, speed: 0.008, color: 0x10b981, yOffset: 5 },
            { name: "Router", radius: 42, speed: -0.006, color: 0xf59e0b, yOffset: -8 },
            { name: "Server", radius: 48, speed: 0.005, color: 0x8b5cf6, yOffset: 12 },
            { name: "Gateway", radius: 54, speed: -0.004, color: 0xf5f2ea, yOffset: -4 }
        ];

        const satelliteGroup = new THREE.Group();
        satelliteData.forEach((sat) => {
            const geom = new THREE.SphereGeometry(2.2, 16, 16);
            const mat = new THREE.MeshStandardMaterial({
                color: sat.color,
                emissive: sat.color,
                emissiveIntensity: 0.6
            });
            const nodeMesh = new THREE.Mesh(geom, mat);
            nodeMesh.userData = { radius: sat.radius, angle: Math.random() * Math.PI * 2, speed: sat.speed, yOffset: sat.yOffset };
            satelliteGroup.add(nodeMesh);
        });
        heroScene.add(satelliteGroup);

        // --- C. PEARL & VIOLET PARTICLE CLOUD ---
        const particleCount = 220;
        const particleGeo = new THREE.BufferGeometry();
        const particlePositions = new Float32Array(particleCount * 3);

        for (let i = 0; i < particleCount * 3; i += 3) {
            particlePositions[i] = (Math.random() - 0.5) * 200;
            particlePositions[i + 1] = (Math.random() - 0.5) * 200;
            particlePositions[i + 2] = (Math.random() - 0.5) * 200;
        }

        particleGeo.setAttribute("position", new THREE.BufferAttribute(particlePositions, 3));
        const particleMat = new THREE.PointsMaterial({
            color: 0xd8b4fe,
            size: 1.2,
            transparent: true,
            opacity: 0.45
        });

        heroParticleCloud = new THREE.Points(particleGeo, particleMat);
        heroScene.add(heroParticleCloud);

        // Mouse Parallax
        let mouseX = 0, mouseY = 0;
        document.addEventListener("mousemove", (e) => {
            mouseX = (e.clientX - window.innerWidth / 2) * 0.0004;
            mouseY = (e.clientY - window.innerHeight / 2) * 0.0004;
        });

        // Animation Loop
        function animateHero() {
            requestAnimationFrame(animateHero);

            aiCoreMesh.rotation.y += 0.004;
            aiCoreMesh.rotation.x += 0.002;
            innerCoreMesh.rotation.y -= 0.006;
            ringMesh1.rotation.z += 0.005;
            ringMesh2.rotation.x += 0.003;

            satelliteGroup.children.forEach((node) => {
                node.userData.angle += node.userData.speed;
                node.position.x = Math.cos(node.userData.angle) * node.userData.radius;
                node.position.z = Math.sin(node.userData.angle) * node.userData.radius;
                node.position.y = Math.sin(node.userData.angle * 2) * node.userData.yOffset;
            });

            heroCamera.position.x += (mouseX * 25 - heroCamera.position.x) * 0.05;
            heroCamera.position.y += (-mouseY * 25 - heroCamera.position.y) * 0.05;
            heroCamera.lookAt(heroScene.position);

            heroRenderer.render(heroScene, heroCamera);
        }

        animateHero();
    }

    // Dynamic State Trigger for Hero Core (Normal vs Threat)
    window.updateHeroCoreState = function (isThreat, label) {
        if (!aiCoreMesh || !innerCoreMesh) return;

        const overlayText = document.getElementById("core-state-text");

        if (isThreat) {
            aiCoreMesh.material.color.setHex(0xf43f5e);
            innerCoreMesh.material.color.setHex(0xf43f5e);
            innerCoreMesh.material.emissive.setHex(0xf43f5e);
            ringMesh1.material.color.setHex(0xf59e0b);
            if (overlayText) {
                overlayText.textContent = `THREAT: ${label.toUpperCase()}`;
                overlayText.style.color = "#f43f5e";
            }
        } else {
            aiCoreMesh.material.color.setHex(0xf5f2ea);
            innerCoreMesh.material.color.setHex(0x8b5cf6);
            innerCoreMesh.material.emissive.setHex(0x9333ea);
            ringMesh1.material.color.setHex(0xf59e0b);
            if (overlayText) {
                overlayText.textContent = "MONITORING FLOWS";
                overlayText.style.color = "#10b981";
            }
        }
    };

    // ==========================================================================
    // 2. INTERACTIVE 3D NETWORK TOPOLOGY VISUALIZER
    // ==========================================================================
    function initTopology3DCanvas() {
        const container = document.getElementById("three-topology-container");
        if (!container) return;

        const width = container.clientWidth || 800;
        const height = container.clientHeight || 520;

        topoScene = new THREE.Scene();
        topoCamera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
        topoCamera.position.set(0, 10, 95);

        topoRenderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
        topoRenderer.setSize(width, height);
        topoRenderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        container.appendChild(topoRenderer.domElement);

        const ambientLight = new THREE.AmbientLight(0xf5f2ea, 0.7);
        topoScene.add(ambientLight);

        const nodeSpecs = [
            { id: "client", name: "Client Node", x: -45, y: 0, z: 0, color: 0x10b981 },
            { id: "router", name: "Network Router", x: -15, y: 5, z: 0, color: 0xf59e0b },
            { id: "server", name: "Server Host", x: 15, y: -5, z: 0, color: 0x6366f1 },
            { id: "ai_engine", name: "AI Detection Engine", x: 45, y: 0, z: 0, color: 0x8b5cf6 }
        ];

        const linePositions = [];

        nodeSpecs.forEach((spec) => {
            const geo = new THREE.SphereGeometry(4.5, 32, 32);
            const mat = new THREE.MeshStandardMaterial({
                color: spec.color,
                emissive: spec.color,
                emissiveIntensity: 0.5,
                metalness: 0.3,
                roughness: 0.2
            });
            const mesh = new THREE.Mesh(geo, mat);
            mesh.position.set(spec.x, spec.y, spec.z);
            topoScene.add(mesh);
            topoNodes[spec.id] = mesh;

            linePositions.push(new THREE.Vector3(spec.x, spec.y, spec.z));

            const ringGeo = new THREE.RingGeometry(5.5, 6.2, 32);
            const ringMat = new THREE.MeshBasicMaterial({ color: spec.color, side: THREE.DoubleSide, transparent: true, opacity: 0.4 });
            const ringMesh = new THREE.Mesh(ringGeo, ringMat);
            ringMesh.position.set(spec.x, spec.y, spec.z);
            topoScene.add(ringMesh);
        });

        const curve = new THREE.CatmullRomCurve3(linePositions);
        const tubeGeo = new THREE.TubeGeometry(curve, 64, 0.4, 8, false);
        const tubeMat = new THREE.MeshBasicMaterial({ color: 0x8b5cf6, transparent: true, opacity: 0.3, wireframe: true });
        const tubeMesh = new THREE.Mesh(tubeGeo, tubeMat);
        topoScene.add(tubeMesh);

        const numPackets = 18;
        for (let i = 0; i < numPackets; i++) {
            const pGeo = new THREE.SphereGeometry(0.85, 16, 16);
            const pMat = new THREE.MeshBasicMaterial({ color: 0xf59e0b });
            const particle = new THREE.Mesh(pGeo, pMat);
            particle.userData = { progress: i / numPackets, speed: 0.004 };
            topoScene.add(particle);
            packetParticles.push(particle);
        }

        function animateTopology() {
            requestAnimationFrame(animateTopology);

            packetParticles.forEach((p) => {
                p.userData.progress += p.userData.speed;
                if (p.userData.progress > 1) p.userData.progress = 0;

                const pos = curve.getPoint(p.userData.progress);
                p.position.copy(pos);
            });

            topoCamera.lookAt(topoScene.position);
            topoRenderer.render(topoScene, topoCamera);
        }

        animateTopology();
    }

    // Dynamic State Trigger for Topology Visualizer
    window.update3DTopologyState = function (isThreat, label) {
        const badge = document.getElementById("topology-state-badge");
        const badgeText = document.getElementById("topo-badge-text");
        const badgeIcon = document.getElementById("topo-badge-icon");

        if (typeof window.updateHeroCoreState === "function") {
            window.updateHeroCoreState(isThreat, label);
        }

        if (!badge) return;

        if (isThreat) {
            badge.className = "topology-state-badge attack-badge";
            if (badgeText) badgeText.textContent = `THREAT DETECTED: ${label.toUpperCase()}`;
            if (badgeIcon) badgeIcon.className = "fa-solid fa-triangle-exclamation";

            packetParticles.forEach((p) => {
                p.material.color.setHex(0xf43f5e);
                p.userData.speed = 0.009;
            });

            if (topoNodes.ai_engine) topoNodes.ai_engine.material.color.setHex(0xf43f5e);
        } else {
            badge.className = "topology-state-badge secure-badge";
            if (badgeText) badgeText.textContent = "NETWORK SECURE";
            if (badgeIcon) badgeIcon.className = "fa-solid fa-shield-check";

            packetParticles.forEach((p) => {
                p.material.color.setHex(0xf59e0b);
                p.userData.speed = 0.004;
            });

            if (topoNodes.ai_engine) topoNodes.ai_engine.material.color.setHex(0x8b5cf6);
        }
    };

    // Window Resize Handler
    function setupWindowResizeHandler() {
        window.addEventListener("resize", () => {
            const heroContainer = document.getElementById("three-canvas-container");
            if (heroContainer && heroRenderer && heroCamera) {
                const w = heroContainer.clientWidth;
                const h = heroContainer.clientHeight;
                heroCamera.aspect = w / h;
                heroCamera.updateProjectionMatrix();
                heroRenderer.setSize(w, h);
            }

            const topoContainer = document.getElementById("three-topology-container");
            if (topoContainer && topoRenderer && topoCamera) {
                const w = topoContainer.clientWidth;
                const h = topoContainer.clientHeight;
                topoCamera.aspect = w / h;
                topoCamera.updateProjectionMatrix();
                topoRenderer.setSize(w, h);
            }
        });
    }
})();
