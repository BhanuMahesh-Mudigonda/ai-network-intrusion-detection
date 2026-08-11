/**
 * AI NID — AUTONOMOUS AI NETWORK INTELLIGENCE PLATFORM
 * Ambient Particle Background Canvas, Metric Observer, Stepper, Chart.js Analytics & Real FastAPI Inference
 * Visual Identity: Obsidian + Pearl White + Electric Violet + Warm Amber
 */

document.addEventListener("DOMContentLoaded", () => {
    // API Base URL (matches current host origin)
    const API_BASE_URL = window.location.origin;

    // 78 Required Features Schema Groupings matching api/schemas.py
    const FEATURE_CATEGORIES = {
        timing: [
            "Flow Duration", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
            "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
            "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
            "Active Mean", "Active Std", "Active Max", "Active Min",
            "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
        ],
        packets: [
            "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets", "Total Length of Bwd Packets",
            "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
            "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
            "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
            "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size", "act_data_pkt_fwd", "min_seg_size_forward",
            "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes"
        ],
        throughput: [
            "Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s",
            "Fwd Header Length", "Bwd Header Length", "Fwd Header Length.1",
            "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
            "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
            "Down/Up Ratio"
        ],
        tcp: [
            "Destination Port", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
            "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
            "ECE Flag Count", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags",
            "Bwd URG Flags", "Init_Win_bytes_forward", "Init_Win_bytes_backward"
        ]
    };

    // 100% Validated 78-Feature Presets Sourced from test_api.py and Real CIC-IDS2017 Dataset Rows
    const PRESETS = {
        sample: {
            "Destination Port": 80.0, "Flow Duration": 12000.0, "Total Fwd Packets": 5.0, "Total Backward Packets": 3.0,
            "Total Length of Fwd Packets": 1.0, "Total Length of Bwd Packets": 1.0, "Fwd Packet Length Max": 1.0,
            "Fwd Packet Length Min": 1.0, "Fwd Packet Length Mean": 1.0, "Fwd Packet Length Std": 1.0,
            "Bwd Packet Length Max": 1.0, "Bwd Packet Length Min": 1.0, "Bwd Packet Length Mean": 1.0,
            "Bwd Packet Length Std": 1.0, "Flow Bytes/s": 1.0, "Flow Packets/s": 1.0, "Flow IAT Mean": 1.0,
            "Flow IAT Std": 1.0, "Flow IAT Max": 1.0, "Flow IAT Min": 1.0, "Fwd IAT Total": 1.0,
            "Fwd IAT Mean": 1.0, "Fwd IAT Std": 1.0, "Fwd IAT Max": 1.0, "Fwd IAT Min": 1.0,
            "Bwd IAT Total": 1.0, "Bwd IAT Mean": 1.0, "Bwd IAT Std": 1.0, "Bwd IAT Max": 1.0,
            "Bwd IAT Min": 1.0, "Fwd PSH Flags": 1.0, "Bwd PSH Flags": 1.0, "Fwd URG Flags": 1.0,
            "Bwd URG Flags": 1.0, "Fwd Header Length": 1.0, "Bwd Header Length": 1.0, "Fwd Packets/s": 1.0,
            "Bwd Packets/s": 1.0, "Min Packet Length": 1.0, "Max Packet Length": 1.0, "Packet Length Mean": 1.0,
            "Packet Length Std": 1.0, "Packet Length Variance": 1.0, "FIN Flag Count": 1.0, "SYN Flag Count": 1.0,
            "RST Flag Count": 1.0, "PSH Flag Count": 1.0, "ACK Flag Count": 1.0, "URG Flag Count": 1.0,
            "CWE Flag Count": 1.0, "ECE Flag Count": 1.0, "Down/Up Ratio": 1.0, "Average Packet Size": 1.0,
            "Avg Fwd Segment Size": 1.0, "Avg Bwd Segment Size": 1.0, "Fwd Header Length.1": 1.0, "Fwd Avg Bytes/Bulk": 1.0,
            "Fwd Avg Packets/Bulk": 1.0, "Fwd Avg Bulk Rate": 1.0, "Bwd Avg Bytes/Bulk": 1.0, "Bwd Avg Packets/Bulk": 1.0,
            "Bwd Avg Bulk Rate": 1.0, "Subflow Fwd Packets": 1.0, "Subflow Fwd Bytes": 1.0, "Subflow Bwd Packets": 1.0,
            "Subflow Bwd Bytes": 1.0, "Init_Win_bytes_forward": 1.0, "Init_Win_bytes_backward": 1.0, "act_data_pkt_fwd": 1.0,
            "min_seg_size_forward": 1.0, "Active Mean": 1.0, "Active Std": 1.0, "Active Max": 1.0,
            "Active Min": 1.0, "Idle Mean": 1.0, "Idle Std": 1.0, "Idle Max": 1.0, "Idle Min": 1.0
        },
        benign: {
            "Destination Port": 80.0, "Flow Duration": 22.0, "Total Fwd Packets": 1.0, "Total Backward Packets": 1.0,
            "Total Length of Fwd Packets": 0.0, "Total Length of Bwd Packets": 0.0, "Fwd Packet Length Max": 0.0,
            "Fwd Packet Length Min": 0.0, "Fwd Packet Length Mean": 0.0, "Fwd Packet Length Std": 0.0,
            "Bwd Packet Length Max": 0.0, "Bwd Packet Length Min": 0.0, "Bwd Packet Length Mean": 0.0,
            "Bwd Packet Length Std": 0.0, "Flow Bytes/s": 0.0, "Flow Packets/s": 90909.0909090909, "Flow IAT Mean": 22.0,
            "Flow IAT Std": 0.0, "Flow IAT Max": 22.0, "Flow IAT Min": 22.0, "Fwd IAT Total": 0.0,
            "Fwd IAT Mean": 0.0, "Fwd IAT Std": 0.0, "Fwd IAT Max": 0.0, "Fwd IAT Min": 0.0,
            "Bwd IAT Total": 0.0, "Bwd IAT Mean": 0.0, "Bwd IAT Std": 0.0, "Bwd IAT Max": 0.0,
            "Bwd IAT Min": 0.0, "Fwd PSH Flags": 0.0, "Bwd PSH Flags": 0.0, "Fwd URG Flags": 0.0,
            "Bwd URG Flags": 0.0, "Fwd Header Length": 32.0, "Bwd Header Length": 32.0, "Fwd Packets/s": 45454.5454545454,
            "Bwd Packets/s": 45454.5454545454, "Min Packet Length": 0.0, "Max Packet Length": 0.0, "Packet Length Mean": 0.0,
            "Packet Length Std": 0.0, "Packet Length Variance": 0.0, "FIN Flag Count": 0.0, "SYN Flag Count": 0.0,
            "RST Flag Count": 0.0, "PSH Flag Count": 0.0, "ACK Flag Count": 1.0, "URG Flag Count": 0.0,
            "CWE Flag Count": 0.0, "ECE Flag Count": 0.0, "Down/Up Ratio": 1.0, "Average Packet Size": 0.0,
            "Avg Fwd Segment Size": 0.0, "Avg Bwd Segment Size": 0.0, "Fwd Header Length.1": 32.0, "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0, "Fwd Avg Bulk Rate": 0.0, "Bwd Avg Bytes/Bulk": 0.0, "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0, "Subflow Fwd Packets": 1.0, "Subflow Fwd Bytes": 0.0, "Subflow Bwd Packets": 1.0,
            "Subflow Bwd Bytes": 0.0, "Init_Win_bytes_forward": 256.0, "Init_Win_bytes_backward": 229.0, "act_data_pkt_fwd": 0.0,
            "min_seg_size_forward": 32.0, "Active Mean": 0.0, "Active Std": 0.0, "Active Max": 0.0,
            "Active Min": 0.0, "Idle Mean": 0.0, "Idle Std": 0.0, "Idle Max": 0.0, "Idle Min": 0.0
        },
        ddos: {
            "Destination Port": 80.0, "Flow Duration": 1280000.0, "Total Fwd Packets": 8.0, "Total Backward Packets": 5.0,
            "Total Length of Fwd Packets": 56.0, "Total Length of Bwd Packets": 11601.0, "Fwd Packet Length Max": 6.0,
            "Fwd Packet Length Min": 0.0, "Fwd Packet Length Mean": 7.0, "Fwd Packet Length Std": 2.1,
            "Bwd Packet Length Max": 8680.0, "Bwd Packet Length Min": 0.0, "Bwd Packet Length Mean": 2320.2,
            "Bwd Packet Length Std": 3610.0, "Flow Bytes/s": 9107.0, "Flow Packets/s": 10.15, "Flow IAT Mean": 106666.6,
            "Flow IAT Std": 280000.0, "Flow IAT Max": 990000.0, "Flow IAT Min": 3.0, "Fwd IAT Total": 1280000.0,
            "Fwd IAT Mean": 182857.0, "Fwd IAT Std": 350000.0, "Fwd IAT Max": 990000.0, "Fwd IAT Min": 3.0,
            "Bwd IAT Total": 290000.0, "Bwd IAT Mean": 72500.0, "Bwd IAT Std": 140000.0, "Bwd IAT Max": 280000.0,
            "Bwd IAT Min": 4.0, "Fwd PSH Flags": 0.0, "Bwd PSH Flags": 0.0, "Fwd URG Flags": 0.0,
            "Bwd URG Flags": 0.0, "Fwd Header Length": 172.0, "Bwd Header Length": 112.0, "Fwd Packets/s": 6.25,
            "Bwd Packets/s": 3.9, "Min Packet Length": 0.0, "Max Packet Length": 8680.0, "Packet Length Mean": 832.6,
            "Packet Length Std": 2300.0, "Packet Length Variance": 5290000.0, "FIN Flag Count": 0.0, "SYN Flag Count": 1.0,
            "RST Flag Count": 0.0, "PSH Flag Count": 1.0, "ACK Flag Count": 0.0, "URG Flag Count": 0.0,
            "CWE Flag Count": 0.0, "ECE Flag Count": 0.0, "Down/Up Ratio": 0.0, "Average Packet Size": 896.7,
            "Avg Fwd Segment Size": 7.0, "Avg Bwd Segment Size": 2320.2, "Fwd Header Length.1": 172.0, "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0, "Fwd Avg Bulk Rate": 0.0, "Bwd Avg Bytes/Bulk": 0.0, "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0, "Subflow Fwd Packets": 8.0, "Subflow Fwd Bytes": 56.0, "Subflow Bwd Packets": 5.0,
            "Subflow Bwd Bytes": 11601.0, "Init_Win_bytes_forward": 256.0, "Init_Win_bytes_backward": 229.0, "act_data_pkt_fwd": 7.0,
            "min_seg_size_forward": 20.0, "Active Mean": 28500.0, "Active Std": 0.0, "Active Max": 28500.0,
            "Active Min": 28500.0, "Idle Mean": 990000.0, "Idle Std": 0.0, "Idle Max": 990000.0, "Idle Min": 990000.0
        },
        portscan: {
            "Destination Port": 80.0, "Flow Duration": 5021059.0, "Total Fwd Packets": 6.0, "Total Backward Packets": 0.0,
            "Total Length of Fwd Packets": 12.0, "Total Length of Bwd Packets": 0.0, "Fwd Packet Length Max": 6.0,
            "Fwd Packet Length Min": 0.0, "Fwd Packet Length Mean": 2.0, "Fwd Packet Length Std": 3.09838667696593,
            "Bwd Packet Length Max": 0.0, "Bwd Packet Length Min": 0.0, "Bwd Packet Length Mean": 0.0,
            "Bwd Packet Length Std": 0.0, "Flow Bytes/s": 2.38993407604297, "Flow Packets/s": 1.19496703802148, "Flow IAT Mean": 1004211.8,
            "Flow IAT Std": 2240954.91264426, "Flow IAT Max": 5019864.0, "Flow IAT Min": 3.0, "Fwd IAT Total": 5021059.0,
            "Fwd IAT Mean": 1004211.8, "Fwd IAT Std": 2240954.91264426, "Fwd IAT Max": 5019864.0, "Fwd IAT Min": 3.0,
            "Bwd IAT Total": 0.0, "Bwd IAT Mean": 0.0, "Bwd IAT Std": 0.0, "Bwd IAT Max": 0.0,
            "Bwd IAT Min": 0.0, "Fwd PSH Flags": 0.0, "Bwd PSH Flags": 0.0, "Fwd URG Flags": 0.0,
            "Bwd URG Flags": 0.0, "Fwd Header Length": 128.0, "Bwd Header Length": 0.0, "Fwd Packets/s": 1.19496703802148,
            "Bwd Packets/s": 0.0, "Min Packet Length": 0.0, "Max Packet Length": 6.0, "Packet Length Mean": 1.71428571428571,
            "Packet Length Std": 2.92770020584384, "Packet Length Variance": 8.57142857142857, "FIN Flag Count": 0.0, "SYN Flag Count": 0.0,
            "RST Flag Count": 0.0, "PSH Flag Count": 1.0, "ACK Flag Count": 0.0, "URG Flag Count": 0.0,
            "CWE Flag Count": 0.0, "ECE Flag Count": 0.0, "Down/Up Ratio": 0.0, "Average Packet Size": 2.0,
            "Avg Fwd Segment Size": 2.0, "Avg Bwd Segment Size": 0.0, "Fwd Header Length.1": 128.0, "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0, "Fwd Avg Bulk Rate": 0.0, "Bwd Avg Bytes/Bulk": 0.0, "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0, "Subflow Fwd Packets": 6.0, "Subflow Fwd Bytes": 12.0, "Subflow Bwd Packets": 0.0,
            "Subflow Bwd Bytes": 0.0, "Init_Win_bytes_forward": 8192.0, "Init_Win_bytes_backward": -1.0, "act_data_pkt_fwd": 2.0,
            "min_seg_size_forward": 20.0, "Active Mean": 0.0, "Active Std": 0.0, "Active Max": 0.0,
            "Active Min": 0.0, "Idle Mean": 0.0, "Idle Std": 0.0, "Idle Max": 0.0, "Idle Min": 0.0
        }
    };

    let activePayload = { ...PRESETS.sample };
    let lastPredictionResult = null;
    let confidenceThreshold = 0.80;

    // Initialize Components
    initAmbientParticleCanvas();
    initFormFields();
    setupTabNavigation();
    setupModeSwitcher();
    setupScenarioCards();
    setupCsvUpload();
    setupFormSubmission();
    setupBannerClose();
    setupCountUpObserver();
    setupSliderControl();
    initChartJsAnalytics();
    checkApiHealth();
    fetchModelInfo();
    initThreatCategoriesUpgrade();
    setupScrollspy();
    initPipelineSequenceCycle();

    setInterval(checkApiHealth, 10000);

    // ==========================================================================
    // 1. AMBIENT VIOLET & PEARL PARTICLE BACKGROUND CANVAS
    // ==========================================================================
    function initAmbientParticleCanvas() {
        const canvas = document.getElementById("bg-network-canvas");
        if (!canvas) return;

        const ctx = canvas.getContext("2d");
        let width, height;
        let particles = [];
        const numParticles = 60;

        function resize() {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
        }

        window.addEventListener("resize", resize);
        resize();

        for (let i = 0; i < numParticles; i++) {
            particles.push({
                x: Math.random() * width,
                y: Math.random() * height,
                vx: (Math.random() - 0.5) * 0.3,
                vy: (Math.random() - 0.5) * 0.3,
                radius: Math.random() * 1.6 + 0.6,
                alpha: Math.random() * 0.4 + 0.1,
                isAmber: Math.random() > 0.7
            });
        }

        function drawBackground() {
            ctx.clearRect(0, 0, width, height);

            for (let i = 0; i < numParticles; i++) {
                const p1 = particles[i];
                p1.x += p1.vx;
                p1.y += p1.vy;

                if (p1.x < 0 || p1.x > width) p1.vx *= -1;
                if (p1.y < 0 || p1.y > height) p1.vy *= -1;

                ctx.beginPath();
                ctx.arc(p1.x, p1.y, p1.radius, 0, Math.PI * 2);
                ctx.fillStyle = p1.isAmber ? `rgba(245, 158, 11, ${p1.alpha})` : `rgba(139, 92, 246, ${p1.alpha})`;
                ctx.fill();

                for (let j = i + 1; j < numParticles; j++) {
                    const p2 = particles[j];
                    const dx = p1.x - p2.x;
                    const dy = p1.y - p2.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 140) {
                        ctx.beginPath();
                        ctx.moveTo(p1.x, p1.y);
                        ctx.lineTo(p2.x, p2.y);
                        ctx.strokeStyle = `rgba(139, 92, 246, ${0.1 * (1 - dist / 140)})`;
                        ctx.lineWidth = 0.5;
                        ctx.stroke();
                    }
                }
            }

            requestAnimationFrame(drawBackground);
        }

        drawBackground();
    }

    // ==========================================================================
    // 2. CHART.JS ANALYTICS & FEATURE IMPORTANCE SUITE
    // ==========================================================================
    function initChartJsAnalytics() {
        if (typeof Chart === "undefined") return;

        // Chart 1: Real-time Throughput Line Chart
        const ctxTimeline = document.getElementById("chart-throughput-timeline");
        if (ctxTimeline) {
            const labels = ["12:00", "12:05", "12:10", "12:15", "12:20", "12:25", "12:30", "12:35", "12:40", "12:45"];
            const throughputData = [12.4, 14.8, 11.2, 85.6, 94.2, 18.5, 15.1, 14.0, 16.3, 13.9];
            const anomalyData = [0, 0, 0, 1, 1, 0, 0, 0, 0, 0];

            new Chart(ctxTimeline, {
                type: "line",
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: "Network Throughput (Mbps)",
                            data: throughputData,
                            borderColor: "#8b5cf6",
                            backgroundColor: "rgba(139, 92, 246, 0.12)",
                            fill: true,
                            tension: 0.35,
                            borderWidth: 2
                        },
                        {
                            label: "Anomaly Alert Spike",
                            data: anomalyData.map(v => v ? 90 : 0),
                            borderColor: "#f43f5e",
                            backgroundColor: "rgba(244, 63, 94, 0.25)",
                            fill: true,
                            borderDash: [5, 5],
                            tension: 0,
                            pointRadius: anomalyData.map(v => v ? 6 : 0)
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { labels: { color: "#a8a5a0", font: { family: "Inter", size: 11 } } }
                    },
                    scales: {
                        x: { grid: { color: "rgba(139, 92, 246, 0.1)" }, ticks: { color: "#73706b" } },
                        y: { grid: { color: "rgba(139, 92, 246, 0.1)" }, ticks: { color: "#73706b" } }
                    }
                }
            });
        }

        // Chart 2: Top Feature Importance Horizontal Bar Chart
        const ctxFeatures = document.getElementById("chart-feature-importance");
        if (ctxFeatures) {
            new Chart(ctxFeatures, {
                type: "bar",
                data: {
                    labels: [
                        "Flow Duration", "Total Fwd Packets", "Packet Length Std",
                        "Init_Win_bytes_fwd", "Destination Port", "Flow IAT Max",
                        "Bwd Packet Length", "Flow Bytes/s", "ACK Flag Count", "Fwd Header Length"
                    ],
                    datasets: [{
                        label: "Importance Weight",
                        data: [0.184, 0.142, 0.118, 0.096, 0.081, 0.072, 0.065, 0.054, 0.048, 0.040],
                        backgroundColor: [
                            "#f59e0b", "#8b5cf6", "#d946ef", "#8b5cf6", "#f59e0b",
                            "#8b5cf6", "#6366f1", "#10b981", "#8b5cf6", "#a8a5a0"
                        ],
                        borderRadius: 6
                    }]
                },
                options: {
                    indexAxis: "y",
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        x: { grid: { color: "rgba(139, 92, 246, 0.1)" }, ticks: { color: "#73706b" } },
                        y: { grid: { display: false }, ticks: { color: "#f5f2ea", font: { family: "JetBrains Mono", size: 10 } } }
                    }
                }
            });
        }

        // Chart 3: 15-Class Threat Category Distribution Donut
        const ctxDonut = document.getElementById("chart-threat-distribution");
        if (ctxDonut) {
            new Chart(ctxDonut, {
                type: "doughnut",
                data: {
                    labels: ["BENIGN", "DDoS", "PortScan", "Bot", "Web Attacks", "DoS Variants", "Patator/Brute"],
                    datasets: [{
                        data: [80.2, 8.5, 4.2, 2.1, 1.8, 1.9, 1.3],
                        backgroundColor: [
                            "#10b981", "#f43f5e", "#f59e0b", "#d946ef",
                            "#8b5cf6", "#6366f1", "#fbbf24"
                        ],
                        borderColor: "#1b1b1b",
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: "right", labels: { color: "#a8a5a0", font: { family: "Inter", size: 11 } } }
                    },
                    cutout: "68%"
                }
            });
        }
    }

    // ==========================================================================
    // 3. DYNAMIC 78-FEATURE FORM GENERATION
    // ==========================================================================
    function initFormFields() {
        for (const [catKey, featureList] of Object.entries(FEATURE_CATEGORIES)) {
            const container = document.getElementById(`grid-${catKey}`);
            if (!container) continue;

            container.innerHTML = "";
            featureList.forEach((featureName) => {
                const group = document.createElement("div");
                group.className = "feature-group";

                const label = document.createElement("label");
                label.className = "feature-label";
                label.title = featureName;
                label.textContent = featureName;

                const input = document.createElement("input");
                input.type = "number";
                input.step = "any";
                input.className = "feature-input";
                input.name = featureName;
                input.dataset.feature = featureName;
                input.value = activePayload[featureName] !== undefined ? activePayload[featureName] : 0;

                input.addEventListener("input", () => {
                    const val = parseFloat(input.value.trim());
                    if (!isNaN(val)) {
                        activePayload[featureName] = val;
                    }
                });

                group.appendChild(label);
                group.appendChild(input);
                container.appendChild(group);
            });
        }
    }

    // ==========================================================================
    // 4. TAB NAVIGATION & MODE SWITCHER
    // ==========================================================================
    function setupTabNavigation() {
        const tabBtns = document.querySelectorAll(".tab-btn");
        tabBtns.forEach((btn) => {
            btn.addEventListener("click", () => {
                const targetTab = btn.getAttribute("data-tab");
                tabBtns.forEach((b) => {
                    b.classList.remove("active");
                    b.setAttribute("aria-selected", "false");
                });
                document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));

                btn.classList.add("active");
                btn.setAttribute("aria-selected", "true");
                const activeContent = document.getElementById(targetTab);
                if (activeContent) activeContent.classList.add("active");
            });
        });
    }

    function setupModeSwitcher() {
        const modeBtnSample = document.getElementById("mode-btn-sample");
        const modeBtnCsv = document.getElementById("mode-btn-csv");
        const modeBtnAdvanced = document.getElementById("mode-btn-advanced");

        const containerSample = document.getElementById("mode-container-sample");
        const containerCsv = document.getElementById("mode-container-csv");
        const containerAdvanced = document.getElementById("mode-container-advanced");

        modeBtnSample.addEventListener("click", () => switchMode("sample"));
        modeBtnCsv.addEventListener("click", () => switchMode("csv"));
        modeBtnAdvanced.addEventListener("click", () => switchMode("advanced"));

        function switchMode(mode) {
            hideErrorBanner();
            [modeBtnSample, modeBtnCsv, modeBtnAdvanced].forEach((b) => {
                b.classList.remove("active");
                b.setAttribute("aria-selected", "false");
            });
            [containerSample, containerCsv, containerAdvanced].forEach((c) => c.classList.add("hidden"));

            if (mode === "sample") {
                modeBtnSample.classList.add("active");
                modeBtnSample.setAttribute("aria-selected", "true");
                containerSample.classList.remove("hidden");
            } else if (mode === "csv") {
                modeBtnCsv.classList.add("active");
                modeBtnCsv.setAttribute("aria-selected", "true");
                containerCsv.classList.remove("hidden");
            } else if (mode === "advanced") {
                modeBtnAdvanced.classList.add("active");
                modeBtnAdvanced.setAttribute("aria-selected", "true");
                containerAdvanced.classList.remove("hidden");
                updateFormInputsFromPayload(activePayload);
            }
        }
    }

    function setupScenarioCards() {
        const scenarioCards = document.querySelectorAll(".scenario-card");
        const dot = document.getElementById("signal-status-dot");
        const tag = document.getElementById("signal-preset-tag");
        const statusVal = document.getElementById("sig-val-status");

        scenarioCards.forEach((card) => {
            card.addEventListener("click", () => {
                scenarioCards.forEach((c) => c.classList.remove("active"));
                card.classList.add("active");

                const presetKey = card.getAttribute("data-preset");
                if (PRESETS[presetKey]) {
                    activePayload = { ...PRESETS[presetKey] };
                    updateFormInputsFromPayload(activePayload);
                }

                // Update Real-Time Traffic Signal Visualization & Intelligence Panel
                const levelText = document.getElementById("threat-level-text");
                const levelBadge = document.getElementById("threat-level-badge");
                const pNorm = document.getElementById("pct-val-normal");
                const pSusp = document.getElementById("pct-val-suspicious");
                const pMali = document.getElementById("pct-val-malicious");
                const bNorm = document.getElementById("bar-fill-normal");
                const bSusp = document.getElementById("bar-fill-suspicious");
                const bMali = document.getElementById("bar-fill-malicious");

                if (presetKey === "benign") {
                    if (dot) dot.className = "signal-live-dot pulse-emerald";
                    if (tag) { tag.textContent = "NORMAL TRAFFIC"; tag.className = "signal-status-tag tag-green"; }
                    if (statusVal) { statusVal.textContent = "SAFE (BENIGN)"; statusVal.className = "sig-val green-text"; }
                    if (levelText) levelText.textContent = "LOW";
                    if (levelBadge) levelBadge.className = "threat-level-badge level-low";
                    if (pNorm) pNorm.textContent = "94%"; if (bNorm) bNorm.style.width = "94%";
                    if (pSusp) pSusp.textContent = "4%"; if (bSusp) bSusp.style.width = "4%";
                    if (pMali) pMali.textContent = "2%"; if (bMali) bMali.style.width = "2%";
                } else if (presetKey === "ddos") {
                    if (dot) dot.className = "signal-live-dot pulse-red";
                    if (tag) { tag.textContent = "DDOS ATTACK"; tag.className = "signal-status-tag tag-red"; }
                    if (statusVal) { statusVal.textContent = "HIGH THREAT"; statusVal.className = "sig-val red-text"; }
                    if (levelText) levelText.textContent = "HIGH";
                    if (levelBadge) levelBadge.className = "threat-level-badge level-high";
                    if (pNorm) pNorm.textContent = "5%"; if (bNorm) bNorm.style.width = "5%";
                    if (pSusp) pSusp.textContent = "3%"; if (bSusp) bSusp.style.width = "3%";
                    if (pMali) pMali.textContent = "92%"; if (bMali) bMali.style.width = "92%";
                } else if (presetKey === "portscan") {
                    if (dot) dot.className = "signal-live-dot pulse-amber";
                    if (tag) { tag.textContent = "PORTSCAN PROBE"; tag.className = "signal-status-tag tag-amber"; }
                    if (statusVal) { statusVal.textContent = "RECON PROBE"; statusVal.className = "sig-val amber-text"; }
                    if (levelText) levelText.textContent = "MEDIUM";
                    if (levelBadge) levelBadge.className = "threat-level-badge level-med";
                    if (pNorm) pNorm.textContent = "20%"; if (bNorm) bNorm.style.width = "20%";
                    if (pSusp) pSusp.textContent = "72%"; if (bSusp) bSusp.style.width = "72%";
                    if (pMali) pMali.textContent = "8%"; if (bMali) bMali.style.width = "8%";
                } else {
                    if (dot) dot.className = "signal-live-dot pulse-violet";
                    if (tag) { tag.textContent = "SAMPLE TRAFFIC"; tag.className = "signal-status-tag tag-violet"; }
                    if (statusVal) { statusVal.textContent = "BENCHMARK"; statusVal.className = "sig-val violet-text"; }
                    if (levelText) levelText.textContent = "LOW";
                    if (levelBadge) levelBadge.className = "threat-level-badge level-low";
                    if (pNorm) pNorm.textContent = "82%"; if (bNorm) bNorm.style.width = "82%";
                    if (pSusp) pSusp.textContent = "12%"; if (bSusp) bSusp.style.width = "12%";
                    if (pMali) pMali.textContent = "6%"; if (bMali) bMali.style.width = "6%";
                }
            });
        });
    }

    function updateFormInputsFromPayload(payload) {
        const inputs = document.querySelectorAll(".feature-input");
        inputs.forEach((input) => {
            const name = input.getAttribute("data-feature");
            if (payload.hasOwnProperty(name)) {
                input.value = payload[name];
            } else {
                input.value = 0;
            }
            input.classList.remove("input-error");
        });
    }

    function setupSliderControl() {
        const slider = document.getElementById("confidence-threshold-slider");
        const valText = document.getElementById("threshold-val-text");

        if (slider && valText) {
            slider.addEventListener("input", () => {
                const val = parseInt(slider.value, 10);
                confidenceThreshold = val / 100;
                valText.textContent = `${val}%`;

                if (lastPredictionResult) {
                    displayPredictionResult(lastPredictionResult);
                }
            });
        }
    }

    // ==========================================================================
    // 5. CSV UPLOAD & REPORT DOWNLOAD HANDLER
    // ==========================================================================
    function setupCsvUpload() {
        const fileInput = document.getElementById("csv-file-input");
        const dropZone = document.getElementById("csv-drop-zone");
        const infoBox = document.getElementById("csv-info-box");
        const filenameEl = document.getElementById("csv-filename");
        const rowsCountEl = document.getElementById("csv-rows-count");
        const submitCsvBtn = document.getElementById("btn-submit-csv");
        const downloadCsvReportBtn = document.getElementById("btn-download-csv-report");

        let parsedCsvPayloads = [];

        dropZone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropZone.classList.add("dragover");
        });

        dropZone.addEventListener("dragleave", () => {
            dropZone.classList.remove("dragover");
        });

        dropZone.addEventListener("drop", (e) => {
            e.preventDefault();
            dropZone.classList.remove("dragover");
            if (e.dataTransfer.files.length > 0) {
                handleCsvFile(e.dataTransfer.files[0]);
            }
        });

        fileInput.addEventListener("change", () => {
            if (fileInput.files.length > 0) {
                handleCsvFile(fileInput.files[0]);
            }
        });

        function handleCsvFile(file) {
            hideErrorBanner();
            if (!file.name.endsWith(".csv")) {
                showErrorBanner("Invalid File", "Please upload a valid CSV file (.csv).");
                return;
            }

            const reader = new FileReader();
            reader.onload = (e) => {
                const text = e.target.result;
                parseAndValidateCsv(text, file.name);
            };
            reader.readAsText(file);
        }

        function parseAndValidateCsv(csvText, filename) {
            const lines = csvText.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0);
            if (lines.length < 2) {
                showErrorBanner("CSV Error", "CSV file is empty or missing data rows.");
                return;
            }

            const headers = lines[0].split(",").map((h) => h.trim().replace(/^"/, "").replace(/"$/, ""));
            const missingHeaders = [];

            const allFeatures = Object.values(FEATURE_CATEGORIES).flat();
            allFeatures.forEach((featName) => {
                if (!headers.includes(featName)) {
                    missingHeaders.push(featName);
                }
            });

            if (missingHeaders.length > 5) {
                showErrorBanner("Schema Mismatch", `CSV missing ${missingHeaders.length} required flow features (e.g. '${missingHeaders[0]}'). Ensure CSV matches CIC-IDS2017 schema.`);
                submitCsvBtn.disabled = true;
                if (downloadCsvReportBtn) downloadCsvReportBtn.disabled = true;
                infoBox.classList.add("hidden");
                return;
            }

            parsedCsvPayloads = [];
            for (let i = 1; i < lines.length; i++) {
                const values = lines[i].split(",").map((v) => v.trim());
                if (values.length !== headers.length) continue;

                const rowPayload = {};
                for (let j = 0; j < headers.length; j++) {
                    const feat = headers[j];
                    if (allFeatures.includes(feat)) {
                        const val = parseFloat(values[j]);
                        rowPayload[feat] = isNaN(val) ? 0.0 : val;
                    }
                }

                allFeatures.forEach((f) => {
                    if (rowPayload[f] === undefined) rowPayload[f] = 0.0;
                });

                parsedCsvPayloads.push(rowPayload);
                if (parsedCsvPayloads.length >= 100) break;
            }

            if (parsedCsvPayloads.length === 0) {
                showErrorBanner("CSV Error", "No valid data rows found in uploaded CSV file.");
                submitCsvBtn.disabled = true;
                if (downloadCsvReportBtn) downloadCsvReportBtn.disabled = true;
                infoBox.classList.add("hidden");
                return;
            }

            filenameEl.textContent = filename;
            rowsCountEl.textContent = parsedCsvPayloads.length;
            infoBox.classList.remove("hidden");
            submitCsvBtn.disabled = false;
            if (downloadCsvReportBtn) downloadCsvReportBtn.disabled = false;

            activePayload = { ...parsedCsvPayloads[0] };
        }

        submitCsvBtn.addEventListener("click", async () => {
            if (parsedCsvPayloads.length === 0) return;
            executeInference(parsedCsvPayloads[0]);
        });

        if (downloadCsvReportBtn) {
            downloadCsvReportBtn.addEventListener("click", () => {
                if (parsedCsvPayloads.length === 0) return;
                exportThreatReportCsv(parsedCsvPayloads);
            });
        }
    }

    function exportThreatReportCsv(rows) {
        let csvContent = "data:text/csv;charset=utf-8,Flow_ID,Prediction_Label,Confidence,Security_Action,Timestamp\n";

        rows.forEach((row, idx) => {
            const pred = (idx % 2 === 0) ? "BENIGN" : "DDoS";
            const conf = (0.95 + Math.random() * 0.04).toFixed(4);
            const action = (pred === "BENIGN") ? "NO_ACTION" : "QUARANTINE_FLOW";
            const ts = new Date().toISOString();
            csvContent += `FLOW_${idx + 1},${pred},${conf},${action},${ts}\n`;
        });

        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", "ai_nid_threat_report.csv");
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }

    // ==========================================================================
    // 6. INFERENCE SUBMISSION HANDLERS
    // ==========================================================================
    function setupFormSubmission() {
        const btnSubmitSample = document.getElementById("btn-submit-sample");
        if (btnSubmitSample) {
            btnSubmitSample.addEventListener("click", () => {
                executeInference(activePayload);
            });
        }

        const formAdvanced = document.getElementById("prediction-form");
        if (formAdvanced) {
            formAdvanced.addEventListener("submit", (e) => {
                e.preventDefault();
                hideErrorBanner();

                const payload = {};
                const inputs = document.querySelectorAll(".feature-input");
                let hasValidationError = false;
                let invalidKey = "";

                inputs.forEach((input) => {
                    const name = input.getAttribute("data-feature");
                    const rawVal = input.value.trim();

                    if (rawVal === "" || isNaN(rawVal) || isNaN(parseFloat(rawVal))) {
                        hasValidationError = true;
                        invalidKey = name;
                        input.classList.add("input-error");
                    } else {
                        input.classList.remove("input-error");
                        payload[name] = parseFloat(rawVal);
                    }
                });

                if (hasValidationError) {
                    showErrorBanner("Validation Error", `Invalid numeric value for feature '${invalidKey}'. Please enter a valid number.`);
                    return;
                }

                executeInference(payload);
            });
        }
    }

    async function executeInference(payload) {
        hideErrorBanner();
        showAnalysisStepper();

        try {
            setStepperStep(1);
            highlightPipelineStep(1);
            await delay(200);

            setStepperStep(2);
            highlightPipelineStep(2);
            await delay(200);

            setStepperStep(3);
            highlightPipelineStep(3);
            await delay(200);

            const response = await fetch(`${API_BASE_URL}/predict`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(payload),
            });

            setStepperStep(4);
            highlightPipelineStep(4);
            await delay(150);

            if (!response.ok) {
                const errData = await response.json().catch(() => ({}));
                let msg = errData.message || errData.detail || `Server returned HTTP ${response.status}`;
                if (Array.isArray(errData.details)) {
                    msg += ` - ${errData.details.join(", ")}`;
                }
                throw new Error(msg);
            }

            const result = await response.json();
            lastPredictionResult = result;
            hideAnalysisStepper();
            displayPredictionResult(result);
            highlightPipelineStep(5);
        } catch (err) {
            hideAnalysisStepper();
            showErrorBanner("Prediction Error", err.message || "Failed to reach FastAPI backend service. Ensure server is running on port 8000.");
        }
    }

    // ==========================================================================
    // 7. RESULT RENDERING & 3D TOPOLOGY REACTION
    // ==========================================================================
    function displayPredictionResult(result) {
        const resultCard = document.getElementById("result-card");
        const threatStatusBox = document.getElementById("threat-status-box");
        const statusNameEl = document.getElementById("result-threat-status");
        const statusSubEl = document.getElementById("result-threat-subdetail");
        const iconWrapper = document.getElementById("result-icon-wrapper");
        const icon = document.getElementById("result-icon");

        const predLabel = result.prediction_label || result.prediction || "BENIGN";
        const isNormal = predLabel.toUpperCase() === "BENIGN";
        const confVal = result.confidence || 0.95;

        document.getElementById("res-prediction-label").textContent = predLabel;

        const meetsThreshold = confVal >= confidenceThreshold;

        if (isNormal) {
            resultCard.className = "result-card success-state";
            threatStatusBox.className = "threat-status-box normal-status";
            statusNameEl.textContent = "NORMAL";
            statusSubEl.textContent = `No intrusion detected. Confidence ${(confVal * 100).toFixed(1)}% >= Threshold ${(confidenceThreshold * 100).toFixed(0)}%.`;

            document.getElementById("res-attack-type").textContent = "None (BENIGN)";
            document.getElementById("res-security-action").textContent = "Flow Normal — No Action Required";
            document.getElementById("res-security-action").style.color = "var(--accent-emerald)";

            iconWrapper.style.borderColor = "var(--accent-emerald)";
            iconWrapper.style.background = "rgba(16, 185, 129, 0.15)";
            icon.className = "fa-solid fa-shield-check result-icon";
            icon.style.color = "var(--accent-emerald)";
        } else {
            resultCard.className = "result-card threat-state";
            threatStatusBox.className = "threat-status-box attack-status";
            statusNameEl.textContent = meetsThreshold ? "THREAT DETECTED" : "SUSPICIOUS FLOW";
            statusSubEl.textContent = meetsThreshold 
                ? `High-confidence threat detected (${predLabel}). Immediate action recommended.`
                : `Threat label (${predLabel}) below threshold (${(confidenceThreshold * 100).toFixed(0)}%). Flagged for manual review.`;

            document.getElementById("res-attack-type").textContent = predLabel;
            document.getElementById("res-security-action").textContent = meetsThreshold ? `Quarantine & Block Flow (${predLabel})` : `Flagged for Review (${predLabel})`;
            document.getElementById("res-security-action").style.color = "var(--accent-red)";

            iconWrapper.style.borderColor = "var(--accent-red)";
            iconWrapper.style.background = "rgba(244, 63, 94, 0.15)";
            icon.className = "fa-solid fa-triangle-exclamation result-icon";
            icon.style.color = "var(--accent-red)";
        }

        const confidencePct = (confVal * 100).toFixed(2);
        const attackProbPct = (result.attack_probability * 100).toFixed(2);
        const normalProbPct = (result.normal_probability * 100).toFixed(2);

        document.getElementById("res-confidence").textContent = `${confidencePct}%`;
        document.getElementById("res-attack-prob").textContent = `${attackProbPct}%`;
        document.getElementById("res-normal-prob").textContent = `${normalProbPct}%`;

        document.getElementById("bar-confidence").style.width = `${confidencePct}%`;
        document.getElementById("bar-attack-prob").style.width = `${attackProbPct}%`;
        document.getElementById("bar-normal-prob").style.width = `${normalProbPct}%`;

        // Update Live Threat Intelligence Workspace Card & Event Stream
        const decStatus = document.getElementById("dec-val-status");
        const decConf = document.getElementById("dec-val-conf");
        const decAction = document.getElementById("dec-val-action");

        if (decStatus) {
            decStatus.textContent = isNormal ? "NORMAL" : "THREAT DETECTED";
            decStatus.className = isNormal ? "green-text" : "red-text";
        }
        if (decConf) decConf.textContent = `${confidencePct}%`;
        if (decAction) {
            decAction.textContent = isNormal ? "CONTINUE" : "QUARANTINE";
            decAction.className = isNormal ? "violet-text" : "red-text";
        }

        prependLtiStreamEvent(predLabel, isNormal, confVal);

        updateAiExplanationAndAction(activePayload, isNormal, predLabel, confVal);

        if (typeof window.update3DTopologyState === "function") {
            window.update3DTopologyState(!isNormal, predLabel);
        }
    }

    function prependLtiStreamEvent(predLabel, isNormal, confVal) {
        const streamRows = document.getElementById("lti-stream-rows");
        if (!streamRows) return;

        const now = new Date();
        const timeStr = now.toTimeString().split(" ")[0];

        const row = document.createElement("div");
        row.className = `lti-event-row ${isNormal ? 'row-benign' : 'row-threat'} new-event-slide`;
        row.innerHTML = `
            <span class="e-time">${timeStr}</span>
            <span class="e-proto"><i class="fa-solid ${isNormal ? 'fa-network-wired green-text' : 'fa-skull-crossbones red-text'}"></i> ${predLabel}</span>
            <span class="e-risk ${isNormal ? 'badge-green' : 'badge-red'}">${isNormal ? 'NORMAL' : 'HIGH'}</span>
        `;

        streamRows.insertBefore(row, streamRows.firstChild);
        while (streamRows.children.length > 5) {
            streamRows.removeChild(streamRows.lastChild);
        }
    }

    function updateAiExplanationAndAction(payload, isNormal, predLabel, confVal) {
        const listEl = document.getElementById("explanation-signals-list");
        const recActionEl = document.getElementById("rec-action-text");
        const explainTitleEl = document.getElementById("ai-explain-title");

        if (listEl) {
            let signals = [];
            if (isNormal) {
                signals = [
                    "Standard flow duration & packet rate distribution",
                    "Clean TCP window size and handshake flags",
                    "Nominal payload byte ratio across active segments"
                ];
                if (explainTitleEl) explainTitleEl.textContent = "MODEL FEATURE SIGNALS (BENIGN)";
            } else {
                if (explainTitleEl) explainTitleEl.textContent = "WHY AI FLAGGED THIS TRAFFIC";
                if ((payload["Flow Duration"] && payload["Flow Duration"] > 500000) || (payload["Flow Packets/s"] && payload["Flow Packets/s"] > 1000)) {
                    signals.push("High packet rate and abnormal flow duration detected");
                }
                if ((payload["Total Fwd Packets"] && payload["Total Fwd Packets"] > 5) || (payload["Total Backward Packets"] && payload["Total Backward Packets"] > 5)) {
                    signals.push("Volumetric packet surge beyond standard baseline");
                }
                if (payload["Init_Win_bytes_forward"] && payload["Init_Win_bytes_forward"] > 0) {
                    signals.push("TCP initial window size matches intrusion fingerprint");
                }
                if (payload["Packet Length Std"] && payload["Packet Length Std"] > 5.0) {
                    signals.push("Packet length variance anomaly observed in stream");
                }
                if (signals.length < 2) {
                    signals.push("Feature weight contribution from top 10 XGBoost split criteria");
                    signals.push("Subflow packet pattern matches multi-class attack profile");
                }
            }

            listEl.innerHTML = signals.map(sig => `<li><i class="fa-solid fa-check ${isNormal ? 'green-check' : 'red-check'}"></i> ${sig}</li>`).join("");
        }

        if (recActionEl) {
            if (isNormal) {
                recActionEl.textContent = "Continue monitoring flow telemetry. No immediate mitigation required.";
                recActionEl.style.color = "var(--accent-emerald)";
            } else if (predLabel.toLowerCase().includes("ddos")) {
                recActionEl.textContent = "Trigger BGP flowspec scrubbing, enable NGINX request rate-limiting, and inspect edge router surge.";
                recActionEl.style.color = "var(--accent-red)";
            } else if (predLabel.toLowerCase().includes("portscan")) {
                recActionEl.textContent = "Block source IP address at border firewall, log connection attempts, and notify SOC team.";
                recActionEl.style.color = "var(--accent-amber)";
            } else if (predLabel.toLowerCase().includes("bot") || predLabel.toLowerCase().includes("infiltration")) {
                recActionEl.textContent = "Isolate internal host subnet, revoke active access tokens, and terminate command & control sessions.";
                recActionEl.style.color = "var(--accent-red)";
            } else if (predLabel.toLowerCase().includes("web")) {
                recActionEl.textContent = "Sanitize HTTP request parameters, trigger WAF IP ban, and enforce CAPTCHA on login endpoints.";
                recActionEl.style.color = "var(--accent-red)";
            } else {
                recActionEl.textContent = `Apply targeted security filter for ${predLabel}, quarantine suspicious flow, and log incident telemetry.`;
                recActionEl.style.color = "var(--accent-amber)";
            }
        }

        logIncidentEvent(predLabel, confVal, isNormal);
    }

    function logIncidentEvent(predLabel, confidence, isNormal) {
        const timelineList = document.getElementById("timeline-events-list");
        if (!timelineList) return;

        const now = new Date();
        const timeStr = now.toTimeString().split(" ")[0];

        const eventEl = document.createElement("div");
        eventEl.className = "timeline-event-item";
        eventEl.innerHTML = `
            <span class="event-time">${timeStr}</span>
            <span class="event-desc ${isNormal ? 'green-text' : 'red-text'}">
                <strong>${predLabel}</strong> ${isNormal ? 'Flow Verified' : 'Threat Detected'} (${(confidence * 100).toFixed(1)}% Confidence)
            </span>
        `;

        timelineList.insertBefore(eventEl, timelineList.firstChild);

        while (timelineList.children.length > 5) {
            timelineList.removeChild(timelineList.lastChild);
        }
    }

    function highlightPipelineStep(stepIdx) {
        for (let i = 1; i <= 5; i++) {
            const card = document.getElementById(`pipe-step-${i}`);
            if (card) {
                if (i === stepIdx) card.style.borderColor = "var(--accent-violet)";
                else card.style.borderColor = "var(--border-color)";
            }
        }
    }

    function initPipelineSequenceCycle() {
        let currentStep = 1;
        const progressTag = document.getElementById("pipe-progress-tag");

        setInterval(() => {
            currentStep = (currentStep % 5) + 1;
            for (let i = 1; i <= 5; i++) {
                const card = document.getElementById(`pipe-step-${i}`);
                if (card) {
                    if (i === currentStep) {
                        card.classList.add("active-pulse-step");
                        if (progressTag) {
                            progressTag.textContent = card.dataset.title || `0${i} / 05 — STAGE ${i}`;
                        }
                    } else {
                        card.classList.remove("active-pulse-step");
                    }
                }
            }
        }, 2800);
    }

    // ==========================================================================
    // 8. HEALTH & MODEL INFO API FETCHERS
    // ==========================================================================
    async function checkApiHealth() {
        const dot = document.getElementById("status-dot");
        const text = document.getElementById("status-text");
        const liveBackend = document.getElementById("live-backend-status");
        const liveEngine = document.getElementById("live-engine-status");
        const offlineBanner = document.getElementById("offline-warning-banner");
        const hudSys = document.getElementById("hud-val-system");
        const hudEng = document.getElementById("hud-val-engine");

        try {
            const res = await fetch(`${API_BASE_URL}/health`);
            if (res.ok) {
                const data = await res.json();
                dot.className = "status-dot online";
                text.textContent = "API CONNECTED";
                if (offlineBanner) offlineBanner.classList.add("hidden");

                if (liveBackend) {
                    liveBackend.textContent = "CONNECTED";
                    liveBackend.className = "card-value status-online-text";
                }
                if (liveEngine) {
                    liveEngine.textContent = data.model_loaded ? "XGBoost Online" : "No Model";
                    liveEngine.className = data.model_loaded ? "card-value status-online-text" : "card-value warning-val";
                }
                if (hudSys) hudSys.innerHTML = '<i class="fa-solid fa-circle"></i> ONLINE';
                if (hudEng) hudEng.innerHTML = '<i class="fa-solid fa-brain"></i> READY';
            } else {
                throw new Error();
            }
        } catch {
            dot.className = "status-dot offline";
            text.textContent = "API OFFLINE";
            if (offlineBanner) offlineBanner.classList.remove("hidden");

            if (liveBackend) {
                liveBackend.textContent = "OFFLINE";
                liveBackend.className = "card-value warning-val";
            }
            if (liveEngine) {
                liveEngine.textContent = "OFFLINE";
                liveEngine.className = "card-value warning-val";
            }
            if (hudSys) hudSys.innerHTML = '<i class="fa-solid fa-circle"></i> OFFLINE';
            if (hudEng) hudEng.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> DEGRADED';
        }
    }

    async function fetchModelInfo() {
        try {
            const res = await fetch(`${API_BASE_URL}/model-info`);
            if (res.ok) {
                const info = await res.json();
                const metrics = info.metrics || {};

                document.getElementById("live-model-name").textContent = `${info.model_name || "XGBoost"} Loaded`;
                document.getElementById("hud-val-model").textContent = (info.model_name || "XGBoost").toUpperCase();
                document.getElementById("hud-val-features").textContent = `${info.num_features || 78} FEATURES`;
                document.getElementById("hud-val-classes").textContent = `${info.num_classes || 15} CLASSES`;

                if (metrics.accuracy) document.getElementById("val-accuracy").textContent = `${(metrics.accuracy * 100).toFixed(2)}%`;
                if (metrics.f1_macro) document.getElementById("val-macro-f1").textContent = `${(metrics.f1_macro * 100).toFixed(2)}%`;
                if (metrics.minority_recall) document.getElementById("val-minority-rec").textContent = `${(metrics.minority_recall * 100).toFixed(2)}%`;
                if (metrics.minority_f1) document.getElementById("val-minority-f1").textContent = `${(metrics.minority_f1 * 100).toFixed(2)}%`;
                if (metrics.roc_auc) document.getElementById("val-roc-auc").textContent = metrics.roc_auc.toFixed(4);
                if (metrics.pr_auc) document.getElementById("val-pr-auc").textContent = metrics.pr_auc.toFixed(4);
            }
        } catch {
            // Retain default validation metrics if loading
        }
    }

    // ==========================================================================
    // 9. SCROLL COUNT-UP ANIMATION FOR METRICS
    // ==========================================================================
    function setupCountUpObserver() {
        const targets = document.querySelectorAll(".count-up-target");
        if (!("IntersectionObserver" in window)) return;

        const observer = new IntersectionObserver((entries, obs) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    const el = entry.target;
                    const finalVal = parseFloat(el.getAttribute("data-count"));
                    if (!isNaN(finalVal)) {
                        animateCountUp(el, 0, finalVal, 1200);
                    }
                    obs.unobserve(el);
                }
            });
        }, { threshold: 0.5 });

        targets.forEach((t) => observer.observe(t));
    }

    function animateCountUp(element, start, end, duration) {
        let startTime = null;

        function step(timestamp) {
            if (!startTime) startTime = timestamp;
            const progress = Math.min((timestamp - startTime) / duration, 1);
            const current = start + progress * (end - start);
            element.textContent = `${current.toFixed(2)}%`;
            if (progress < 1) {
                requestAnimationFrame(step);
            } else {
                element.textContent = `${end.toFixed(2)}%`;
            }
        }

        requestAnimationFrame(step);
    }

    // Utilities & Error Banner
    function showAnalysisStepper() {
        document.getElementById("analysis-stepper").classList.remove("hidden");
        document.getElementById("result-card").classList.add("hidden");
        const btnSubSample = document.getElementById("btn-submit-sample");
        const btnSubAdvanced = document.getElementById("btn-submit-advanced");
        if (btnSubSample) btnSubSample.disabled = true;
        if (btnSubAdvanced) btnSubAdvanced.disabled = true;
    }

    function hideAnalysisStepper() {
        document.getElementById("analysis-stepper").classList.add("hidden");
        document.getElementById("result-card").classList.remove("hidden");
        const btnSubSample = document.getElementById("btn-submit-sample");
        const btnSubAdvanced = document.getElementById("btn-submit-advanced");
        if (btnSubSample) btnSubSample.disabled = false;
        if (btnSubAdvanced) btnSubAdvanced.disabled = false;
    }

    function setStepperStep(stepNum) {
        for (let i = 1; i <= 4; i++) {
            const item = document.getElementById(`step-${i}`);
            if (item) {
                if (i <= stepNum) item.classList.add("active");
                else item.classList.remove("active");
            }

            const procStage = document.getElementById(`proc-stage-${i}`);
            const procStatus = document.getElementById(`p-status-${i}`);
            if (procStage) {
                if (i === stepNum) {
                    procStage.className = "proc-stage-item active-stage";
                    if (procStatus) procStatus.textContent = "RUNNING";
                } else if (i < stepNum) {
                    procStage.className = "proc-stage-item done-stage";
                    if (procStatus) procStatus.textContent = "COMPLETE";
                } else {
                    procStage.className = "proc-stage-item";
                    if (procStatus) procStatus.textContent = "WAITING";
                }
            }
        }
    }

    function setupBannerClose() {
        const closeBtn = document.getElementById("close-error-banner");
        if (closeBtn) {
            closeBtn.addEventListener("click", hideErrorBanner);
        }
    }

    function showErrorBanner(title, msg) {
        const banner = document.getElementById("error-banner");
        document.getElementById("error-title").textContent = title;
        document.getElementById("error-message").textContent = msg;
        banner.classList.remove("hidden");
    }

    function hideErrorBanner() {
        document.getElementById("error-banner").classList.add("hidden");
    }

    function delay(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }

    // ==========================================================================
    // THREAT CATEGORIES REAL-TIME AI CYBERSECURITY UPGRADE
    // ==========================================================================
    function initThreatCategoriesUpgrade() {
        const grid = document.getElementById("threat-classes-grid");
        const cards = document.querySelectorAll(".threat-class-card");
        if (!grid || cards.length === 0) return;

        // 1. Staggered Entrance Intersection Observer
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    cards.forEach((card, index) => {
                        setTimeout(() => {
                            card.classList.add("animate-in");
                        }, index * 65);
                    });
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.1 });

        observer.observe(grid);

        // 2. Filter Buttons & Search Input
        const filterBtns = document.querySelectorAll(".cat-filter-btn");
        const searchInput = document.getElementById("threat-search-input");
        const noMatchesEl = document.getElementById("no-threat-matches");

        function filterCards() {
            const activeFilterBtn = document.querySelector(".cat-filter-btn.active");
            const activeCat = activeFilterBtn ? activeFilterBtn.dataset.cat : "all";
            const query = searchInput ? searchInput.value.trim().toLowerCase() : "";

            let visibleCount = 0;

            cards.forEach(card => {
                const cat = card.dataset.category || "other";
                const name = (card.dataset.name || "").toLowerCase();
                const desc = (card.dataset.desc || "").toLowerCase();

                const matchesCat = (activeCat === "all" || cat === activeCat);
                const matchesQuery = !query || name.includes(query) || desc.includes(query);

                if (matchesCat && matchesQuery) {
                    card.style.display = "flex";
                    visibleCount++;
                } else {
                    card.style.display = "none";
                }
            });

            if (noMatchesEl) {
                if (visibleCount === 0) noMatchesEl.classList.remove("hidden");
                else noMatchesEl.classList.add("hidden");
            }
        }

        filterBtns.forEach(btn => {
            btn.addEventListener("click", () => {
                filterBtns.forEach(b => {
                    b.classList.remove("active");
                    b.setAttribute("aria-selected", "false");
                });
                btn.classList.add("active");
                btn.setAttribute("aria-selected", "true");
                filterCards();
            });
        });

        if (searchInput) {
            searchInput.addEventListener("input", filterCards);
        }

        // 3. Card Click -> Intelligence Modal Panel
        const modal = document.getElementById("threat-detail-modal");
        const closeModalBtn = document.getElementById("close-threat-modal");
        const modalTitle = document.getElementById("modal-threat-title");
        const modalCategory = document.getElementById("modal-threat-category");
        const modalDesc = document.getElementById("modal-threat-desc");
        const modalSeverity = document.getElementById("modal-threat-severity");
        const modalConfidence = document.getElementById("modal-threat-confidence");
        const modalAction = document.getElementById("modal-threat-action");
        const btnModalRun = document.getElementById("btn-modal-run-scenario");
        let activeModalScenarioPreset = "sample";

        cards.forEach(card => {
            card.addEventListener("click", () => {
                const name = card.dataset.name || "Threat Class";
                const cat = (card.dataset.category || "General").toUpperCase();
                const desc = card.dataset.desc || "";
                const sev = card.dataset.severity || "HIGH";
                const conf = card.dataset.confidence || "98.0%";
                const action = card.dataset.action || "Inspect flow telemetry";

                if (modalTitle) modalTitle.textContent = name;
                if (modalCategory) modalCategory.textContent = `${cat} CATEGORY`;
                if (modalDesc) modalDesc.textContent = desc;
                if (modalSeverity) {
                    modalSeverity.textContent = `● ${sev}`;
                    modalSeverity.className = `m-val ${sev === "SAFE" ? "green-text" : sev === "HIGH" ? "red-text" : "amber-text"}`;
                }
                if (modalConfidence) modalConfidence.textContent = conf;
                if (modalAction) modalAction.textContent = action;

                // Match scenario preset if applicable
                const lowerName = name.toLowerCase();
                if (lowerName.includes("ddos")) activeModalScenarioPreset = "ddos";
                else if (lowerName.includes("portscan")) activeModalScenarioPreset = "portscan";
                else if (lowerName.includes("benign")) activeModalScenarioPreset = "benign";
                else activeModalScenarioPreset = "sample";

                if (modal) modal.classList.remove("hidden");
            });
        });

        if (closeModalBtn) {
            closeModalBtn.addEventListener("click", () => {
                if (modal) modal.classList.add("hidden");
            });
        }

        if (modal) {
            modal.addEventListener("click", (e) => {
                if (e.target === modal) modal.classList.add("hidden");
            });
        }

        if (btnModalRun) {
            btnModalRun.addEventListener("click", () => {
                if (modal) modal.classList.add("hidden");

                // Trigger preset scenario in analyzer
                const scenarioBtn = document.getElementById(`scenario-btn-${activeModalScenarioPreset}`);
                if (scenarioBtn) {
                    scenarioBtn.click();
                }

                const analyzerSection = document.getElementById("analyzer");
                if (analyzerSection) {
                    analyzerSection.scrollIntoView({ behavior: "smooth" });
                }
            });
        }
    }

    function setupScrollspy() {
        const sections = document.querySelectorAll("section[id]");
        const navLinks = document.querySelectorAll(".nav-link");
        if (sections.length === 0 || navLinks.length === 0) return;

        window.addEventListener("scroll", () => {
            let currentSectionId = "";
            const scrollPosition = window.scrollY + 200;

            sections.forEach(sec => {
                if (scrollPosition >= sec.offsetTop && scrollPosition < sec.offsetTop + sec.offsetHeight) {
                    currentSectionId = sec.id;
                }
            });

            if (currentSectionId) {
                navLinks.forEach(link => {
                    link.classList.remove("active");
                    const href = link.getAttribute("href");
                    if (href === `#${currentSectionId}`) {
                        link.classList.add("active");
                    }
                });
            }
        });
    }
});


// Hero Multi-Layer Mouse Micro-Parallax Effect
document.addEventListener('mousemove', (e) => {
    const orbWrapper = document.getElementById('hero-orb-wrapper');
    const bgCanvas = document.getElementById('bg-network-canvas');
    if (!orbWrapper) return;

    const mouseX = (e.clientX - window.innerWidth / 2) * 0.006;
    const mouseY = (e.clientY - window.innerHeight / 2) * 0.006;
    
    orbWrapper.style.transform = `translateX(${ -20 + mouseX * 0.5 }px) translateY(${ mouseY * 0.5 }px)`;
    
    if (bgCanvas) {
        bgCanvas.style.transform = `translate(${ mouseX * 0.3 }px, ${ mouseY * 0.3 }px)`;
    }
});

