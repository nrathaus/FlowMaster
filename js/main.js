const MONITORED_PORTS = [8000, 8001, 8002];
const UPDATE_INTERVAL = 2500; // 2.5 seconds
const HISTORY_LENGTH = 120; // Store 5 minutes of data
let trafficHistory = [];

// Modified createServerCard function to include user disconnect buttons
function createServerCard(port) {
    const card = document.createElement("div");
    card.className = "stats-card";
    card.innerHTML = `
                <h2>
                    <span class="status-indicator status-inactive" id="status-${port}"></span>
                    Port ${port}
                </h2>
                <p>Active Users: <span id="activeUsers-${port}">Checking...</span></p>
                <p>Last Update: <span id="lastUpdate-${port}">-</span></p>
                <div class="user-list" id="userList-${port}"></div>
            `;
    return card;
}

// New function to create user list items with disconnect buttons
function createUserListItem(userId, port) {
    return `
                <div class="user-item">
                    <span>${userId}</span>
                    <button class="disconnect-btn" onclick="disconnectUser('${userId}', ${port})">
                        Disconnect
                    </button>
                </div>
            `;
}
// Get current user information
async function fetchCurrentUser() {
    try {
        console.log("Fetching user info...");
        const response = await fetch("/user-info");
        console.log("Response status:", response.status);

        if (!response.ok) {
            console.error("Failed to fetch user info:", response.statusText);
            document.getElementById("currentUser").textContent = "Error";
            return;
        }

        const data = await response.json();
        console.log("Received user data:", data);
        document.getElementById("currentUser").textContent = data.username;
    } catch (error) {
        console.error("Error fetching user info:", error);
        document.getElementById("currentUser").textContent = "Error";
    }
}

// New function to handle user disconnection
async function disconnectUser(userId, port) {
    try {
        const response = await fetch("/disconnect", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                userId: userId,
                port: port,
            }),
            redirect: "manual" // prevent automatic redirect following
        });

        console.log("Disconnect response status:", response.status);
        console.log("Disconnect response headers:", [...response.headers.entries()]);

        if (response.status === 302) {
            // Manually handle redirect by navigating to the Location header
            const redirectUrl = response.headers.get("Location");
            console.log("Redirect URL:", redirectUrl);
            if (redirectUrl) {
                window.location.href = redirectUrl;
                return;
            }
        }

        if (!response.ok) {
            const text = await response.text();
            console.error("Disconnect response text:", text);
            throw new Error("Failed to disconnect user");
        }

        let result = await response.json();
        console.log("Disconnect response JSON:", result);

        // Only alert failure if response field exists and is not success
        if ('response' in result && result.response !== "leave received") {
            alert(`Failed to disconnect user : ${result.response}`);
        }

        // Refresh stats immediately after disconnection
        fetchStats();
    } catch (error) {
        console.alrt(error)
        console.error("Error disconnecting user:", error);
        // Only alert failure if not redirected
        alert("Failed to disconnect user. Please try again.");
    }
}

// Modified update logic in fetchStats to include disconnect buttons
async function fetchStats() {
    try {
        const response = await fetch(`/stats`);
        if (!response.ok) throw new Error("Stats fetch failed");

        const data = await response.json();
        const timestamp = new Date().toLocaleTimeString();

        // Filter out the host IP from the data
        const filteredData = filterHostIp(data);

        // Previous stats update logic with filtered data
        const total = filteredData.total_users || 1;

        const trafficDataPoint = {
            timestamp,
            total: filteredData.total_users,
        };

        MONITORED_PORTS.forEach((port) => {
            const users = filteredData.servers[port]?.active_users || 0;
            trafficDataPoint[`port${port}`] = users;
        });

        trafficHistory.push(trafficDataPoint);
        if (trafficHistory.length > HISTORY_LENGTH) {
            trafficHistory.shift();
        }

        document.getElementById("totalUsers").textContent =
            filteredData.total_users;
        document.getElementById("lastUpdate").textContent = timestamp;

        // Modified user list update logic with filtered data
        Object.entries(filteredData.servers).forEach(([port, serverData]) => {
            const statusElement = document.getElementById(`status-${port}`);
            const usersElement = document.getElementById(`activeUsers-${port}`);
            const updateElement = document.getElementById(`lastUpdate-${port}`);
            const userListElement = document.getElementById(`userList-${port}`);

            if (statusElement && usersElement && updateElement) {
                statusElement.className = `status-indicator ${serverData.active_users > 0 ? "status-active" : "status-inactive"
                    }`;
                usersElement.textContent = serverData.active_users;
                updateElement.textContent = timestamp;

                if (userListElement) {
                    userListElement.innerHTML =
                        serverData.users.length > 0
                            ? serverData.users
                                .map((userId) => createUserListItem(userId, port))
                                .join("")
                            : "No active clients";
                }
            }
        });

        // Update the graphs
        updateGraphs();
    } catch (error) {
        console.error("Error fetching stats:", error);
        MONITORED_PORTS.forEach((port) => {
            const statusElement = document.getElementById(`status-${port}`);
            const usersElement = document.getElementById(`activeUsers-${port}`);
            if (statusElement && usersElement) {
                statusElement.className = "status-indicator status-inactive";
                usersElement.textContent = "Error";
            }
        });
    }
}

// Function to filter out the host IP from stats
function filterHostIp(data) {
    // Create a deep copy of the data
    const filteredData = JSON.parse(JSON.stringify(data));

    // Calculate the original total
    let originalTotal = 0;
    Object.values(data.servers).forEach((server) => {
        originalTotal += server.active_users;
    });

    // Filter each server's users
    let filteredTotal = 0;

    Object.entries(filteredData.servers).forEach(([port, serverData]) => {
        // Filter out the server IP
        const originalCount = serverData.users.length;
        serverData.users = serverData.users.filter((userId) => userId !== serverIp);

        // Update the active_users count
        const removedCount = originalCount - serverData.users.length;
        serverData.active_users -= removedCount;
        if (serverData.active_users < 0) serverData.active_users = 0;

        // Add to the filtered total
        filteredTotal += serverData.active_users;
    });

    // Update the total_users count
    filteredData.total_users = filteredTotal;

    return filteredData;
}

// Previous graph drawing functions remain the same
function drawLineGraph(svgId, data, options) {
    const svg = document.getElementById(svgId);
    const width = svg.clientWidth;
    const height = svg.clientHeight;
    const padding = 40;
    const rightPadding = 60;

    svg.innerHTML = "";

    if (data.length < 2) return;

    const maxValue =
        options.maxValue ||
        Math.max(
            ...data.map((point) =>
                Math.max(...options.lines.map((line) => point[line.key] || 0))
            )
        );

    const xScale = (i) =>
        padding + (i * (width - padding - rightPadding)) / (HISTORY_LENGTH - 1);
    const yScale = (value) =>
        height - padding - (value * (height - 2 * padding)) / maxValue;

    // Draw axes and grid
    const axisColor = "#ccc";
    svg.innerHTML += `
                <line x1="${padding}" y1="${height - padding}" x2="${width - rightPadding
        }" y2="${height - padding}" stroke="${axisColor}" />
                <line x1="${padding}" y1="${padding}" x2="${padding}" y2="${height - padding
        }" stroke="${axisColor}" />
            `;

    // Draw grid lines and labels
    for (let i = 0; i <= 5; i++) {
        const y = padding + (i * (height - 2 * padding)) / 5;
        const value = maxValue - (i * maxValue) / 5;
        svg.innerHTML += `
                    <line x1="${padding}" y1="${y}" x2="${width - rightPadding
            }" y2="${y}" stroke="${axisColor}" stroke-dasharray="2,2" />
                    <text x="${padding - 5
            }" y="${y}" text-anchor="end" alignment-baseline="middle" font-size="12">
                        ${options.formatValue
                ? options.formatValue(value)
                : Math.round(value)
            }
                    </text>
                `;
    }

    // Draw time labels
    for (let i = 0; i < data.length; i += 24) {
        if (i < data.length) {
            const x = xScale(i);
            svg.innerHTML += `
                        <text x="${x}" y="${height - padding + 20}"
                              text-anchor="middle" class="x-axis-label">
                            ${data[i].timestamp}
                        </text>
                    `;
        }
    }

    // Draw lines
    options.lines.forEach((line) => {
        let path = `M ${xScale(0)} ${yScale(data[0][line.key] || 0)}`;
        data.forEach((point, i) => {
            path += ` L ${xScale(i)} ${yScale(point[line.key] || 0)}`;
        });
        svg.innerHTML += `<path d="${path}" stroke="${line.color
            }" fill="none" stroke-width="${line.width || 1}" />`;
    });
}

function drawStackedAreaGraph(svgId, data) {
    const svg = document.getElementById(svgId);
    const width = svg.clientWidth;
    const height = svg.clientHeight;
    const padding = 40;
    const rightPadding = 60;

    svg.innerHTML = "";

    if (data.length < 2) return;

    const xScale = (i) =>
        padding + (i * (width - padding - rightPadding)) / (HISTORY_LENGTH - 1);
    const yScale = (value) =>
        height - padding - (value * (height - 2 * padding)) / 100;

    // Draw axes and grid (keep existing axes code...)
    const axisColor = "#ccc";
    svg.innerHTML += `
                <line x1="${padding}" y1="${height - padding}" x2="${width - rightPadding
        }" y2="${height - padding}" stroke="${axisColor}" />
                <line x1="${padding}" y1="${padding}" x2="${padding}" y2="${height - padding
        }" stroke="${axisColor}" />
            `;

    // Keep existing grid lines and labels code...
    for (let i = 0; i <= 5; i++) {
        const y = padding + (i * (height - 2 * padding)) / 5;
        const value = 100 - i * 20;
        svg.innerHTML += `
                    <line x1="${padding}" y1="${y}" x2="${width - rightPadding
            }" y2="${y}" stroke="${axisColor}" stroke-dasharray="2,2" />
                    <text x="${padding - 5
            }" y="${y}" text-anchor="end" alignment-baseline="middle" font-size="12">
                        ${value}%
                    </text>
                `;
    }

    // Keep existing time labels code...
    for (let i = 0; i < data.length; i += 24) {
        if (i < data.length) {
            const x = xScale(i);
            svg.innerHTML += `
                        <text x="${x}" y="${height - padding + 20}"
                              text-anchor="middle" class="x-axis-label">
                            ${data[i].timestamp}
                        </text>
                    `;
        }
    }

    // Draw stacked areas with calculated percentages
    const areas = [
        { key: "port8000", color: "#82ca9d" },
        { key: "port8001", color: "#ffc658" },
        { key: "port8002", color: "#ff8042" },
    ];

    data.forEach((point) => {
        const total = point.total || 1; // Prevent division by zero
        let runningPercentage = 0;

        areas.forEach((area) => {
            point[`${area.key}_percent`] = (point[area.key] / total) * 100;
            point[`${area.key}_stack`] =
                runningPercentage + point[`${area.key}_percent`];
            runningPercentage += point[`${area.key}_percent`];
        });
    });

    areas.forEach((area, index) => {
        let path = `M ${xScale(0)} ${yScale(data[0][`${area.key}_stack`] || 0)}`;

        data.forEach((point, i) => {
            path += ` L ${xScale(i)} ${yScale(point[`${area.key}_stack`] || 0)}`;
        });

        const prevKey = index > 0 ? `${areas[index - 1].key}_stack` : null;
        path += ` L ${xScale(data.length - 1)} ${yScale(
            prevKey ? data[data.length - 1][prevKey] || 0 : 0
        )}`;

        for (let i = data.length - 1; i >= 0; i--) {
            path += ` L ${xScale(i)} ${yScale(prevKey ? data[i][prevKey] || 0 : 0)}`;
        }

        path += " Z";
        svg.innerHTML += `<path d="${path}" fill="${area.color}" class="area" />`;
    });
}

function updateGraphs() {
    // Update total connections graph
    drawLineGraph("totalConnectionsGraph", trafficHistory, {
        lines: [{ key: "total", color: "#8884d8", width: 2 }],
        formatValue: (value) => Math.round(value),
    });

    // Update individual server connections graph
    drawLineGraph("serverConnectionsGraph", trafficHistory, {
        lines: [
            { key: "port8000", color: "#82ca9d" },
            { key: "port8001", color: "#ffc658" },
            { key: "port8002", color: "#ff8042" },
        ],
        formatValue: (value) => Math.round(value),
    });

    // Update percentage distribution graph
    drawStackedAreaGraph("percentageGraph", trafficHistory);
}

let serverFullState = false; // false means default caps, true means pretend caps (full)

function make_server_full() {
    fetch("/make_server_full", {
        method: "POST",
    })
        .then(response => response.json())
        .then(data => {
            if (data.state === "full") {
                serverFullState = true;
                document.getElementById("toggleFullBtn").textContent = "Return to default caps";
            } else {
                serverFullState = false;
                document.getElementById("toggleFullBtn").textContent = "Make All Servers Appear Full";
            }
        })
        .catch(error => {
            console.error("Error toggling server caps:", error);
        });
}

// Logout function
function logout() {
    fetch("/logout", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ action: "logout" }),
    })
        .then((response) => {
            if (response.ok) {
                // Redirect to login page
                window.location.href = "/login.html";
            } else {
                alert("Logout failed. Please try again.");
            }
        })
        .catch((error) => {
            console.error("Error during logout:", error);
            alert("Logout failed. Please try again.");
        });
}

// Handle window resize
window.addEventListener("resize", updateGraphs);

function onPageLoad() {
    // Get the server IP address
    const serverIp = window.location.hostname;
    document.getElementById("serverIp").textContent = serverIp;
    document.getElementById("hostIpBadge").textContent = serverIp;

    const statsContainer = document.getElementById("statsContainer");
    MONITORED_PORTS.forEach((port) => {
        statsContainer.appendChild(createServerCard(port));
    });

    // Initial fetch

    fetchStats();

    // Set up regular polling
    setInterval(fetchStats, UPDATE_INTERVAL);
}
document.addEventListener("DOMContentLoaded", onPageLoad);