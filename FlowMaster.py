import json
import signal
import socket
import sys
import threading
import time
from datetime import datetime, timedelta
import hashlib
import FlowMasterClasses

# LOGGER INITIALIZATION
LOGGER = FlowMasterClasses.lggr("../server.log")  # Set up logging

# CONFIGURATION CONSTANTS
CURRENT_USERNAME = None  # Variable to store the current username
MONITOR_SERVER = True  # Flag to control monitoring server status
SERVICE_USERS = True  # Flag to control user service status
IP = socket.gethostbyname(
    socket.gethostname()
)  # Get the local machine's IP address automatically
PORTS = [8000, 8001, 8002]  # Ports for content servers
ACTUAL_CAPS = {
    8000: 60,
    8001: 150,
    8002: 90,
}  # Maximal amount of Connections allowed to connect to each port
PRETEND_CAPS = {
    8000: 1,
    8001: 1,
    8002: 1,
}  # Pretend to be full for testing purposes
SERVER_CAPS = ACTUAL_CAPS  # Default server capabilities
LOADING_PORT = 7999  # Port for the loading page
DISCONNECT_PORT = 8888  # Port for the disconnect page


# Function to handle user logout
def HandleLogout():
    global CURRENT_USERNAME  # Use the global variable
    CURRENT_USERNAME = None  # Clear the current username


if len(PORTS) != len(SERVER_CAPS):
    LOGGER.LogError("Ports and their capabilities list don't match")
FOUND_PORTS = []
for port in PORTS:
    if port not in SERVER_CAPS:
        LOGGER.LogError(f"Port '{port}' missing its capability")
    FOUND_PORTS.append(port)
if len(FOUND_PORTS) != len(PORTS):
    LOGGER.LogError(
        f"Ports list contains duplicates or missing ports, found ports: {FOUND_PORTS}, vs: {PORTS}"
    )

ROUTING_PORT = 8080  # Port for the load balancer
MONITORING_PORT = 8081  # Port for the monitoring dashboard
SOCKET_TIMEOUT = 5  # Socket timeout in seconds
AUTHENTICATED_SESSIONS = {}  # Dictionary to track authenticated sessions
HEARTBEAT_INTERVAL = 2.5  # Time between heartbeat checks (in seconds)
TIMEOUT_THRESHOLD = (
    1800  # Time after which a client is considered inactive (in seconds)
)
DELAY_BETWEEN_ROUTING = 0.35  # Delay between routing requests

# Paths to HTML files served by different servers
FILE_PATHS = {
    "index1": "html/index1.html",  # Server on port 8000
    "index2": "html/index2.html",  # Server on port 8001
    "index3": "html/index3.html",  # Server on port 8002
    "tracker": "html/tracker.html",  # Monitoring dashboard
    "login": "html/login.html",  # Login page
    "disconnect": "html/disconnect.html",  # Disconnect page
    "loading": "html/loading.html",  # Loading page
    "main.js": "js/main.js",  # Javascript for tracker
}

# SHARED STATE AND SYNCHRONIZATION
# Track active users per port and users in queue
AWAITING_USERS = {
    port: {} for port in PORTS + [MONITORING_PORT, LOADING_PORT, DISCONNECT_PORT]
}
WAITING_QUEUE = []  # List of users waiting to connect
QUEUE_LOCK = threading.Lock()  # Lock for thread-safe queue operations
DENIED_USERS = {}  # Track users we want to deny access
USERS_LOCK = (
    threading.Lock()
)  # Lock to protect the active_users dictionary during concurrent access
CLIENT_SOCKETS = {}  # Dictionary to hold client sockets
CONNECTED_CLIENTS = (
    set()
)  # Set of unique client identifiers that have connected at least once
CLIENTS_LOCK = (
    threading.Lock()
)  # Lock to protect the connected_clients set during concurrent access

# Initialize the database and user session manager
USERNAMES = FlowMasterClasses.dtbs(
    "PUP.db", ["Username", "Password", "Perm"], "UserPassPerm"
)  # Allowed usernames for logins
PERMISSIONS = FlowMasterClasses.dtbs(
    "PUP.db", ["PermissionNum", "CanView", "CanDisconnect"], "Permissions"
)  # Allowed permissions
PERMCANDISCONNECT = [
    key
    for key, perm in PERMISSIONS.user_library.items()
    if len(perm) > 1 and perm[1] == True
]  # Permissions that allow disconnecting users
USER_SESSION_MANAGER = FlowMasterClasses.usrson()  # Manage user sessions


def TestPorts():
    """
    Test if all required ports are available before starting servers.
    Returns:
        bool: True if all ports are available, False otherwise.
    """
    for port in PORTS + [ROUTING_PORT, MONITORING_PORT]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_socket:
            try:
                test_socket.bind((IP, port))  # Try to bind to the port
                test_socket.close()
            except socket.error:
                LOGGER.LogError(f"Port {port} is not available!")
                return False
    return True


def SignalHandler(*_):
    """
    Handle graceful shutdown on SIGINT (Ctrl+C).
    This ensures that the program exits cleanly when terminated by user.
    Args:
        *_: Ignored signal parameters.
    """
    global MONITOR_SERVER, SERVICE_USERS, CLIENT_SOCKETS
    LOGGER.LogInfo("Shutting down server - waiting for 1 second")
    MONITOR_SERVER = False
    SERVICE_USERS = False

    for _, PeerName in CLIENT_SOCKETS.items():
        try:
            PeerName.shutdown()  # Drop the connection
        finally:
            pass

    time.sleep(1)  # Wait for a moment before exiting
    sys.exit(0)


def Hash(string: str) -> str:
    """
    As I am a very lazy person I don't like to write that long line of code every time I need to hash something, so I made a function for it.
    Args:
        string (str): The string to hash.
    Returns:
        str: The MD5 hash of the input string.
    """
    return hashlib.md5(string.encode()).hexdigest()


def UpdateActiveUsers():
    """
    Background task to maintain active user counts.
    Periodically checks for and removes inactive users based on
    their last activity timestamp. Runs continuously in a separate thread.
    """
    while SERVICE_USERS:
        time.sleep(HEARTBEAT_INTERVAL)  # Wait between checks
        current_time = datetime.now()

        with USERS_LOCK:  # Ensure thread-safe access to shared data
            for port in PORTS + [MONITORING_PORT]:
                # Find users who haven't sent a heartbeat within the threshold
                inactive_users = [
                    client_id
                    for client_id, last_active in AWAITING_USERS[port].items()
                    if (current_time - last_active)
                    > timedelta(seconds=TIMEOUT_THRESHOLD)
                ]

                # Remove inactive users
                for client_id in inactive_users:
                    del AWAITING_USERS[port][client_id]

            # Log current active user counts for monitoring
            LOGGER.LogInfo("--- Current Active Users ---")
            for port in PORTS:
                LOGGER.LogInfo(f"Port {port}: {len(AWAITING_USERS[port])} active users")


def GetServerLoads():
    """
    Get the current load (number of active users) of each content server.
    Returns:
        dict: Dictionary mapping port numbers to user counts.
    """
    with USERS_LOCK:  # Protect shared data during read
        return {port: len(AWAITING_USERS[port]) for port in PORTS}


def GetQueueData():
    """
    Get comprehensive queue data for all servers and queue.
    Returns:
        dict:
    """
    with USERS_LOCK:  # Protect shared data during read
        with QUEUE_LOCK:
            return {
                "timestamp": datetime.now().isoformat(),
                "waiting": len(WAITING_QUEUE),
                "total": sum(len(SERVER_CAPS[port]) for port in PORTS),
            }


def GetMonitoringData():
    """
    Get comprehensive monitoring data for all servers and queue.
    Returns:
        dict: Dictionary with timestamp, per-server stats, queue, and totals.
    """
    with USERS_LOCK:  # Protect shared data during read
        with QUEUE_LOCK:
            return {
                "timestamp": datetime.now().isoformat(),
                "servers": {
                    str(port): {
                        "active_users": len(AWAITING_USERS[port]),
                        "users": list(AWAITING_USERS[port].keys()),
                        "capacity": SERVER_CAPS[port],
                    }
                    for _, port in enumerate(PORTS)
                },
                "queue": {
                    "count": len(WAITING_QUEUE),
                    "users": list(WAITING_QUEUE),
                },
                "total_users": sum(len(AWAITING_USERS[port]) for port in PORTS),
            }


def SelectTargetPort(client_id=None):
    """
    Select the least loaded port for new connections (load balancing).
    If all servers are busy, adds client to queue and returns ROUTING_PORT.
    Args:
        client_id (str): Optional client identifier for queue tracking
    Returns:
        int: The selected port number or ROUTING_PORT if queued
    """
    loads = GetServerLoads()

    percentage_occupied = []
    for port in PORTS:
        percentage_occupied.append(loads[port] / SERVER_CAPS[port])

    load_percentages = [f"{percent*100:.1f}%" for percent in percentage_occupied]
    LOGGER.LogInfo(f"current loads are: {load_percentages}")

    # percentage_occupied = [
    #     (load / cap) for load, cap in zip(loads.values(), server_caps[port])
    # ]

    min_load = min(percentage_occupied)

    if min_load < 1:
        min_load_ports = [
            port
            for port, percentage in zip(loads.keys(), percentage_occupied)
            if percentage == min_load
        ]
        selected_port = min(min_load_ports)
        LOGGER.LogInfo(f"Selected port {selected_port} with load {min_load}")
        are_all_full = False
        return selected_port

    if client_id is not None:
        with QUEUE_LOCK:
            if client_id not in WAITING_QUEUE:
                WAITING_QUEUE.append(client_id)
                LOGGER.LogInfo(f"Added {client_id} to waiting queue")
    are_all_full = True
    return LOADING_PORT  # Redirect to loading page if all servers are full


def SendRedirect(client_socket, port):
    """
    Send HTTP redirect response to client.
    Creates and sends a 302 Found HTTP response directing the client
    to the selected content server.
    Args:
        client_socket (socket): The client's socket connection.
        port (int): The port to redirect the client to.
    """

    redirect_response = (
        f"HTTP/1.1 302 Found\r\n" f"Location: http://{IP}:{port}/\r\n" "\r\n"
    ).encode()

    client_socket.sendall(redirect_response)
    LOGGER.LogInfo(f"Sent redirect to port {port}")


def SendFile(file_path: str, client_socket):
    """
    Send file content to client with proper HTTP headers.
    Args:
        file_path (str): Path to the file to send.
        client_socket (socket): The client's socket connection.
    """

    content_type = "text/html"
    if file_path.endswith(".js"):
        content_type = "application/javascript"

    try:
        if not FlowMasterClasses.flmngr.FileExists(file_path):
            LOGGER.LogWarning(f"File not found: {file_path}")
            response = (
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Type: text/plain\r\n"
                "\r\nFile not found."
            ).encode()
            client_socket.sendall(response)
            return

        content = FlowMasterClasses.flmngr.ReadFile(file_path)
        if content is None:
            raise FileNotFoundError(f"File not found or could not be read: {file_path}")

        content_bytes = content.encode() if isinstance(content, str) else content

        response = (
            "HTTP/1.1 200 OK\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(content_bytes)}\r\n"
            f"\r\n"
        ).encode()

        client_socket.sendall(response + content_bytes)
        LOGGER.LogInfo(f"Sent file: {file_path}")

    except FileNotFoundError:
        LOGGER.LogWarning(f"File not found: {file_path}")
        response = (
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/plain\r\n"
            "\r\nFile not found."
        ).encode()
        client_socket.sendall(response)
    except Exception as e:
        LOGGER.LogError(f"Error sending file: {str(e)}")
        response = (
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: text/plain\r\n"
            "\r\nServer error."
        ).encode()
        client_socket.sendall(response)


def HandleQueueRequest(client_socket):
    """
    Handle requests for queue statistics.
    Sends JSON-formatted queue data to the client.
    Args:
        client_socket (socket): The client's socket connection.
    """
    queue = GetQueueData()  # Get current queue statistics

    response = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: application/json\r\n"
        f"Access-Control-Allow-Origin: *\r\n"  # Allow cross-origin requests for dashboard
        f"\r\n"
        f"{json.dumps(queue)}"  # Convert stats to JSON
    ).encode()

    client_socket.sendall(response)
    LOGGER.LogInfo("Sent monitoring stats")


def HandleStatsRequest(client_socket):
    """
    Handle requests for monitoring statistics.
    Sends JSON-formatted monitoring data to the client.
    Args:
        client_socket (socket): The client's socket connection.
    """
    stats = GetMonitoringData()  # Get current monitoring statistics

    response = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: application/json\r\n"
        f"Access-Control-Allow-Origin: *\r\n"  # Allow cross-origin requests for dashboard
        f"X-Active-Users: {stats['total_users']}\r\n"  # Custom header with user count
        f"\r\n"
        f"{json.dumps(stats)}"  # Convert stats to JSON
    ).encode()

    client_socket.sendall(response)
    LOGGER.LogInfo("Sent monitoring stats")


def HandleUserRequest(client_socket, file_path, port):
    """
    Handle incoming user HTTP requests based on the server type and request path.
    This function decodes the request, identifies the client, updates activity tracking,
    and routes the request to the appropriate handler function.
    Args:
        client_socket (socket): The client's socket connection.
        file_path (str): Path to the file to serve (if applicable).
        port (int): The port number this request was received on.
    Returns:
        bool: True if request was handled successfully, False otherwise.
    """
    try:
        if not SERVICE_USERS or not MONITOR_SERVER:
            sys.exit()

        data = client_socket.recv(9999).decode()  # Read data from client (HTTP request)
        if client_socket.fileno() == -1:  # Check if socket is still valid
            LOGGER.LogError(f"Socket already closed on port {port}")
            return False

        client_id = None
        if "client_id=" in data:
            client_id = data.split("client_id=")[1].split(" ")[0]

        if client_id is not None and client_id in DENIED_USERS:
            # If user has been denied access, send redirect to disconnect page
            LOGGER.LogInfo(f"Detected blocked access from {client_id} ({port})")
            try:
                redirect_response = (
                    f"HTTP/1.1 302 Found\r\n"
                    f"Location: http://{IP}:{DISCONNECT_PORT}/disconnect.html\r\n"
                    f"\r\n"
                ).encode()
                client_socket.sendall(redirect_response)
            except Exception as e:
                LOGGER.LogError(f"Error sending redirect to disconnect page: {str(e)}")
                msg = "Access has been denied"
                response = f"HTTP/1.1 403 Forbidden\r\nContent-Length: {len(msg)}\r\n\r\n{msg}".encode()
                client_socket.sendall(response)
            return True

        connection_type = "new"
        if client_id is not None:
            with CLIENTS_LOCK:  # Track if this is a new or continuing connection
                if client_id not in CONNECTED_CLIENTS:
                    CONNECTED_CLIENTS.add(client_id)
                else:
                    connection_type = "returning"

        # logger.log_info(f"Detected '{connection_type}' connection from {client_id} on port {port}")

        if client_id is not None and "/heartbeat" in data:
            with USERS_LOCK:
                AWAITING_USERS[port][
                    client_id
                ] = datetime.now()  # Update last active time for this client
                active_count = len(AWAITING_USERS[port])

            # Send minimal response with active user count in header
            msg = (
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                f"X-Active-Users: {active_count}\r\n"
                "Content-Length: 0\r\n\r\n"
            ).encode()

            client_socket.sendall(msg)
            return True

        if client_id is not None and "/leave" in data:  # Handle client leave requests
            with USERS_LOCK:
                if client_id in AWAITING_USERS[port]:
                    del AWAITING_USERS[port][client_id]

            msg = json.dumps({"response": "leave received"})
            client_socket.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(msg)}\r\n\r\n{msg}".encode()
            )
            return True

        if port == ROUTING_PORT:  # Handle routing server (load balancer) requests
            selected_port = SelectTargetPort()
            SendRedirect(client_socket, selected_port)
            return True

        # Handle content server requests
        if client_id is not None:
            with USERS_LOCK:
                AWAITING_USERS[port][client_id] = datetime.now()

        SendFile(file_path, client_socket)
        # logger.log_info("handle_user_requset after send_file")

        return True

    except socket.timeout:
        LOGGER.LogWarning(f"Socket timeout occurred on port {port}")
    except Exception as e:
        LOGGER.LogError(
            f"An error occurred on port while handling user request {port}: {str(e)}"
        )
    finally:
        try:  # Always ensure the socket is closed
            client_socket.close()  # Close the socket
        except Exception as e:
            LOGGER.LogError(f"Error closing socket on port {port}: {str(e)}")
    return False


def HandleMonitorRequest(client_socket, file_path, port):
    """
    Handle incoming monitor HTTP requests based on the server type and request path.
    This function decodes the request, identifies the client, updates activity tracking,
    and routes the request to the appropriate handler function.
    Args:
        client_socket (socket): The client's socket connection.
        file_path (str): Path to the file to serve (if applicable).
        port (int): The port number this request was received on.
    Returns:
        bool: True if request was handled successfully, False otherwise.
    """
    try:
        if not SERVICE_USERS or not MONITOR_SERVER:
            sys.exit()

        data = client_socket.recv(9999).decode()  # Read data from client (HTTP request)

        if client_socket.fileno() == -1:  # Check if socket is still valid
            LOGGER.LogError(f"Socket already closed on port {port}")
            return False

        # Extract request method and path
        request_line = data.split("\r\n")[0]
        method, path, _ = request_line.split(" ", 2)
        if "?" in path:
            # After the ? it is the query parameters, before is the path
            path, _ = path.split("?")

        # Check for cookies to identify session
        session_id = None
        if "Cookie:" in data:
            cookie_line = [
                line for line in data.split("\r\n") if line.startswith("Cookie:")
            ][0]
            cookies = cookie_line.split(":", 1)[1].strip()
            cookie_parts = cookies.split(";")
            for part in cookie_parts:
                if "session_id=" in part:
                    session_id = part.split("=", 1)[1].strip()
                    break

        # Check if this is a login request
        if path == "/login" and method == "POST":
            return HandleLoginRequest(client_socket, data)

        # Check if user is authenticated or requesting login page
        is_authenticated = USER_SESSION_MANAGER.ValidateSession(session_id)

        # Root path or empty path should serve login if not authenticated
        if path == "/" or path == "":
            if is_authenticated:
                # Get the tracker.html file content
                SendFile(FILE_PATHS["tracker"], client_socket)
                LOGGER.LogInfo(f"Sent tracker.html with username: {CURRENT_USERNAME}")
            else:
                SendFile(FILE_PATHS["login"], client_socket)  # Serve login.html
            return True

        # Explicitly handle tracker.html request
        if path == "/tracker.html":
            if is_authenticated:
                # Get the tracker.html file content
                SendFile(FILE_PATHS["tracker"], client_socket)  # Fallback
                LOGGER.LogInfo(f"Sent tracker.html with username: {CURRENT_USERNAME}")
            else:
                SendRedirectToLogin(client_socket)  # Redirect to log in
            return True

        # Explicitly handle login.html request
        if path == "/login.html":
            SendFile(FILE_PATHS["login"], client_socket)  # Always serve login page
            return True

        # Handle queue request (for auth and non auth)
        if path == "/queue":
            HandleQueueRequest(client_socket)
            return True

        # Handle stats request (for authenticated users only)
        if "/stats" in path:
            if is_authenticated:
                HandleStatsRequest(client_socket)
            else:
                SendRedirectToLogin(client_socket)
            return True

        # Make the server caps appear full (toggle)
        if "/make_server_full" in path:
            if not is_authenticated:
                SendRedirectToLogin(client_socket)
                return True

            global SERVER_CAPS
            # Toggle SERVER_CAPS between ACTUAL_CAPS and PRETEND_CAPS
            if SERVER_CAPS == ACTUAL_CAPS:
                SERVER_CAPS = PRETEND_CAPS
                state = "full"
            else:
                SERVER_CAPS = ACTUAL_CAPS
                state = "default"

            msg = json.dumps({"response": "make_server_full received", "state": state})
            client_socket.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(msg)}\r\n\r\n{msg}".encode()
            )
            return True

        # Logout the user
        if "/logout" in path:
            if not is_authenticated:
                SendRedirectToLogin(client_socket)
                return True

            HandleLogout()
            SendRedirectToLogin(client_socket)
            return True

        if "/disconnect" in path:  # Handle client leave requests
            if (
                not USERNAMES.GetSecondOfArray(Hash(CURRENT_USERNAME))
                in PERMCANDISCONNECT
            ):
                msg = json.dumps({"response": "missing permissions"})
                response = (
                    "HTTP/1.1 403 Forbidden\r\n"
                    f"Content-Length: {len(msg)}\r\n"
                    "Content-Type: application/json\r\n"
                    "\r\n"
                    f"{msg}"
                ).encode()
                client_socket.sendall(response)
                LOGGER.LogInfo("Did not have proper permissions to Disconnect")
                return True

            if not is_authenticated:
                SendRedirectToLogin(client_socket)
                return True

            # Find the body inside the 'data'
            header_and_body = data.split("\r\n\r\n")
            user_id = None
            if len(header_and_body) > 1:
                body = header_and_body[1]

                # Parse the body - it comes as JSON
                body_json = json.loads(body)

                if "userId" in body_json:
                    user_id = body_json["userId"]

            if user_id is None:
                msg = json.dumps({"response": "disconnect failed"})
                response = (
                    "HTTP/1.1 400 Bad Request\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(msg)}\r\n"
                    "\r\n"
                    f"{msg}"
                ).encode()

                client_socket.sendall(response)
                return True

            with USERS_LOCK:
                for check_port in PORTS + [MONITORING_PORT]:
                    if user_id in AWAITING_USERS[check_port]:
                        del AWAITING_USERS[check_port][user_id]

                DENIED_USERS[user_id] = True

            # Send HTTP redirect to disconnect.html after processing disconnect
            redirect_response = (
                f"HTTP/1.1 302 Found\r\n"
                f"Location: http://{IP}:{DISCONNECT_PORT}/disconnect.html\r\n"
                f"\r\n"
            ).encode()
            client_socket.sendall(redirect_response)
            LOGGER.LogInfo(f"Redirected user {user_id} to disconnect.html")
            return True

        # If we are authenticated and we are asked for /user-info return it
        if is_authenticated and path == "/user-info":
            response_json = json.dumps({"username": CURRENT_USERNAME})

            headers = (
                "HTTP/1.1 200 OK\r\n"
                f"Content-Type: application/json\r\n"
                f"Set-Cookie: session_id={session_id}; Path=/; HttpOnly; SameSite=Lax\r\n"
                f"Content-Length: {len(response_json)}\r\n"
                "\r\n"
            )

            client_socket.sendall((headers + response_json).encode())
            return True

        # For other requests, check authentication
        if not is_authenticated:
            SendRedirectToLogin(client_socket)
            return True

        # Default: serve the requested file
        no_leading_slash_path = path.removeprefix("/")
        for _, item in FILE_PATHS.items():
            if item == no_leading_slash_path:
                SendFile(no_leading_slash_path, client_socket)
                return True

        LOGGER.LogInfo(f"Return the '{file_path}' page")
        SendFile(file_path, client_socket)
        return True

    except socket.timeout:
        LOGGER.LogWarning(f"Socket timeout occurred on port {port}")
    except Exception as e:
        LOGGER.LogError(
            f"An error occurred on port while handling monitor request {port}: {str(e)}"
        )
    finally:
        try:  # Always ensure the socket is closed
            client_socket.close()
        except Exception as e:
            LOGGER.LogError(f"Error closing socket on port {port}: {str(e)}")
    return False


def SendRedirectToLogin(client_socket):
    """Send HTTP redirect to login page
    Args:
        client_socket (socket): The client's socket connection.
    """
    redirect_response = (
        f"HTTP/1.1 302 Found\r\n"
        f"Location: http://{IP}:{MONITORING_PORT}/login.html\r\n"
        f"\r\n"
    ).encode()

    client_socket.sendall(redirect_response)
    LOGGER.LogInfo("Redirected unauthenticated user to login page")


def HandleLoginRequest(client_socket, data):
    """Handle login POST requests
    Args:
        client_socket (socket): The client's socket connection.
        data (str): The HTTP request data.
    Returns:
        bool: True if request was handled successfully.
    """
    global CURRENT_USERNAME  # Access the global variable

    try:
        # Extract the request body
        body = data.split("\r\n\r\n")[1]
        login_data = json.loads(body)

        username = login_data.get("username")
        password = login_data.get("password")

        encrypted_username = Hash(username)
        encrypted_password = Hash(password)

        # Check credentials against USERNAMES dictionary
        if (
            encrypted_username in USERNAMES.user_library
            and USERNAMES.user_library[encrypted_username][0] == encrypted_password
        ):
            # Update current_username when login is successful
            CURRENT_USERNAME = username

            # Generate a session ID
            session_id = USER_SESSION_MANAGER.CreateSession(CURRENT_USERNAME)
            response = {
                "success": True,
                "message": "Login successful",
                "redirect": f"http://{IP}:{MONITORING_PORT}/tracker.html",
            }
            response_json = json.dumps(response)

            headers = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: application/json\r\n"
                f"Set-Cookie: session_id={session_id}; Path=/; HttpOnly; SameSite=Lax\r\n"
                f"Content-Length: {len(response_json)}\r\n"
                f"\r\n"
            )

            client_socket.sendall((headers + response_json).encode())
            LOGGER.LogInfo(f"User {username} logged in successfully")
            CURRENT_USERNAME = username
        else:
            # Send failure response
            response = {"success": False, "message": "Invalid username or password"}
            response_json = json.dumps(response)

            headers = (
                f"HTTP/1.1 401 Unauthorized\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(response_json)}\r\n"
                f"\r\n"
            )

            client_socket.sendall((headers + response_json).encode())
            LOGGER.LogInfo(f"Failed login attempt for user {username}")

        return True
    except Exception as e:
        LOGGER.LogError(f"Error handling login: {str(e)}")
        error_response = json.dumps({"success": False, "message": "Server error"})
        client_socket.sendall(
            f"HTTP/1.1 500 Internal Server Error\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(error_response)}\r\n"
            f"\r\n{error_response}".encode()
        )
        return True


def MonitoringServer():
    """
    Start the monitoring server that provides the dashboard and stats API.
    This server runs on its own thread and handles requests for monitoring data.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((IP, MONITORING_PORT))
        server_socket.listen()
        LOGGER.LogInfo(f"Monitoring server listening on: {IP}:{MONITORING_PORT}")

        while MONITOR_SERVER:
            client_socket, _ = server_socket.accept()  # Accept incoming connections
            client_socket.settimeout(SOCKET_TIMEOUT)
            Client_PeerName = f"{client_socket.getpeername()}"
            CLIENT_SOCKETS[Client_PeerName] = client_socket

            threading.Thread(  # Handle each request in a separate thread
                target=lambda: HandleMonitorRequest(
                    client_socket,
                    FILE_PATHS["login"],
                    MONITORING_PORT,  # Default to login page
                )
            ).start()


def StartRoutingServer():
    """
    Start the main routing server (load balancer).
    This is the main entry point for clients and redirects them to the
    least loaded content server. Runs on the main thread.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as routing_socket:
        routing_socket.bind((IP, ROUTING_PORT))
        routing_socket.listen()
        LOGGER.LogInfo(f"Routing server listening on: {IP}:{ROUTING_PORT}")

        last_routing_time = time.time()

        while True:
            client_socket, _ = routing_socket.accept()  # Accept incoming connections
            client_socket.settimeout(SOCKET_TIMEOUT)

            current_time = time.time()
            time_since_last = current_time - last_routing_time

            # If too little time has passed since last routing, add a delay
            if time_since_last < DELAY_BETWEEN_ROUTING:
                time.sleep(DELAY_BETWEEN_ROUTING - time_since_last)

            last_routing_time = time.time()  # Update last routing time

            threading.Thread(  # Handle each routing request in a separate thread
                target=lambda: HandleUserRequest(client_socket, None, ROUTING_PORT)
            ).start()


def StaticServer(port, file_path, max_connections):
    """
    Start a static content server on a specific port.
    Each static server serves one HTML file and handles client tracking.
    Args:
        port (int): Port number to listen on.
        file_path (str): Path to the HTML file to serve.
        max_connections (int): Maximum allowed concurrent connections
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((IP, port))
        server_socket.listen()
        LOGGER.LogInfo(
            f"Static server listening on: {IP}:{port} (max connections: {max_connections})"
        )

        while MONITOR_SERVER:
            client_socket, _ = server_socket.accept()  # Accept incoming connections
            client_socket.settimeout(SOCKET_TIMEOUT)

            # Check current connection count before processing
            with USERS_LOCK:
                current_connections = len(AWAITING_USERS[port])

            threading.Thread(  # Handle each request in a separate thread
                target=lambda: HandleUserRequest(client_socket, file_path, port)
            ).start()


def StartStaticServers(max_connections=None):
    """
    Start all static content servers in separate threads.
    Creates one server for each port/file pair defined in PORTS and FILE_PATHS.
    Args:
        max_connections (int|list): Maximum connections per server.
                   If single int, applies to all servers.
                   If list, specifies per-server limits.
    """
    files = [FILE_PATHS["index1"], FILE_PATHS["index2"], FILE_PATHS["index3"]]
    if isinstance(max_connections, int):
        max_connections = [max_connections] * len(PORTS)
    elif max_connections is None:
        max_connections = [10] * len(PORTS)

    for port, file_path, max_conn in zip(PORTS, files, max_connections):
        LOGGER.LogInfo(
            f"Starting server on port {port} with max connections: {max_conn}"
        )
        threading.Thread(
            target=lambda p=port, f=file_path, m=max_conn: StaticServer(p, f, m)
        ).start()

    # Start loading server on LOADING_PORT with no connection cap
    LOGGER.LogInfo(
        f"Starting loading server on port {LOADING_PORT} with no max connections"
    )
    threading.Thread(
        target=lambda: StaticServer(
            LOADING_PORT, FILE_PATHS["loading"], max_connections=1000000
        )
    ).start()

    # Start disconnect server on DISCONNECT_PORT with no connection cap
    LOGGER.LogInfo(
        f"Starting disconnect server on port {DISCONNECT_PORT} with no max connections"
    )
    threading.Thread(
        target=lambda: StaticServer(
            DISCONNECT_PORT, FILE_PATHS["disconnect"], max_connections=1000000
        )
    ).start()


def FetchCurrentUser(session_id):
    """Fetch the current username based on the session ID."""
    if USER_SESSION_MANAGER.ValidateSession(session_id):
        return USER_SESSION_MANAGER.GetUsername(session_id)
    return None


def main():
    """
    Main entry point for the server application.
    Tests ports, sets up signal handling, starts all servers,
    and manages the main thread.
    """
    # First check if all ports are available
    if not TestPorts():
        LOGGER.LogError("Port test failed! Please check if ports are available.")
        sys.exit()

    # Log access information
    LOGGER.LogInfo(f"Server accessible at: http://{IP}:{ROUTING_PORT}")
    LOGGER.LogInfo(f"Monitoring interface at: http://{IP}:{MONITORING_PORT}")
    LOGGER.LogInfo(
        f"Direct access ports: {', '.join(f'http://{IP}:{port}' for port in PORTS)}"
    )

    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, SignalHandler)

    # Start background task for updating active users
    threading.Thread(target=UpdateActiveUsers, daemon=True).start()

    # Start all content servers in separate threads
    StartStaticServers([SERVER_CAPS[port] for port in PORTS])

    # Start monitoring server in a separate thread
    threading.Thread(target=MonitoringServer, daemon=True).start()

    # Start routing server on the main thread
    StartRoutingServer()


# Entry point when script is run directly

if __name__ == "__main__":
    main()
