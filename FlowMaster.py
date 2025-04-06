# TO IMPLEMENT SERVERS WITH DIFFERENT SIZES


import json
import signal
import socket
import sys
import threading
import time
from datetime import datetime, timedelta
import FlowMasterClasses

# CONFIGURATION CONSTANTS
current_username = None  # Variable to store the current username


# Function to handle user logout
def handle_logout():
    global current_username  # Use the global variable
    current_username = None  # Clear the current username
    # TO IMPLEMENT LOGIC TO DELETE SESSION COOKIE


monitor_server = True  # Flag to control monitoring server status
service_users = True  # Flag to control user service status
ip = socket.gethostbyname(
    socket.gethostname()
)  # Get the local machine's IP address automatically

# Ports for content servers and routing
ports = [8000, 8001, 8002]
routing_port = 8080  # Port for the load balancer
monitoring_port = 8081  # Port for the monitoring dashboard
socket_timeout = 5  # Socket timeout in seconds

# Paths to HTML files served by different servers
file_paths = {
    "index1": "html/index1.html",  # Server on port 8000
    "index2": "html/index2.html",  # Server on port 8001
    "index3": "html/index3.html",  # Server on port 8002
    "tracker": "html/tracker.html",  # Monitoring dashboard
    "login": "html/login.html",  # Login page
    "disconnect": "html/disconnect.html",  # Disconnect page
    "loading": "html/loading.html",  # Loading page
    "main.js": "js/main.js",  # Javascript for tracker
}

authenticated_sessions = {}  # Dictionary to track authenticated sessions
heartbeat_interval = 2.5  # Time between heartbeat checks (in seconds)
timeout_threshold = (
    1800  # Time after which a client is considered inactive (in seconds)
)
delay_between_routing = 0.35  # Delay between routing requests

# SHARED STATE AND SYNCHRONIZATION
active_users = {
    port: {} for port in ports + [monitoring_port]
}  # Track active users per port
denied_users = {}  # Track users we want to deny access

users_lock = (
    threading.Lock()
)  # Lock to protect the active_users dictionary during concurrent access

client_sockets = {}  # Dictionary to hold client sockets
connected_clients = (
    set()
)  # Set of unique client identifiers that have connected at least once

clients_lock = (
    threading.Lock()
)  # Lock to protect the connected_clients set during concurrent access

# Initialize the database and user session manager
usernames = FlowMasterClasses.Database(
    "PUP.db",
    ["Username", "Password", "Perm"],
    "UserPassPerm",
)  # Allowed usernames for logins
permissions = FlowMasterClasses.Database(
    "PUP.db",
    ["PermissionNum", "CanView", "CanDisconnect"],
    "Permissions",
) # Allowed permissions
user_session_manager = FlowMasterClasses.UserSession()  # Manage user sessions
logger = FlowMasterClasses.Logger("../server.log")  # Set up logging


def test_ports():
    """
    Test if all required ports are available before starting servers.
    Returns:
        bool: True if all ports are available, False otherwise.
    """
    for port in ports + [routing_port, monitoring_port]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_socket:
            try:
                test_socket.bind((ip, port))  # Try to bind to the port
            except socket.error:
                logger.log_error(f"Port {port} is not available!")
                return False
    return True


def signal_handler(*_):
    """
    Handle graceful shutdown on SIGINT (Ctrl+C).
    This ensures that the program exits cleanly when terminated by user.
    Args:
        *_: Ignored signal parameters.
    """
    global monitor_server, service_users, client_sockets
    logger.log_info("Shutting down server - waiting for 1 second")
    monitor_server = False
    service_users = False

    for _, PeerName in client_sockets.items():
        try:
            PeerName.shutdown()  # Drop the connection
        finally:
            pass

    time.sleep(1)  # Wait for a moment before exiting
    sys.exit(0)


def update_active_users():
    """
    Background task to maintain active user counts.
    Periodically checks for and removes inactive users based on
    their last activity timestamp. Runs continuously in a separate thread.
    """
    while service_users:
        time.sleep(heartbeat_interval)  # Wait between checks
        current_time = datetime.now()

        with users_lock:  # Ensure thread-safe access to shared data
            for port in ports + [monitoring_port]:
                # Find users who haven't sent a heartbeat within the threshold
                inactive_users = [
                    client_id
                    for client_id, last_active in active_users[port].items()
                    if (current_time - last_active)
                    > timedelta(seconds=timeout_threshold)
                ]

                # Remove inactive users
                for client_id in inactive_users:
                    del active_users[port][client_id]

            # Log current active user counts for monitoring
            logger.log_info("--- Current Active Users ---")
            for port in ports:
                logger.log_info(f"Port {port}: {len(active_users[port])} active users")


def get_server_loads():
    """
    Get the current load (number of active users) of each content server.
    Returns:
        dict: Dictionary mapping port numbers to user counts.
    """
    with users_lock:  # Protect shared data during read
        return {port: len(active_users[port]) for port in ports}


def get_monitoring_data():
    """
    Get comprehensive monitoring data for all servers.
    Formats data for the monitoring dashboard, including total counts
    and details about individual servers.
    Returns:
        dict: Dictionary with timestamp, per-server stats, and totals.
    """
    with users_lock:  # Protect shared data during read
        return {
            "timestamp": datetime.now().isoformat(),
            "servers": {
                str(port): {
                    "active_users": len(active_users[port]),
                    "users": list(active_users[port].keys()),
                }
                for port in ports
            },
            "total_users": sum(len(active_users[port]) for port in ports),
        }


def select_target_port():
    """
    Select the least loaded port for new connections (load balancing).
    Uses a simple algorithm: choose the server with the fewest active users.
    If multiple servers tie for the lowest load, selects the one with the lowest port number.
    Returns:
        int: The selected port number for the new connection.
    """
    loads = get_server_loads()
    logger.log_info(f"Current server loads: {json.dumps(loads)}")

    min_load = min(loads.values())  # Find the minimum load across all servers
    min_load_ports = [
        port for port, load in loads.items() if load == min_load
    ]  # Get all servers that have this minimum load

    # Use the lowest port number among the minimally loaded servers
    selected_port = min(min_load_ports)
    logger.log_info(f"Selected port {selected_port} with load {min_load}")
    return selected_port


def send_redirect(client_socket, port):
    """
    Send HTTP redirect response to client.
    Creates and sends a 302 Found HTTP response directing the client
    to the selected content server.
    Args:
        client_socket (socket): The client's socket connection.
        port (int): The port to redirect the client to.
    """
    redirect_response = (
        f"HTTP/1.1 302 Found\r\n" f"Location: http://{ip}:{port}/\r\n" "\r\n"
    ).encode()

    client_socket.sendall(redirect_response)
    logger.log_info(f"Sent redirect to port {port}")


def send_file(file_path: str, client_socket):
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
        with open(file_path, "rb") as file:  # Read the file content
            content = file.read()

        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: " + content_type.encode() + b"\r\n"
            b"Content-Length: " + str(len(content)).encode() + b"\r\n"
            b"\r\n" + content
        )
        client_socket.sendall(response)
        logger.log_info(f"Sent file: {file_path}")

    except FileNotFoundError:
        logger.log_warning(f"File not found: {file_path}")
        client_socket.sendall(
            b"HTTP/1.1 404 Not Found\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\nFile not found."
        )
    except Exception as e:
        logger.log_error(f"Error sending file: {str(e)}")
        client_socket.sendall(
            b"HTTP/1.1 500 Internal Server Error\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\nServer error."
        )


def handle_stats_request(client_socket):
    """
    Handle requests for monitoring statistics.
    Sends JSON-formatted monitoring data to the client.
    Args:
        client_socket (socket): The client's socket connection.
    """
    stats = get_monitoring_data()  # Get current monitoring statistics

    response = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: application/json\r\n"
        f"Access-Control-Allow-Origin: *\r\n"  # Allow cross-origin requests for dashboard
        f"X-Active-Users: {stats['total_users']}\r\n"  # Custom header with user count
        f"\r\n"
        f"{json.dumps(stats)}"  # Convert stats to JSON
    ).encode()

    client_socket.sendall(response)
    logger.log_info("Sent monitoring stats")


def user_info():
    """Endpoint to fetch the current username."""
    logger.log_info(
        f"User info request with session_id: {session_id}"
    )  # Log session ID for debugging

    # Get session ID from cookies
    session_id = request.cookies.get("session_id")

    # Debug log to see what session ID we're getting
    logger.log_info(f"User info request with session_id: {session_id}")

    # Get username from session
    username = (
        user_session_manager.get_username(session_id) if session_id else None
    )  # Get username from session
    logger.log_info(
        f"Found username: {username}"
    )  # Log the found username for debugging

    # Debug log to see what username we found
    logger.log_info(f"Found username: {username}")

    return jsonify({"username": username if username else "Unknown"})


def handle_user_request(client_socket, file_path, port):
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
        if not service_users or not monitor_server:
            sys.exit()

        data = client_socket.recv(9999).decode()  # Read data from client (HTTP request)

        if client_socket.fileno() == -1:  # Check if socket is still valid
            logger.log_error(f"Socket already closed on port {port}")
            return False

        client_id = None
        if "client_id=" in data:
            client_id = data.split("client_id=")[1].split(" ")[0]

        if client_id is not None and client_id in denied_users:
            # If user has been denied access, ignore him
            logger.log_info(f"Detected blocked access from {client_id} ({port})")
            msg = "Access has been denied"
            response = f"HTTP/1.1 403 Forbidden\r\nContent-Length: {len(msg)}\r\n\r\n{msg}".encode()
            client_socket.sendall(response)
            return True

        connection_type = "new"
        if client_id is not None:
            with clients_lock:  # Track if this is a new or continuing connection
                if client_id not in connected_clients:
                    connected_clients.add(client_id)
                else:
                    connection_type = "returning"

        logger.log_info(
            f"Detected '{connection_type}' connection from {client_id} on port {port}"
        )

        if client_id is not None and "/heartbeat" in data:
            with users_lock:
                active_users[port][
                    client_id
                ] = datetime.now()  # Update last active time for this client
                active_count = len(active_users[port])

            # Send minimal response with active user count in header
            msg = (
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                f"X-Active-Users: {active_count}\r\n"
                "Content-Length: 0\r\n\r\n"
            ).encode()

            client_socket.sendall(msg)
            return True

        if client_id is not None and "/leave" in data:  # Handle client leave requests
            with users_lock:
                if client_id in active_users[port]:
                    del active_users[port][client_id]

            msg = "{'response': 'leave received'}"
            client_socket.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Length: {len(msg)}\r\n\r\n{msg}".encode()
            )
            return True

        if port == routing_port:  # Handle routing server (load balancer) requests
            selected_port = select_target_port()
            send_redirect(client_socket, selected_port)
            return True

        # Handle content server requests
        if client_id is not None:
            with users_lock:
                active_users[port][client_id] = datetime.now()

        send_file(file_path, client_socket)

        return True

    except socket.timeout:
        logger.log_warning(f"Socket timeout occurred on port {port}")
    except Exception as e:
        logger.log_error(f"An error occurred on port {port}: {str(e)}")
    finally:
        try:  # Always ensure the socket is closed
            client_socket.close()  # Close the socket
        except Exception as e:
            logger.log_error(f"Error closing socket on port {port}: {str(e)}")
    return False


def can_disconnect(username, USERNAMES, PERMISSIONS):
    """
    Determines if a user has permission to disconnect based on their admin status.
    Args:
        username (str): The username to check permissions for
        USERNAMES (dict): Dictionary containing user information with structure {username: (password, is_admin)}
        PERMISSIONS (dict): Dictionary containing permission information
    Returns:
        bool: True if the user has permission to disconnect, False otherwise
    """
    # Check if the username exists in the database
    if username not in USERNAMES:
        return False

    # Get user information
    user_info = USERNAMES.get(username)

    # Check if user is an admin (admin flag is at index 1)
    if isinstance(user_info, tuple) and len(user_info) > 1:
        is_admin = user_info[1]
        # Convert to bool if it's not already
        if isinstance(is_admin, int):
            is_admin = bool(is_admin)
        return is_admin

    return False


def handle_monitor_request(client_socket, file_path, port):
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
        if not service_users or not monitor_server:
            sys.exit()

        data = client_socket.recv(9999).decode()  # Read data from client (HTTP request)
        logger.log_info(f"Received data on port {port}\n{str(data)}")

        if client_socket.fileno() == -1:  # Check if socket is still valid
            logger.log_error(f"Socket already closed on port {port}")
            return False

        # Extract request method and path
        request_line = data.split("\r\n")[0]
        method, path, _ = request_line.split(" ", 2)
        if "?" in path:
            # After the ? it is the query parameters, before is the path
            path, _ = path.split("?")

        # Extract client IP for session tracking
        client_ip = client_socket.getpeername()[0]  # TO IMPLEMENT

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
            return handle_login_request(client_socket, data)

        # Check if user is authenticated or requesting login page
        is_authenticated = user_session_manager.validate_session(session_id)

        # Root path or empty path should serve login if not authenticated
        if path == "/" or path == "":
            if is_authenticated:
                # Get the tracker.html file content
                send_file(file_paths["tracker"], client_socket)
                logger.log_info(f"Sent tracker.html with username: {current_username}")
            else:
                send_file(file_paths["login"], client_socket)  # Serve login.html
            return True

        # Explicitly handle tracker.html request
        if path == "/tracker.html":
            if is_authenticated:
                # Get the tracker.html file content
                send_file(file_paths["tracker"], client_socket)  # Fallback
                logger.log_info(f"Sent tracker.html with username: {current_username}")
            else:
                send_redirect_to_login(client_socket)  # Redirect to log in
            return True

        # Explicitly handle login.html request
        if path == "/login.html":
            send_file(file_paths["login"], client_socket)  # Always serve login page
            return True

        # Handle stats request (for authenticated users only)
        if "/stats" in path:
            if is_authenticated:
                handle_stats_request(client_socket)
            else:
                send_redirect_to_login(client_socket)
            return True

        if "/disconnect" in path:  # Handle client leave requests
            if not usernames.GetSecondOfArray(current_username) == 1:
                msg = "{'response': 'missing permissions'}"
                client_socket.sendall(
                    f"HTTP/1.1 200 OK\r\nContent-Length: {len(msg)}\r\n\r\n{msg}".encode()
                )
                logger.log_info("Did not have proper permissions to Disconnect")
                return True

            if not is_authenticated:
                send_redirect_to_login(client_socket)
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
                msg = "{'response': 'disconnect failed'}"
                client_socket.sendall(
                    f"HTTP/1.1 200 OK\r\nContent-Length: {len(msg)}\r\n\r\n{msg}".encode()
                )
                return True

            with users_lock:
                for check_port in ports + [monitoring_port]:
                    if user_id in active_users[check_port]:
                        del active_users[check_port][user_id]

                denied_users[user_id] = True

            msg = "{'response': 'disconnect received'}"
            client_socket.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Length: {len(msg)}\r\n\r\n{msg}".encode()
            )
            return True

        # If we are authenticated and we are asked for /user-info return it
        if is_authenticated and path == "/user-info":
            response_json = json.dumps({"username": current_username})

            headers = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: application/json\r\n"
                f"Set-Cookie: session_id={session_id}; Path=/; HttpOnly; SameSite=Lax\r\n"
                f"Content-Length: {len(response_json)}\r\n"
                f"\r\n"
            )

            client_socket.sendall((headers + response_json).encode())
            return True

        # For other requests, check authentication
        if not is_authenticated:
            send_redirect_to_login(client_socket)
            return True

        # Default: serve the requested file
        no_leading_slash_path = path.removeprefix("/")
        for _, item in file_paths.items():
            if item == no_leading_slash_path:
                send_file(no_leading_slash_path, client_socket)
                return True

        # Return the default page
        send_file(file_path, client_socket)
        return True

    except socket.timeout:
        logger.log_warning(f"Socket timeout occurred on port {port}")
    except Exception as e:
        logger.log_error(f"An error occurred on port {port}: {str(e)}")
    finally:
        try:  # Always ensure the socket is closed
            client_socket.close()
        except Exception as e:
            logger.log_error(f"Error closing socket on port {port}: {str(e)}")
    return False


def send_redirect_to_login(client_socket):
    """Send HTTP redirect to login page
    Args:
        client_socket (socket): The client's socket connection.
    """
    redirect_response = (
        f"HTTP/1.1 302 Found\r\n"
        f"Location: http://{ip}:{monitoring_port}/login.html\r\n"
        f"\r\n"
    ).encode()

    client_socket.sendall(redirect_response)
    logger.log_info("Redirected unauthenticated user to login page")


def handle_login_request(client_socket, data):
    """Handle login POST requests
    Args:
        client_socket (socket): The client's socket connection.
        data (str): The HTTP request data.
    Returns:
        bool: True if request was handled successfully.
    """
    global current_username  # Access the global variable

    try:
        # Extract the request body
        body = data.split("\r\n\r\n")[1]
        login_data = json.loads(body)

        username = login_data.get("username")
        password = login_data.get("password")

        # Check credentials against USERNAMES dictionary
        if (
            username in usernames.user_library
            and usernames.user_library[username][0] == password
        ):
            # Update current_username when login is successful
            current_username = username

            # Generate a session ID
            session_id = user_session_manager.create_session(current_username)
            response = {
                "success": True,
                "message": "Login successful",
                "redirect": f"http://{ip}:{monitoring_port}/tracker.html",
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
            logger.log_info(f"User {username} logged in successfully")
            current_username = username
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
            logger.log_info(f"Failed login attempt for user {username}")

        return True
    except Exception as e:
        logger.log_error(f"Error handling login: {str(e)}")
        error_response = json.dumps({"success": False, "message": "Server error"})
        client_socket.sendall(
            f"HTTP/1.1 500 Internal Server Error\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(error_response)}\r\n"
            f"\r\n{error_response}".encode()
        )
        return True


def monitoring_server():
    """
    Start the monitoring server that provides the dashboard and stats API.
    This server runs on its own thread and handles requests for monitoring data.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((ip, monitoring_port))
        server_socket.listen()
        logger.log_info(f"Monitoring server listening on: {ip}:{monitoring_port}")

        while monitor_server:
            client_socket, _ = server_socket.accept()  # Accept incoming connections
            client_socket.settimeout(socket_timeout)
            Client_PeerName = f"{client_socket.getpeername()}"
            client_sockets[Client_PeerName] = client_socket

            threading.Thread(  # Handle each request in a separate thread
                target=lambda: handle_monitor_request(
                    client_socket,
                    file_paths["login"],
                    monitoring_port,  # Default to login page
                )
            ).start()


def start_routing_server():
    """
    Start the main routing server (load balancer).
    This is the main entry point for clients and redirects them to the
    least loaded content server. Runs on the main thread.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as routing_socket:
        routing_socket.bind((ip, routing_port))
        routing_socket.listen()
        logger.log_info(f"Routing server listening on: {ip}:{routing_port}")

        last_routing_time = time.time()

        while True:
            client_socket, _ = routing_socket.accept()  # Accept incoming connections
            client_socket.settimeout(socket_timeout)

            current_time = time.time()  # Implement rate limiting for routing requests
            time_since_last = current_time - last_routing_time

            # If too little time has passed since last routing, add a delay
            if time_since_last < delay_between_routing:
                time.sleep(delay_between_routing - time_since_last)

            last_routing_time = time.time()  # Update last routing time

            threading.Thread(  # Handle each routing request in a separate thread
                target=lambda: handle_user_request(client_socket, None, routing_port)
            ).start()


def static_server(port, file_path):
    """
    Start a static content server on a specific port.
    Each static server serves one HTML file and handles client tracking.
    Args:
        port (int): Port number to listen on.
        file_path (str): Path to the HTML file to serve.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((ip, port))
        server_socket.listen()
        logger.log_info(f"Static server listening on: {ip}:{port}")

        while monitor_server:
            client_socket, _ = server_socket.accept()  # Accept incoming connections
            client_socket.settimeout(socket_timeout)

            threading.Thread(  # Handle each request in a separate thread
                target=lambda: handle_user_request(client_socket, file_path, port)
            ).start()


def start_static_servers():
    """
    Start all static content servers in separate threads.
    Creates one server for each port/file pair defined in PORTS and FILE_PATHS.
    """
    files = [file_paths["index1"], file_paths["index2"], file_paths["index3"]]
    for port, file_path in zip(ports, files):  # Exclude monitoring page
        threading.Thread(
            target=lambda p=port, f=file_path: static_server(p, f)
        ).start()  # Create a new thread for each static server


def main():
    """
    Main entry point for the server application.
    Tests ports, sets up signal handling, starts all servers,
    and manages the main thread.
    """
    # First check if all ports are available
    if not test_ports():
        logger.log_error("Port test failed! Please check if ports are available.")
        sys.exit()

    # Log access information
    logger.log_info(f"Server accessible at: http://{ip}:{routing_port}")
    logger.log_info(f"Monitoring interface at: http://{ip}:{monitoring_port}")
    logger.log_info(
        f"Direct access ports: {', '.join(f'http://{ip}:{port}' for port in ports)}"
    )

    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)

    # Start background task for updating active users
    threading.Thread(target=update_active_users, daemon=True).start()

    # Start all content servers in separate threads
    start_static_servers()

    # Start monitoring server in a separate thread
    threading.Thread(target=monitoring_server, daemon=True).start()

    # Start routing server on the main thread
    start_routing_server()


def fetchCurrentUser(session_id):
    """Fetch the current username based on the session ID."""
    if user_session_manager.validate_session(session_id):
        return user_session_manager.get_username(session_id)
    return None


# Entry point when script is run directly

if __name__ == "__main__":
    main()