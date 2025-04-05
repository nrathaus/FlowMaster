# TO IMPLEMENT SERVERS WITH DIFFERENT SIZES

import json
import signal
import socket
import sys
import threading
import time
from datetime import datetime, timedelta
from urllib import request
import FlowMasterClasses

# CONFIGURATION CONSTANTS
CURRENT_USERNAME = None  # Variable to store the current username
MONITOR_SERVER = True  # Flag to control monitoring server status
SERVICE_USERS = True  # Flag to control user service status
IP = socket.gethostbyname(
    socket.gethostname()
)  # Get the local machine's IP address automatically

# Ports for content servers and routing
PORTS = [8000, 8001, 8002]  # List of ports for content servers
ROUTING_PORT = 8080  # Port for the load balancer
MONITORING_PORT = 8081  # Port for the monitoring dashboard
SOCKET_TIMEOUT = 5  # Socket timeout in seconds

# Paths to HTML files served by different servers
FILE_PATHS = {
    "index1": "html/index1.html",  # Server on port 8000
    "index2": "html/index2.html",  # Server on port 8001
    "index3": "html/index3.html",  # Server on port 8002
    "tracker": "html/tracker.html",  # Monitoring dashboard
    "login": "html/login.html",  # Login page
    "main.js": "js/main.js",  # Javascript for tracker
}

authenticated_sessions = {}  # Dictionary to track authenticated sessions
HEARTBEAT_INTERVAL = 2.5  # Time between heartbeat checks (in seconds)
TIMEOUT_THRESHOLD = (
    1800  # Time after which a client is considered inactive (in seconds)
)
DELAY_BETWEEN_ROUTING = 0.35  # Delay between routing requests

# SHARED STATE AND SYNCHRONIZATION
ACTIVE_USERS = {
    port: {} for port in PORTS + [MONITORING_PORT]
}  # Track active users per port
DENIED_USERS = {}  # Track users we want to deny access

USERS_LOCK = (
    threading.Lock()
)  # Lock to protect the ACTIVE_USERS dictionary during concurrent access

CLIENT_SOCKETS = {}  # Dictionary to hold client sockets
CONNECTED_CLIENTS = (
    set()
)  # Set of unique client identifiers that have connected at least once

CLIENTS_LOCK = (
    threading.Lock()
)  # Lock to protect the CONNECTED_CLIENTS set during concurrent access

# Initialize the database and user session manager
USERNAMES = FlowMasterClasses.Database(
    "PUP.db",
    ["Username", "Password", "Perm"],
    "User PassPerm",
)  # Allowed usernames for logins
PERMISSIONS = FlowMasterClasses.Database(
    "PUP.db",
    ["PermissionNum", "CanView", "CanDisconnect"],
    "Permissions",
)  # Allowed permissions
USER_SESSION_MANAGER = FlowMasterClasses.UserSession()  # Manage user sessions
LOGGER = FlowMasterClasses.Logger("../server.log")  # Set up logging


# Function to handle user logout
def FandleLogout():
    global CURRENT_USERNAME  # Use the global variable
    CURRENT_USERNAME = None  # Clear the current username
    # TO IMPLEMENT LOGIC TO DELETE SESSION COOKIE


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
            except socket.error:
                LOGGER.log_error(
                    f"Port {port} is not available!"
                )  # Log error if port is not available
                return False
    return True  # All ports are available


def SignalHandler(*_):
    """
    Handle graceful shutdown on SIGINT (Ctrl+C).
    This ensures that the program exits cleanly when terminated by user.
    Args:
        *_: Ignored signal parameters.
    """
    global MONITOR_SERVER, SERVICE_USERS, CLIENT_SOCKETS
    LOGGER.log_info(
        "Shutting down server - waiting for 1 second"
    )  # Log shutdown message
    MONITOR_SERVER = False  # Stop monitoring server
    SERVICE_USERS = False  # Stop user services

    for _, PeerName in CLIENT_SOCKETS.items():
        try:
            PeerName.shutdown()  # Drop the connection
        finally:
            pass

    time.sleep(1)  # Wait for a moment before exiting
    sys.exit(0)  # Exit the program


def UpdateActiveUsers():
    """
    Background task to maintain active user counts.
    Periodically checks for and removes inactive users based on
    their last activity timestamp. Runs continuously in a separate thread.
    """
    while SERVICE_USERS:
        time.sleep(HEARTBEAT_INTERVAL)  # Wait between checks
        current_time = datetime.now()  # Get the current time

        with USERS_LOCK:  # Ensure thread-safe access to shared data
            for port in PORTS + [MONITORING_PORT]:
                # Find users who haven't sent a heartbeat within the threshold
                inACTIVE_USERS = [
                    client_id
                    for client_id, last_active in ACTIVE_USERS[port].items()
                    if (current_time - last_active)
                    > timedelta(seconds=TIMEOUT_THRESHOLD)
                ]

                # Remove inactive users
                for client_id in inACTIVE_USERS:
                    del ACTIVE_USERS[port][client_id]

            # Log current active user counts for monitoring
            LOGGER.log_info("--- Current Active Users ---")
            for port in PORTS:
                LOGGER.log_info(f"Port {port}: {len(ACTIVE_USERS[port])} active users")


def GetServerLoads():
    """
    Get the current load (number of active users) of each content server.
    Returns:
        dict: Dictionary mapping port numbers to user counts.
    """
    with USERS_LOCK:  # Protect shared data during read
        return {
            port: len(ACTIVE_USERS[port]) for port in PORTS
        }  # Return the number of active users per port


def GetMonitoringData():
    """
    Get comprehensive monitoring data for all servers.
    Formats data for the monitoring dashboard, including total counts
    and details about individual servers.
    Returns:
        dict: Dictionary with timestamp, per-server stats, and totals.
    """
    with USERS_LOCK:  # Protect shared data during read
        return {
            "timestamp": datetime.now().isoformat(),  # Current timestamp
            "servers": {
                str(port): {
                    "ACTIVE_USERS": len(ACTIVE_USERS[port]),  # Count of active users
                    "users": list(ACTIVE_USERS[port].keys()),  # List of active user IDs
                }
                for port in PORTS
            },
            "total_users": sum(
                len(ACTIVE_USERS[port]) for port in PORTS
            ),  # Total active users across all servers
        }


def SelectTargetPort():
    """
    Select the least loaded port for new connections (load balancing).
    Uses a simple algorithm: choose the server with the fewest active users.
    If multiple servers tie for the lowest load, selects the one with the lowest port number.
    Returns:
        int: The selected port number for the new connection.
    """
    loads = GetServerLoads()  # Get current server loads
    LOGGER.log_info(f"Current server loads: {json.dumps(loads)}")  # Log current loads

    min_load = min(loads.values())  # Find the minimum load across all servers
    min_load_ports = [
        port for port, load in loads.items() if load == min_load
    ]  # Get all servers that have this minimum load

    # Use the lowest port number among the minimally loaded servers
    selected_port = min(min_load_ports)
    LOGGER.log_info(
        f"Selected port {selected_port} with load {min_load}"
    )  # Log selected port
    return selected_port  # Return the selected port


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
    ).encode()  # Create redirect response

    client_socket.sendall(redirect_response)  # Send redirect response to client
    LOGGER.log_info(f"Sent redirect to port {port}")  # Log redirect action


def SendFile(file_path: str, client_socket):
    """
    Send file content to client with proper HTTP headers.
    Args:
        file_path (str): Path to the file to send.
        client_socket (socket): The client's socket connection.
    """

    content_type = "text/html"  # Default content type
    if file_path.endswith(".js"):
        content_type = "application/javascript"  # Set content type for JavaScript files

    try:
        with open(file_path, "rb") as file:  # Read the file content
            content = file.read()  # Read the entire file

        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: " + content_type.encode() + b"\r\n"
            b"Content-Length: " + str(len(content)).encode() + b"\r\n"
            b"\r\n" + content  # Combine headers and content
        )
        client_socket.sendall(response)  # Send response to client
        LOGGER.log_info(f"Sent file: {file_path}")  # Log file sent

    except FileNotFoundError:
        LOGGER.log_warning(
            f"File not found: {file_path}"
        )  # Log warning if file not found
        client_socket.sendall(
            b"HTTP/1.1 404 Not Found\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\nFile not found."  # Send 404 response
        )
    except Exception as e:
        LOGGER.log_error(f"Error sending file: {str(e)}")  # Log error if sending fails
        client_socket.sendall(
            b"HTTP/1.1 500 Internal Server Error\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\nServer error."  # Send 500 response
        )


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

    client_socket.sendall(response)  # Send monitoring stats to client
    LOGGER.log_info("Sent monitoring stats")  # Log stats sent


def UserInfo():
    """Endpoint to fetch the current username."""
    LOGGER.log_info(
        f"User  info request with session_id: {session_id}"
    )  # Log session ID for debugging

    # Get session ID from cookies
    session_id = request.cookies.get("session_id")

    # Debug log to see what session ID we're getting
    LOGGER.log_info(f"User  info request with session_id: {session_id}")

    # Get username from session
    username = (
        USER_SESSION_MANAGER.get_username(session_id) if session_id else None
    )  # Get username from session
    LOGGER.log_info(
        f"Found username: {username}"
    )  # Log the found username for debugging

    # Debug log to see what username we found
    LOGGER.log_info(f"Found username: {username}")

    response_json = json.dumps({"username": username if username else "Unknown"})
    return f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(response_json)}\r\n\r\n{response_json}"


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
            sys.exit()  # Exit if services are not running

        data = client_socket.recv(9999).decode()  # Read data from client (HTTP request)
        LOGGER.log_info(
            f"Received data on port {port}\n{str(data)}"
        )  # Log received data

        if client_socket.fileno() == -1:  # Check if socket is still valid
            LOGGER.log_error(
                f"Socket already closed on port {port}"
            )  # Log error if socket is closed
            return False

        client_id = None
        if "client_id=" in data:
            client_id = data.split("client_id=")[1].split(" ")[
                0
            ]  # Extract client ID from request

        if client_id is not None and client_id in DENIED_USERS:
            # If user has been denied access, ignore him
            LOGGER.log_info(f"Detected blocked access from {client_id} ({port})")
            msg = "Access has been denied"
            response = f"HTTP/1.1 403 Forbidden\r\nContent-Length: {len(msg)}\r\n\r\n{msg}".encode()
            client_socket.sendall(response)  # Send 403 response
            return True

        connection_type = "new"
        if client_id is not None:
            with CLIENTS_LOCK:  # Track if this is a new or continuing connection
                if client_id not in CONNECTED_CLIENTS:
                    CONNECTED_CLIENTS.add(
                        client_id
                    )  # Add new client ID to connected clients
                else:
                    connection_type = "returning"  # Mark as returning client

        LOGGER.log_info(
            f"Detected '{connection_type}' connection from {client_id} on port {port}"
        )  # Log connection type

        if client_id is not None and "/heartbeat" in data:
            with USERS_LOCK:
                ACTIVE_USERS[port][
                    client_id
                ] = datetime.now()  # Update last active time for this client
                active_count = len(ACTIVE_USERS[port])  # Get active user count

            # Send minimal response with active user count in header
            msg = (
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                f"X-Active-Users: {active_count}\r\n"
                "Content-Length: 0\r\n\r\n"
            ).encode()

            client_socket.sendall(msg)  # Send heartbeat response
            return True

        if client_id is not None and "/leave" in data:  # Handle client leave requests
            with USERS_LOCK:
                if client_id in ACTIVE_USERS[port]:
                    del ACTIVE_USERS[port][client_id]  # Remove client from active users

            msg = "{'response': 'leave received'}"
            client_socket.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Length: {len(msg)}\r\n\r\n{msg}".encode()
            )  # Send leave response
            return True

        if port == ROUTING_PORT:  # Handle routing server (load balancer) requests
            selected_port = SelectTargetPort()  # Select least loaded port
            SendRedirect(client_socket, selected_port)  # Redirect client
            return True

        # Handle content server requests
        if client_id is not None:
            with USERS_LOCK:
                ACTIVE_USERS[port][
                    client_id
                ] = datetime.now()  # Update last active time

        SendFile(file_path, client_socket)  # Send requested file

        return True

    except socket.timeout:
        LOGGER.log_warning(
            f"Socket timeout occurred on port {port}"
        )  # Log socket timeout
    except Exception as e:
        LOGGER.log_error(
            f"An error occurred on port {port}: {str(e)}"
        )  # Log any other errors
    finally:
        try:  # Always ensure the socket is closed
            client_socket.close()  # Close the socket
        except Exception as e:
            LOGGER.log_error(
                f"Error closing socket on port {port}: {str(e)}"
            )  # Log error on closing socket
    return False


def CanDisconnect(username, USERNAMES, PERMISSIONS):
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
        return False  # User does not exist

    # Get user information
    user_info = USERNAMES.get(username)

    # Check if user is an admin (admin flag is at index 1)
    if isinstance(user_info, tuple) and len(user_info) > 1:
        is_admin = user_info[1]  # Get admin status
        # Convert to bool if it's not already
        if isinstance(is_admin, int):
            is_admin = bool(is_admin)
        return is_admin  # Return admin status

    return False  # User is not an admin


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
            sys.exit()  # Exit if services are not running

        data = client_socket.recv(9999).decode()  # Read data from client (HTTP request)
        LOGGER.log_info(
            f"Received data on port {port}\n{str(data)}"
        )  # Log received data

        if client_socket.fileno() == -1:  # Check if socket is still valid
            LOGGER.log_error(
                f"Socket already closed on port {port}"
            )  # Log error if socket is closed
            return False

        # Extract request method and path
        request_line = data.split("\r\n")[0]  # Get the first line of the request
        method, path, _ = request_line.split(
            " ", 2
        )  # Split the request line into method, path, and version
        if "?" in path:
            # After the ? it is the query parameters, before is the path
            path, _ = path.split("?")  # Remove query parameters

        # Extract client IP for session tracking
        client_ip = client_socket.getpeername()[
            0
        ]  # Get client IP address (TO IMPLEMENT)

        # Check for cookies to identify session
        session_id = None
        if "Cookie:" in data:
            cookie_line = [
                line for line in data.split("\r\n") if line.startswith("Cookie:")
            ][
                0
            ]  # Find the cookie line
            cookies = cookie_line.split(":", 1)[1].strip()  # Get the cookie value
            cookie_parts = cookies.split(";")  # Split cookies by semicolon
            for part in cookie_parts:
                if "session_id=" in part:
                    session_id = part.split("=", 1)[1].strip()  # Extract session ID
                    break

        # Check if this is a login request
        if path == "/login" and method == "POST":
            return HandleLoginRequest(client_socket, data)  # Handle login request

        # Check if user is authenticated or requesting login page
        is_authenticated = USER_SESSION_MANAGER.validate_session(
            session_id
        )  # Validate session

        # Root path or empty path should serve login if not authenticated
        if path == "/" or path == "":
            if is_authenticated:
                # Get the tracker.html file content
                SendFile(FILE_PATHS["tracker"], client_socket)  # Serve tracker page
                LOGGER.log_info(f"Sent tracker.html with username: {CURRENT_USERNAME}")
            else:
                SendFile(FILE_PATHS["login"], client_socket)  # Serve login.html
            return True

        # Explicitly handle tracker.html request
        if path == "/tracker.html":
            if is_authenticated:
                # Get the tracker.html file content
                SendFile(FILE_PATHS["tracker"], client_socket)  # Serve tracker page
                LOGGER.log_info(f"Sent tracker.html with username: {CURRENT_USERNAME}")
            else:
                SendRedirectToLogin(client_socket)  # Redirect to log in
            return True

        # Explicitly handle login.html request
        if path == "/login.html":
            SendFile(FILE_PATHS["login"], client_socket)  # Always serve login page
            return True

        # Handle stats request (for authenticated users only)
        if "/stats" in path:
            if is_authenticated:
                HandleStatsRequest(client_socket)  # Send stats if authenticated
            else:
                SendRedirectToLogin(
                    client_socket
                )  # Redirect to login if not authenticated
            return True

        if "/disconnect" in path:  # Handle client leave requests
            if (
                not USERNAMES.GetSecondOfArray(CURRENT_USERNAME) == 1
            ):  # Check permissions
                msg = "{'response': 'missing permissions'}"
                client_socket.sendall(
                    f"HTTP/1.1 200 OK\r\nContent-Length: {len(msg)}\r\n\r\n{msg}".encode()
                )  # Send response for missing permissions
                LOGGER.log_info("Did not have proper permissions to Disconnect")
                return True

            if not is_authenticated:
                SendRedirectToLogin(
                    client_socket
                )  # Redirect to login if not authenticated
                return True

            # Find the body inside the 'data'
            header_and_body = data.split("\r\n\r\n")  # Split headers and body
            user_id = None
            if len(header_and_body) > 1:
                body = header_and_body[1]  # Get the body part

                # Parse the body - it comes as JSON
                body_json = json.loads(body)  # Load JSON data

                if "userId" in body_json:
                    user_id = body_json["userId"]  # Extract user ID

            if user_id is None:
                msg = "{'response': 'disconnect failed'}"
                client_socket.sendall(
                    f"HTTP/1.1 200 OK\r\nContent-Length: {len(msg)}\r\n\r\n{msg}".encode()
                )  # Send response for disconnect failure
                return True

            with USERS_LOCK:
                for check_port in PORTS + [MONITORING_PORT]:
                    if user_id in ACTIVE_USERS[check_port]:
                        del ACTIVE_USERS[check_port][
                            user_id
                        ]  # Remove user from active users

                DENIED_USERS[user_id] = True  # Deny access to user

            msg = "{'response': 'disconnect received'}"
            client_socket.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Length: {len(msg)}\r\n\r\n{msg}".encode()
            )  # Send response for disconnect received
            return True

        # If we are authenticated and we are asked for /user-info return it
        if is_authenticated and path == "/user-info":
            response_json = json.dumps(
                {"username": CURRENT_USERNAME}
            )  # Prepare user info response

            headers = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: application/json\r\n"
                f"Set-Cookie: session_id={session_id}; Path=/; HttpOnly; SameSite=Lax\r\n"
                f"Content-Length: {len(response_json)}\r\n"
                f"\r\n"
            )

            client_socket.sendall(
                (headers + response_json).encode()
            )  # Send user info response
            return True

        # For other requests, check authentication
        if not is_authenticated:
            SendRedirectToLogin(client_socket)  # Redirect to login if not authenticated
            return True

        # Default: serve the requested file
        no_leading_slash_path = path.removeprefix("/")  # Remove leading slash from path
        for _, item in FILE_PATHS.items():
            if item == no_leading_slash_path:
                SendFile(no_leading_slash_path, client_socket)  # Serve requested file
                return True

        # Return the default page
        SendFile(file_path, client_socket)  # Serve default file
        return True

    except socket.timeout:
        LOGGER.log_warning(
            f"Socket timeout occurred on port {port}"
        )  # Log socket timeout
    except Exception as e:
        LOGGER.log_error(
            f"An error occurred on port {port}: {str(e)}"
        )  # Log any other errors
    finally:
        try:  # Always ensure the socket is closed
            client_socket.close()  # Close the socket
        except Exception as e:
            LOGGER.log_error(
                f"Error closing socket on port {port}: {str(e)}"
            )  # Log error on closing socket
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
    ).encode()  # Create redirect response to login page

    client_socket.sendall(redirect_response)  # Send redirect response to client
    LOGGER.log_info(
        "Redirected unauthenticated user to login page"
    )  # Log redirect action


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
        body = data.split("\r\n\r\n")[1]  # Get the body part of the request
        login_data = json.loads(body)  # Load JSON data from body

        username = login_data.get("username")  # Get username from login data
        password = login_data.get("password")  # Get password from login data

        # Check credentials against USERNAMES dictionary
        if (
            username in USERNAMES.user_library
            and USERNAMES.user_library[username][0] == password
        ):
            # Update CURRENT_USERNAME when login is successful
            CURRENT_USERNAME = username

            # Generate a session ID
            session_id = USER_SESSION_MANAGER.create_session(
                CURRENT_USERNAME
            )  # Create session
            response = {
                "success": True,
                "message": "Login successful",
                "redirect": f"http://{IP}:{MONITORING_PORT}/tracker.html",  # Redirect URL after login
            }
            response_json = json.dumps(response)  # Convert response to JSON

            headers = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: application/json\r\n"
                f"Set-Cookie: session_id={session_id}; Path=/; HttpOnly; SameSite=Lax\r\n"
                f"Content-Length: {len(response_json)}\r\n"
                f"\r\n"
            )

            client_socket.sendall(
                (headers + response_json).encode()
            )  # Send login success response
            LOGGER.log_info(
                f"User  {username} logged in successfully"
            )  # Log successful login
            CURRENT_USERNAME = username  # Update current username
        else:
            # Send failure response
            response = {
                "success": False,
                "message": "Invalid username or password",
            }  # Prepare failure response
            response_json = json.dumps(response)  # Convert response to JSON

            headers = (
                f"HTTP/1.1 401 Unauthorized\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(response_json)}\r\n"
                f"\r\n"
            )

            client_socket.sendall(
                (headers + response_json).encode()
            )  # Send login failure response
            LOGGER.log_info(
                f"Failed login attempt for user {username}"
            )  # Log failed login

        return True  # Indicate request was handled successfully
    except Exception as e:
        LOGGER.log_error(f"Error handling login: {str(e)}")  # Log error handling login
        error_response = json.dumps(
            {"success": False, "message": "Server error"}
        )  # Prepare error response
        client_socket.sendall(
            f"HTTP/1.1 500 Internal Server Error\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(error_response)}\r\n"
            f"\r\n{error_response}".encode()
        )  # Send error response
        return True  # Indicate request was handled


def MonitoringServer():
    """
    Start the monitoring server that provides the dashboard and stats API.
    This server runs on its own thread and handles requests for monitoring data.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((IP, MONITORING_PORT))  # Bind to monitoring port
        server_socket.listen()  # Start listening for connections
        LOGGER.log_info(
            f"Monitoring server listening on: {IP}:{MONITORING_PORT}"
        )  # Log monitoring server start

        while MONITOR_SERVER:
            client_socket, _ = server_socket.accept()  # Accept incoming connections
            client_socket.settimeout(SOCKET_TIMEOUT)  # Set socket timeout
            Client_PeerName = f"{client_socket.getpeername()}"  # Get client peer name
            CLIENT_SOCKETS[Client_PeerName] = client_socket  # Store client socket

            threading.Thread(  # Handle each request in a separate thread
                target=lambda: HandleMonitorRequest(
                    client_socket,
                    FILE_PATHS["login"],
                    MONITORING_PORT,  # Default to login page
                )
            ).start()  # Start thread for handling request


def StartRoutingServer():
    """
    Start the main routing server (load balancer).
    This is the main entry point for clients and redirects them to the
    least loaded content server. Runs on the main thread.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as routing_socket:
        routing_socket.bind((IP, ROUTING_PORT))  # Bind to routing port
        routing_socket.listen()  # Start listening for connections
        LOGGER.log_info(
            f"Routing server listening on: {IP}:{ROUTING_PORT}"
        )  # Log routing server start

        last_routing_time = time.time()  # Initialize last routing time

        while True:
            client_socket, _ = routing_socket.accept()  # Accept incoming connections
            client_socket.settimeout(SOCKET_TIMEOUT)  # Set socket timeout

            current_time = time.time()  # Implement rate limiting for routing requests
            time_since_last = (
                current_time - last_routing_time
            )  # Calculate time since last routing

            # If too little time has passed since last routing, add a delay
            if time_since_last < DELAY_BETWEEN_ROUTING:
                time.sleep(
                    DELAY_BETWEEN_ROUTING - time_since_last
                )  # Sleep to enforce delay

            last_routing_time = time.time()  # Update last routing time

            threading.Thread(  # Handle each routing request in a separate thread
                target=lambda: HandleUserRequest(
                    client_socket, None, ROUTING_PORT
                )  # Handle user request
            ).start()  # Start thread for handling request


def StaticServer(port, file_path):
    """
    Start a static content server on a specific port.
    Each static server serves one HTML file and handles client tracking.
    Args:
        port (int): Port number to listen on.
        file_path (str): Path to the HTML file to serve.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((IP, port))  # Bind to specified port
        server_socket.listen()  # Start listening for connections
        LOGGER.log_info(
            f"Static server listening on: {IP}:{port}"
        )  # Log static server start

        while MONITOR_SERVER:
            client_socket, _ = server_socket.accept()  # Accept incoming connections
            client_socket.settimeout(SOCKET_TIMEOUT)  # Set socket timeout

            threading.Thread(  # Handle each request in a separate thread
                target=lambda: HandleUserRequest(
                    client_socket, file_path, port
                )  # Handle user request
            ).start()  # Start thread for handling request


def StartStaticServers():
    """
    Start all static content servers in separate threads.
    Creates one server for each port/file pair defined in PORTS and FILE_PATHS.
    """
    files = [
        FILE_PATHS["index1"],
        FILE_PATHS["index2"],
        FILE_PATHS["index3"],
    ]  # List of files to serve
    for port, file_path in zip(PORTS, files):  # Exclude monitoring page
        threading.Thread(
            target=lambda p=port, f=file_path: StaticServer(
                p, f
            )  # Start static server for each port/file
        ).start()  # Create a new thread for each static server


def FetchCurrentUser(session_id):
    """Fetch the current username based on the session ID."""
    if USER_SESSION_MANAGER.validate_session(session_id):  # Validate session
        return USER_SESSION_MANAGER.get_username(
            session_id
        )  # Return username if session is valid
    return None  # Return None if session is invalid


def main():
    """
    Main entry point for the server application.
    Tests ports, sets up signal handling, starts all servers,
    and manages the main thread.
    """
    # First check if all ports are available
    if not TestPorts():
        LOGGER.log_error(
            "Port test failed! Please check if ports are available."
        )  # Log error if ports are not available
        sys.exit()  # Exit if ports are not available

    # Log access information
    LOGGER.log_info(
        f"Server accessible at: http://{IP}:{ROUTING_PORT}"
    )  # Log routing server URL
    LOGGER.log_info(
        f"Monitoring interface at: http://{IP}:{MONITORING_PORT}"
    )  # Log monitoring server URL
    LOGGER.log_info(
        f"Direct access ports: {', '.join(f'http://{IP}:{port}' for port in PORTS)}"  # Log direct access ports
    )

    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, SignalHandler)  # Handle Ctrl+C for graceful shutdown

    # Start background task for updating active users
    threading.Thread(
        target=UpdateActiveUsers, daemon=True
    ).start()  # Start updating active users in background

    # Start all content servers in separate threads
    StartStaticServers()  # Start static content servers

    # Start monitoring server in a separate thread
    threading.Thread(
        target=MonitoringServer, daemon=True
    ).start()  # Start monitoring server in background

    # Start routing server on the main thread
    StartRoutingServer()  # Start routing server


# Entry point when script is run directly
if __name__ == "__main__":
    main()  # Call the main function to start the server
