import json  # Import JSON for handling JSON data
import signal  # Import signal for handling signals
import socket  # Import socket for network communication
import sys  # Import sys for system-specific parameters and functions
import threading  # Import threading for multi-threading support
import time  # Import time for time-related functions
from datetime import (
    datetime,
    timedelta,
)  # Import datetime and timedelta for date and time manipulation
import hashlib  # Import hashlib for hashing data
import FlowMasterClasses  # Import FlowMasterClasses for custom classes and functions

# LOGGER INITIALIZATION
LOGGER = FlowMasterClasses.Logger("../server.log")

# CONFIGURATION CONSTANTS
CURRENT_USERNAME = None  # Variable to store the current username
MONITOR_SERVER = True  # Flag to control monitoring server status
SERVICE_USERS = True  # Flag to control user service status
IP = socket.gethostbyname(
    socket.gethostname()
)  # Get the local machine's IP address automatically
PORTS = [8000, 8001, 8002]  # Ports for content servers
ACTUAL_CAPS = {
    8000: 600, # 20%
    8001: 1500, # 50%
    8002: 900, # 30%
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


if len(PORTS) != len(
    SERVER_CAPS
):  # Check if the number of ports matches the number of server capabilities
    LOGGER.LogError("Ports and their capabilities list don't match")
FOUND_PORTS = []  # List to store the available ports
for port in PORTS:
    if port not in SERVER_CAPS:  # Check if the port is in the server capabilities list
        LOGGER.LogError(f"Port '{port}' missing its capability")
    FOUND_PORTS.append(port)  # Add the port to the found ports list
if len(FOUND_PORTS) != len(
    PORTS
):  # Check if the number of found ports matches the number of ports
    LOGGER.LogError(
        f"Ports list contains duplicates or missing ports, found ports: {FOUND_PORTS}, vs: {PORTS}"
    )

ROUTING_PORT = 8080  # Port for the load balancer
MONITORING_PORT = 8081  # Port for the monitoring dashboard
SOCKET_TIMEOUT = 5  # Socket timeout in seconds
AUTHENTICATED_SESSIONS = {}  # Dictionary to track authenticated sessions
HEARTBEAT_INTERVAL = 2.5  # Time between heartbeat checks (in seconds)
TIMEOUT_THRESHOLD = 600  # Time after which a client is considered inactive (in seconds)
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
AWAITING_USERS = {
    port: {} for port in PORTS + [MONITORING_PORT, LOADING_PORT, DISCONNECT_PORT]
}  # Track active users per port and users in queue
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
USERNAMES = FlowMasterClasses.DataBase(
    "PUP.db", ["Username", "Password", "Perm"], "UserPassPerm"
)  # Allowed usernames for logins
PERMISSIONS = FlowMasterClasses.DataBase(
    "PUP.db", ["PermissionNum", "CanView", "CanDisconnect"], "Permissions"
)  # Allowed permissions
PERMCANDISCONNECT = [
    key
    for key, perm in PERMISSIONS.user_library.items()
    if len(perm) > 1 and perm[1] == True
]  # Permissions that allow disconnecting users
USER_SESSION_MANAGER = FlowMasterClasses.UserSession()  # Manage user sessions


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
    Handles graceful shutdown of the server upon receiving a SIGINT (Ctrl+C) signal.
    This function ensures that the server and its associated resources are properly
    terminated, including shutting down client connections and stopping server operations.
        *_: Ignored signal parameters, typically signal number and frame.
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
    Hashes a given string using the MD5 algorithm.

    This function provides a convenient way to generate an MD5 hash for a given string.

        string (str): The input string to be hashed.

        str: The MD5 hash of the input string as a hexadecimal string.
    """
    return hashlib.md5(string.encode()).hexdigest()


def UpdateActiveUsers():
    """
    Monitors and updates the list of active users by removing inactive users
    based on their last heartbeat timestamp.
    This function runs in a loop, periodically checking the activity of users
    across specified ports. Users who have not sent a heartbeat within the
    defined timeout threshold are considered inactive and are removed from
    the active user list. The function also logs the current count of active
    users for monitoring purposes.
    Key Variables:
    - SERVICE_USERS: A flag indicating whether the service is running.
    - HEARTBEAT_INTERVAL: The interval (in seconds) between consecutive checks.
    - TIMEOUT_THRESHOLD: The maximum allowed time (in seconds) since the last
      heartbeat before a user is considered inactive.
    - USERS_LOCK: A threading lock to ensure thread-safe access to shared data.
    - AWAITING_USERS: A dictionary mapping ports to dictionaries of user IDs
      and their last active timestamps.
    - PORTS: A list of ports being monitored for user activity.
    - MONITORING_PORT: An additional port used for monitoring purposes.
    - LOGGER: A logging utility for recording information.
    Behavior:
    - Periodically checks user activity on all monitored ports.
    - Removes users who have been inactive beyond the timeout threshold.
    - Logs the number of active users for each port.
    Note:
    This function is designed to be run in a separate thread to continuously
    monitor user activity without blocking other operations.
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
    Fetches the current load of each content server.

    This function retrieves the number of active users for each content server by
    accessing shared data protected by a lock to ensure thread safety.

        dict: A dictionary where the keys are port numbers (int) and the values
        are the corresponding user counts (int) for each server.
    """
    with USERS_LOCK:  # Protect shared data during read
        return {port: len(AWAITING_USERS[port]) for port in PORTS}


def GetQueueData():
    """
    Retrieves data about the current state of the queue and server capacities.
    This function is thread-safe, utilizing locks to protect shared data during
    the read operation. It returns a dictionary containing the following information:
    - `timestamp`: The current timestamp in ISO 8601 format.
    - `waiting`: The number of items currently in the waiting queue.
    - `total`: The total number of items across all server capacities.
    Returns:
        dict: A dictionary with keys `timestamp`, `waiting`, and `total`.
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
    Retrieves monitoring data for the server, including active users, queue information,
    and total users across all servers.

    Returns:
        dict: A dictionary containing the following keys:
            - "timestamp" (str): The current timestamp in ISO 8601 format.
            - "servers" (dict): A dictionary where each key is a server port (str) and
              the value is another dictionary with:
                - "active_users" (int): The number of active users on the server.
                - "users" (list): A list of user identifiers currently on the server.
                - "capacity" (int): The maximum capacity of the server.
            - "queue" (dict): A dictionary containing:
                - "count" (int): The number of users in the waiting queue.
                - "users" (list): A list of user identifiers in the waiting queue.
            - "total_users" (int): The total number of users across all servers.
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
    Selects the target port with the minimum load from a predefined list of ports.
    If all ports are fully occupied, optionally adds the client to a waiting queue
    and redirects to a loading port.
    Args:
        client_id (optional): The ID of the client requesting a port. If provided
                              and all ports are full, the client is added to a
                              waiting queue.
    Returns:
        int: The selected port with the minimum load if available.
        str: A loading port identifier if all ports are fully occupied.
    Logs:
        - Current load percentages of all ports.
        - Selected port and its load percentage.
        - Addition of a client to the waiting queue if applicable.
    """

    loads = GetServerLoads()  # Get current load percentages of all ports

    percentage_occupied = []
    for port in PORTS:
        percentage_occupied.append(
            loads[port] / SERVER_CAPS[port]
        )  # Calculate the load percentage of each port and put it in a list

    load_percentages = [
        f"{percent*100:.1f}%" for percent in percentage_occupied
    ]  # Convert the list of load percentages to a list of strings
    LOGGER.LogInfo(f"current loads are: {load_percentages}")

    min_load = min(percentage_occupied)  # Find the minimum load percentage

    if min_load < 1:  # If the minimum load is less than 100%
        min_load_ports = [
            port
            for port, percentage in zip(loads.keys(), percentage_occupied)
            if percentage == min_load
        ]
        selected_port = min(min_load_ports)  # Select the port with the minimum load
        LOGGER.LogInfo(f"Selected port {selected_port} with load {min_load}")
        are_all_full = False
        return selected_port

    if client_id is not None:  # If the minimum load is more or equal to than 100%
        with QUEUE_LOCK:
            if client_id not in WAITING_QUEUE:
                WAITING_QUEUE.append(client_id)  # Add the client to the waiting queue
                LOGGER.LogInfo(f"Added {client_id} to waiting queue")
    are_all_full = True
    return LOADING_PORT  # Redirect to loading page if all servers are full


def SendRedirect(client_socket, port):
    """
    Sends an HTTP 302 redirect response to the client, redirecting them to a specified port.
    Args:
        client_socket (socket.socket): The socket object representing the client connection.
        port (int): The port number to which the client should be redirected.
    Returns:
        None
    """
    redirect_response = (
        f"HTTP/1.1 302 Found\r\n" f"Location: http://{IP}:{port}/\r\n" "\r\n"
    ).encode()  # Create the redirect response

    client_socket.sendall(redirect_response)  # Send the redirect response to the client
    LOGGER.LogInfo(f"Sent redirect to port {port}")


def SendFile(file_path: str, client_socket):
    """
    Sends a file over a client socket as an HTTP response.
    Args:
        file_path (str): The path to the file to be sent.
        client_socket: The socket object used to send the HTTP response.
    Behavior:
        - Determines the content type based on the file extension.
        - Checks if the file exists using FlowMasterClasses.FileManager.FileExists.
        - Reads the file content using FlowMasterClasses.FileManager.ReadFile.
        - Sends an HTTP response with the file content if the file exists.
        - Sends a 404 Not Found response if the file does not exist.
        - Sends a 500 Internal Server Error response if an unexpected error occurs.
    Logging:
        - Logs a warning if the file is not found.
        - Logs an error if an exception occurs while sending the file.
        - Logs an info message when the file is successfully sent.
    """

    content_type = "text/html"
    if file_path.endswith(".js"):
        content_type = "application/javascript"

    try:
        if not FlowMasterClasses.FileManager.FileExists(
            file_path
        ):  # Check if the file exists
            LOGGER.LogWarning(f"File not found: {file_path}")
            response = (
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Type: text/plain\r\n"
                "\r\nFile not found."
            ).encode()  # Create a 404 Not Found response
            client_socket.sendall(
                response
            )  # Send a 404 response if the file is not found
            return

        content = FlowMasterClasses.FileManager.ReadFile(file_path)  # Read the file content
        if content is None:
            raise FileNotFoundError(f"File not found or could not be read: {file_path}")

        content_bytes = (
            content.encode() if isinstance(content, str) else content
        )  # Convert the content to bytes

        response = (
            "HTTP/1.1 200 OK\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(content_bytes)}\r\n"
            f"\r\n"
        ).encode()  # Create the HTTP response with the content type and length

        client_socket.sendall(
            response + content_bytes
        )  # Send the HTTP response with the file content
        LOGGER.LogInfo(f"Sent file: {file_path}")

    except FileNotFoundError:  # Handle the case when the file is not found
        LOGGER.LogWarning(f"File not found: {file_path}")
        response = (
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/plain\r\n"
            "\r\nFile not found."
        ).encode()
        client_socket.sendall(response)  # Send a 404 response if the file is not found
    except Exception as e:  # Handle any unexpected exceptions
        LOGGER.LogError(f"Error sending file: {str(e)}")
        response = (
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: text/plain\r\n"
            "\r\nServer error."
        ).encode()  # Create a 500 Internal Server Error response
        client_socket.sendall(response)  # Send a 500 response if an error occurs


def HandleQueueRequest(client_socket):
    """
    Handles an HTTP request to retrieve queue statistics and sends the response back to the client.
    Args:
        client_socket (socket.socket): The socket object representing the client connection.
    Behavior:
        - Retrieves the current queue statistics by calling the `GetQueueData` function.
        - Constructs an HTTP response with a 200 OK status, JSON content type, and CORS headers.
        - Sends the JSON-encoded queue statistics as the response body to the client.
        - Logs the action using the `LOGGER.LogInfo` method.
    Note:
        This function assumes that `GetQueueData` and `LOGGER.LogInfo` are defined elsewhere in the code.
    """
    queue = GetQueueData()  # Get current queue statistics

    response = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: application/json\r\n"
        f"Access-Control-Allow-Origin: *\r\n"  # Allow cross-origin requests for dashboard
        f"\r\n"
        f"{json.dumps(queue)}"  # Convert stats to JSON
    ).encode()  # Construct the HTTP response with JSON content

    client_socket.sendall(response)  # Send the HTTP response with the queue statistics
    LOGGER.LogInfo("Sent monitoring stats")


def HandleStatsRequest(client_socket):
    """
    Handles an HTTP request to retrieve monitoring statistics.
    This function retrieves current monitoring data, formats it as an HTTP
    response with JSON content, and sends it back to the client. It also
    includes custom headers such as the total number of active users and
    allows cross-origin requests for dashboard compatibility.
    Args:
        client_socket (socket.socket): The socket object representing the
        client connection.
    Returns:
        None
    """
    stats = GetMonitoringData()  # Get current monitoring statistics

    response = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: application/json\r\n"
        f"Access-Control-Allow-Origin: *\r\n"  # Allow cross-origin requests for dashboard
        f"X-Active-Users: {stats['total_users']}\r\n"  # Custom header with user count
        f"\r\n"
        f"{json.dumps(stats)}"
    ).encode()  # Construct the HTTP response with JSON content

    client_socket.sendall(response)  # Send the HTTP response with the monitoring stats
    LOGGER.LogInfo("Sent monitoring stats")


def HandleUserRequest(client_socket, file_path, port):
    """
    Handles incoming user requests on a given socket, processes the request, and sends an appropriate response.
    Args:
        client_socket (socket.socket): The socket object representing the client connection.
        file_path (str): The file path to serve content from.
        port (int): The port number on which the request is being handled.
    Returns:
        bool: True if the request was handled successfully, False otherwise.
    Behavior:
        - Validates the service and monitoring server status.
        - Reads and decodes the HTTP request data from the client socket.
        - Checks if the client socket is still valid.
        - Extracts the `client_id` from the request data, if present.
        - Handles blocked users by sending a redirect to a disconnect page or a 403 Forbidden response.
        - Tracks new or returning client connections.
        - Processes heartbeat requests to update the client's last active time and sends a minimal response.
        - Handles client leave requests by removing the client from the active user list and sending a confirmation response.
        - Routes requests to a target port if the request is received on the routing server port.
        - Updates the client's last active time for content server requests and serves the requested file.
        - Logs errors and warnings for socket timeouts or other exceptions.
        - Ensures the client socket is closed after processing the request.
    Exceptions:
        - Handles `socket.timeout` and logs a warning.
        - Logs any other exceptions that occur during request handling.
    """
    try:
        if not SERVICE_USERS or not MONITOR_SERVER:
            sys.exit()

        data = client_socket.recv(9999).decode()  # Read data from client (HTTP request)
        if client_socket.fileno() == -1:  # Check if socket is still valid
            LOGGER.LogError(f"Socket already closed on port {port}")
            return False

        client_id = None  # Initialize client_id to None
        if "client_id=" in data:
            client_id = data.split("client_id=")[1].split(" ")[
                0
            ]  # Extract client_id from request data

        if client_id is not None and client_id in DENIED_USERS:
            # If user has been denied access, send redirect to disconnect page
            LOGGER.LogInfo(f"Detected blocked access from {client_id} ({port})")
            try:  # Attempt to send redirect response
                redirect_response = (
                    f"HTTP/1.1 302 Found\r\n"
                    f"Location: http://{IP}:{DISCONNECT_PORT}/disconnect.html\r\n"
                    f"\r\n"
                ).encode()
                client_socket.sendall(redirect_response)  # Send redirect response
            except Exception as e:  # Handle any exceptions during redirect response
                LOGGER.LogError(f"Error sending redirect to disconnect page: {str(e)}")
                msg = "Access has been denied"
                response = f"HTTP/1.1 403 Forbidden\r\nContent-Length: {len(msg)}\r\n\r\n{msg}".encode()
                client_socket.sendall(response)
            return True

        connection_type = "new"
        if client_id is not None:
            with CLIENTS_LOCK:  # Track if this is a new or continuing connection
                if client_id not in CONNECTED_CLIENTS:
                    CONNECTED_CLIENTS.add(client_id)  # Add client to active user list
                else:
                    connection_type = "returning"  # Mark as returning connection

        if (
            client_id is not None and "/heartbeat" in data
        ):  # Check if request is a heartbeat
            with USERS_LOCK:
                AWAITING_USERS[port][
                    client_id
                ] = datetime.now()  # Update last active time for this client
                active_count = len(AWAITING_USERS[port])  # Get active user count

            msg = (
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                f"X-Active-Users: {active_count}\r\n"
                "Content-Length: 0\r\n\r\n"
            ).encode()  # Send minimal response with active user count in header

            client_socket.sendall(msg)  # Send response with active user count
            return True

        if client_id is not None and "/leave" in data:  # Handle client leave requests
            with USERS_LOCK:
                if client_id in AWAITING_USERS[port]:  # Check if client is active
                    del AWAITING_USERS[port][
                        client_id
                    ]  # Remove client from active user list

            msg = json.dumps({"response": "leave received"})
            client_socket.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(msg)}\r\n\r\n{msg}".encode()
            )  # Send response to client
            return True

        if port == ROUTING_PORT:  # Handle routing server (load balancer) requests
            selected_port = SelectTargetPort()
            SendRedirect(client_socket, selected_port)  # Send redirect to selected port
            return True

        # Handle content server requests
        if client_id is not None:
            with USERS_LOCK:
                AWAITING_USERS[port][
                    client_id
                ] = datetime.now()  # Update last active time for this client

        SendFile(file_path, client_socket)  # Send file to client

        return True

    except socket.timeout:  # Handle socket timeout
        LOGGER.LogWarning(f"Socket timeout occurred on port {port}")
    except Exception as e:  # Handle other exceptions
        LOGGER.LogError(
            f"An error occurred on port while handling user request {port}: {str(e)}"
        )
    finally:  # Clean up
        try:  # Always ensure the socket is closed
            client_socket.close()  # Close the socket
        except Exception as e:  # Handle any exceptions during socket closure
            LOGGER.LogError(f"Error closing socket on port {port}: {str(e)}")
    return False


def HandleMonitorRequest(client_socket, file_path, port):
    """
    Handles incoming HTTP requests from a client socket and processes them based on the request path and method.
    Args:
        client_socket (socket.socket): The socket object representing the client connection.
        file_path (str): The default file path to serve if no specific path is requested.
        port (int): The port number on which the server is listening.
    Returns:
        bool: True if the request was successfully handled, False otherwise.
    Behavior:
        - Handles various HTTP request paths such as `/login`, `/tracker.html`, `/queue`, `/stats`, `/logout`,
          `/disconnect`, `/user-info`, and others.
        - Validates user sessions using cookies and redirects unauthenticated users to the login page.
        - Serves static files like `tracker.html` and `login.html` based on the request and authentication status.
        - Processes specific actions such as toggling server capacity, logging out users, and disconnecting users.
        - Sends appropriate HTTP responses, including JSON responses, file content, or redirects.
        - Logs relevant information and errors using the `LOGGER` object.
    Exceptions:
        - Handles `socket.timeout` and logs a warning if a timeout occurs.
        - Catches and logs any other exceptions that occur during request handling.
        - Ensures the client socket is closed in the `finally` block to release resources.
    Notes:
        - The function relies on several global variables and helper functions such as `SERVICE_USERS`,
          `MONITOR_SERVER`, `USER_SESSION_MANAGER`, `LOGGER`, `SendFile`, `SendRedirectToLogin`,
          `HandleLoginRequest`, `HandleQueueRequest`, `HandleStatsRequest`, `HandleLogout`, and others.
        - The function assumes the presence of predefined constants like `FILE_PATHS`, `SERVER_CAPS`,
          `ACTUAL_CAPS`, `PRETEND_CAPS`, `CURRENT_USERNAME`, `AWAITING_USERS`, `DENIED_USERS`, and `PORTS`.
        - The function processes JSON payloads for specific requests and constructs appropriate HTTP responses.
    """
    try:
        if not SERVICE_USERS or not MONITOR_SERVER:  # Check if the service is running
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
        if "Cookie:" in data:  # Check if cookies are present in the request
            cookie_line = [
                line for line in data.split("\r\n") if line.startswith("Cookie:")
            ][
                0
            ]  # Extract the cookie line
            cookies = cookie_line.split(":", 1)[1].strip()
            cookie_parts = cookies.split(";")
            for part in cookie_parts:  # Extract session ID from cookies
                if "session_id=" in part:
                    session_id = part.split("=", 1)[1].strip()
                    break  # Extract session ID from cookies

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
                state = "full"  # Set the state to "full" to indicate that the server is full
            else:
                SERVER_CAPS = ACTUAL_CAPS
                state = "default"  # Reset the state to "default" to indicate that the server is not full

            msg = json.dumps({"response": "make_server_full received", "state": state})
            client_socket.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(msg)}\r\n\r\n{msg}".encode()
            )
            return True

        # Logout the user
        if "/logout" in path:  # Logout
            if not is_authenticated:  # If the user is not logged in
                SendRedirectToLogin(client_socket)  # Redirect to log in
                return True

            HandleLogout()  # Handle user logout
            SendRedirectToLogin(client_socket)  # Redirect to log in
            return True

        if "/disconnect" in path:  # Handle client leave requests
            if (
                not USERNAMES.GetSecondOfArray(
                    Hash(CURRENT_USERNAME)
                )  # Check if the user is in the queue
                in PERMCANDISCONNECT  # Check if the user has permission to disconnect
            ):
                msg = json.dumps(
                    {"response": "missing permissions"}
                )  # Send a response indicating that the user lacks permissions
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
                SendRedirectToLogin(client_socket)  # Redirect to log in
                return True

            # Find the body inside the 'data'
            header_and_body = data.split("\r\n\r\n")
            user_id = None
            if len(header_and_body) > 1:
                body = header_and_body[1]

                # Parse the body - it comes as JSON
                body_json = json.loads(body)

                if "userId" in body_json:  # Check if the user has a user ID
                    user_id = body_json["userId"]

            if user_id is None:  # If the user ID is not in the body
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

            client_socket.sendall(
                (headers + response_json).encode()
            )  # Send the response with user info
            return True

        # For other requests, check authentication
        if not is_authenticated:
            SendRedirectToLogin(client_socket)  # Send redirect to login page
            return True

        # Default: serve the requested file
        no_leading_slash_path = path.removeprefix("/")  # Remove leading slash from path
        for _, item in FILE_PATHS.items():
            if item == no_leading_slash_path:
                SendFile(no_leading_slash_path, client_socket)
                return True

        LOGGER.LogInfo(f"Return the '{file_path}' page")
        SendFile(file_path, client_socket)
        return True

    except socket.timeout:  # Handle socket timeout
        LOGGER.LogWarning(f"Socket timeout occurred on port {port}")
    except Exception as e:  # Handle other exceptions
        LOGGER.LogError(
            f"An error occurred on port while handling monitor request {port}: {str(e)}"
        )
    finally:  # Close the socket
        try:  # Always ensure the socket is closed
            client_socket.close()
        except Exception as e:  # Handle socket close exception
            LOGGER.LogError(f"Error closing socket on port {port}: {str(e)}")
    return False


def SendRedirectToLogin(client_socket):
    """
    Sends an HTTP 302 redirect response to the client socket, directing the user to the login page.
    Args:
        client_socket (socket.socket): The socket object representing the client connection.
    Behavior:
        - Constructs an HTTP 302 response with a "Location" header pointing to the login page.
        - Sends the response to the client socket.
        - Logs the redirection action using the LOGGER.
    Note:
        Ensure that the variables `IP` and `MONITORING_PORT` are properly defined and accessible
        within the scope of this function.
    """

    redirect_response = (
        f"HTTP/1.1 302 Found\r\n"
        f"Location: http://{IP}:{MONITORING_PORT}/login.html\r\n"
        f"\r\n"
    ).encode()

    client_socket.sendall(redirect_response)
    LOGGER.LogInfo("Redirected unauthenticated user to login page")


def HandleLoginRequest(client_socket, data):
    """
    Handles a login request from a client by validating the provided credentials
    and generating a session ID upon successful authentication.
    Args:
        client_socket (socket.socket): The socket object representing the client connection.
        data (str): The HTTP request data received from the client.
    Returns:
        bool: Always returns True to indicate the request was handled.
    Behavior:
        - Parses the HTTP request to extract the login credentials (username and password).
        - Hashes the username and password for secure comparison.
        - Validates the credentials against the `USERNAMES.user_library` dictionary.
        - If authentication is successful:
            - Updates the global `CURRENT_USERNAME` variable.
            - Generates a session ID using `USER_SESSION_MANAGER.CreateSession`.
            - Sends a success response with a session cookie and a redirect URL.
            - Logs the successful login attempt.
        - If authentication fails:
            - Sends a failure response with an appropriate error message.
            - Logs the failed login attempt.
        - Handles exceptions by logging the error and sending a 500 Internal Server Error response.
    Notes:
        - The function relies on several global variables and external modules:
            - `CURRENT_USERNAME`: A global variable to track the currently logged-in user.
            - `USERNAMES`: A module or object containing user credentials.
            - `USER_SESSION_MANAGER`: A module or object responsible for session management.
            - `LOGGER`: A logging utility for recording events.
            - `IP` and `MONITORING_PORT`: Global variables for constructing the redirect URL.
        - The function assumes the request body is in JSON format and contains "username" and "password" keys.
    """
    global CURRENT_USERNAME  # Access the global variable

    try:
        # Extract the request body
        body = data.split("\r\n\r\n")[1]
        login_data = json.loads(body)

        username = login_data.get("username")
        password = login_data.get(
            "password"
        )  # Extract username and password from the request body

        encrypted_username = Hash(username)
        encrypted_password = Hash(
            password
        )  # Hash the username and password for secure comparison

        if (  # Check credentials against USERNAMES dictionary
            encrypted_username in USERNAMES.user_library
            and USERNAMES.user_library[encrypted_username][0] == encrypted_password
        ):
            CURRENT_USERNAME = (
                username  # Update current_username when login is successful
            )

            session_id = USER_SESSION_MANAGER.CreateSession(
                CURRENT_USERNAME
            )  # Generate a session ID
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
        else:  # Send failure response
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
    except Exception as e:  # Handle any exceptions that occur during the login process
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
    Starts a monitoring server that listens for incoming client connections on a specified IP and port.
    Each client connection is handled in a separate thread.
    The server performs the following tasks:
    - Binds to the specified IP address and monitoring port.
    - Listens for incoming client connections.
    - Accepts client connections and sets a timeout for the client socket.
    - Stores the client socket in a global dictionary using the client's peer name as the key.
    - Spawns a new thread to handle each client's monitoring request.
    Global Variables:
    - IP (str): The IP address the server binds to.
    - MONITORING_PORT (int): The port number the server listens on.
    - LOGGER (object): Logger instance used for logging server activities.
    - MONITOR_SERVER (bool): Flag to control the server's running state.
    - SOCKET_TIMEOUT (int): Timeout value for client sockets.
    - CLIENT_SOCKETS (dict): Dictionary to store active client sockets.
    - FILE_PATHS (dict): Dictionary containing file paths for various resources.
    Notes:
    - The server will continue running as long as the MONITOR_SERVER flag is set to True.
    - Each client request is handled by the `HandleMonitorRequest` function in a separate thread.
    """

    with socket.socket(
        socket.AF_INET, socket.SOCK_STREAM
    ) as server_socket:  # Create a new socket object for the server
        server_socket.bind((IP, MONITORING_PORT))
        server_socket.listen()
        LOGGER.LogInfo(f"Monitoring server listening on: {IP}:{MONITORING_PORT}")

        while MONITOR_SERVER:  # Continuously listen for incoming client connections
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
            ).start()  # Start a new thread to handle the request


def StartRoutingServer():
    """
    Starts the routing server to handle incoming client connections.
    The server listens on a specified IP and port, accepts incoming connections,
    and processes each routing request in a separate thread. If the time since
    the last routing request is less than the defined delay, the server waits
    before processing the next request.
    Key functionality:
    - Binds to the specified IP and port.
    - Listens for incoming client connections.
    - Ensures a minimum delay between handling routing requests.
    - Processes each request in a separate thread.
    Globals:
        IP (str): The IP address the server binds to.
        ROUTING_PORT (int): The port number the server listens on.
        LOGGER (object): Logger instance for logging server activity.
        SOCKET_TIMEOUT (float): Timeout duration for client sockets.
        DELAY_BETWEEN_ROUTING (float): Minimum delay between routing requests.
    Raises:
        socket.error: If there is an issue with socket creation or binding.
    """

    with socket.socket(
        socket.AF_INET, socket.SOCK_STREAM
    ) as routing_socket:  # Create a new socket object for the routing server
        routing_socket.bind(
            (IP, ROUTING_PORT)
        )  # Bind the socket to the specified IP and port
        routing_socket.listen()
        LOGGER.LogInfo(f"Routing server listening on: {IP}:{ROUTING_PORT}")

        last_routing_time = time.time()  # Initialize last routing time

        while True:  # Continuously listen for incoming client connections
            client_socket, _ = routing_socket.accept()  # Accept incoming connections
            client_socket.settimeout(SOCKET_TIMEOUT)

            current_time = time.time()
            time_since_last = (
                current_time - last_routing_time
            )  # Calculate time since last routing request

            if time_since_last < DELAY_BETWEEN_ROUTING:
                time.sleep(
                    DELAY_BETWEEN_ROUTING - time_since_last
                )  # If too little time has passed since last routing, add a delay

            last_routing_time = time.time()  # Update last routing time

            threading.Thread(  # Handle each routing request in a separate thread
                target=lambda: HandleUserRequest(client_socket, None, ROUTING_PORT)
            ).start()


def StaticServer(port, file_path, max_connections):
    """
    Starts a static server that listens for incoming connections on the specified port
    and serves files from the given file path.
    Args:
        port (int): The port number on which the server will listen for incoming connections.
        file_path (str): The path to the directory or file to be served by the static server.
        max_connections (int): The maximum number of concurrent connections allowed.
    Behavior:
        - The server listens for incoming TCP connections using a socket.
        - Logs the server's listening status, including the IP, port, and maximum connections.
        - Handles each client request in a separate thread.
        - Monitors the number of active connections to ensure it does not exceed the limit.
    Notes:
        - The server uses a global `MONITOR_SERVER` flag to determine whether to continue running.
        - A global `USERS_LOCK` is used to synchronize access to the connection count.
        - The `SOCKET_TIMEOUT` is applied to client sockets to prevent indefinite blocking.
    Raises:
        socket.error: If there is an issue with socket creation, binding, or listening.
        Exception: If any unexpected error occurs during request handling.
    """

    with socket.socket(
        socket.AF_INET, socket.SOCK_STREAM
    ) as server_socket:  # Create a new socket object for the static server
        server_socket.bind((IP, port))  # Bind the socket to the specified IP and port
        server_socket.listen()
        LOGGER.LogInfo(
            f"Static server listening on: {IP}:{port} (max connections: {max_connections})"
        )

        while MONITOR_SERVER:  # Continuously listen for incoming client connections
            client_socket, _ = server_socket.accept()  # Accept incoming connections
            client_socket.settimeout(
                SOCKET_TIMEOUT
            )  # Set a timeout for the client socket

            with USERS_LOCK:
                current_connections = len(
                    AWAITING_USERS[port]
                )  # Check current connection count before processing

            threading.Thread(  # Handle each request in a separate thread
                target=lambda: HandleUserRequest(client_socket, file_path, port)
            ).start()


def StartStaticServers(max_connections=None):
    """
    Starts multiple static servers on predefined ports with specified or default maximum connections.
    This function initializes and starts static servers for serving files on specific ports.
    It also starts a loading server and a disconnect server with no connection cap.
    Args:
        max_connections (int or None, optional):
            The maximum number of connections allowed for each server.
            If an integer is provided, it is applied to all servers.
            If None, a default of 10 connections is used for each server.
    Behavior:
        - Starts servers on ports defined in the `PORTS` list, serving files specified in `FILE_PATHS`.
        - If `max_connections` is not provided, defaults to 10 connections per server.
        - Starts a loading server on `LOADING_PORT` with no connection cap.
        - Starts a disconnect server on `DISCONNECT_PORT` with no connection cap.
    Note:
        - The `PORTS`, `FILE_PATHS`, `LOGGER`, `LOADING_PORT`, and `DISCONNECT_PORT` variables
          are expected to be defined globally.
        - Each server is started in a separate thread using the `threading` module.
    """

    files = [
        FILE_PATHS["index1"],
        FILE_PATHS["index2"],
        FILE_PATHS["index3"],
    ]  # Define the files to be served by each server
    if isinstance(
        max_connections, int
    ):  # If max_connections is provided, apply it to all servers
        max_connections = [max_connections] * len(PORTS)
    elif (
        max_connections is None
    ):  # If max_connections is not provided, use a default of 10 connections per server
        max_connections = [10] * len(PORTS)

    for port, file_path, max_conn in zip(
        PORTS, files, max_connections
    ):  # Start each server on the specified port
        LOGGER.LogInfo(
            f"Starting server on port {port} with max connections: {max_conn}"
        )
        threading.Thread(  # Start a new thread for each server
            target=lambda p=port, f=file_path, m=max_conn: StaticServer(p, f, m)
        ).start()

    LOGGER.LogInfo(
        f"Starting loading server on port {LOADING_PORT} with no max connections"
    )
    threading.Thread(  # Start a new thread for the loading server
        target=lambda: StaticServer(
            LOADING_PORT, FILE_PATHS["loading"], max_connections=1000000
        )
    ).start()  # Start loading server on LOADING_PORT with no connection cap

    # Start disconnect server on DISCONNECT_PORT with no connection cap
    LOGGER.LogInfo(
        f"Starting disconnect server on port {DISCONNECT_PORT} with no max connections"
    )
    threading.Thread(  # Start a new thread for the disconnect server
        target=lambda: StaticServer(
            DISCONNECT_PORT, FILE_PATHS["disconnect"], max_connections=1000000
        )
    ).start()


def FetchCurrentUser(session_id):
    """
    Fetches the username of the currently logged-in user based on the provided session ID.

    Args:
        session_id (str): The session ID associated with the user's session.

    Returns:
        str: The username of the current user if the session is valid.
        None: If the session is invalid or the user is not logged in.
    """
    if USER_SESSION_MANAGER.ValidateSession(
        session_id
    ):  # Check if the session is valid
        return USER_SESSION_MANAGER.GetUsername(session_id)
    return None


def main():
    """
    Main function to initialize and start the FlowMaster application.
    This function performs the following tasks:
    1. Checks if all required ports are available using the `TestPorts` function.
        - Logs an error and exits the program if the port test fails.
    2. Logs server access information, including:
        - The main server URL.
        - The monitoring interface URL.
        - Direct access URLs for all configured ports.
    3. Sets up a signal handler for graceful shutdown on receiving a SIGINT signal.
    4. Starts a background thread to update active users periodically.
    5. Initializes and starts all static content servers in separate threads.
    6. Starts the monitoring server in a separate thread.
    7. Starts the routing server on the main thread.
    Raises:
         SystemExit: If the port test fails and the application cannot proceed.
    """
    if not TestPorts():  # First check if all ports are available
        LOGGER.LogError("Port test failed! Please check if ports are available.")
        sys.exit()  # Exit the program if the port test fails

    LOGGER.LogInfo(f"Server accessible at: http://{IP}:{ROUTING_PORT}")
    LOGGER.LogInfo(f"Monitoring interface at: http://{IP}:{MONITORING_PORT}")
    LOGGER.LogInfo(
        f"Direct access ports: {', '.join(f'http://{IP}:{port}' for port in PORTS)}"
    )  # Log access information

    signal.signal(
        signal.SIGINT, SignalHandler
    )  # Set up signal handler for graceful shutdown

    threading.Thread(
        target=UpdateActiveUsers, daemon=True
    ).start()  # Start background task for updating active users

    StartStaticServers(
        [SERVER_CAPS[port] for port in PORTS]
    )  # Start all content servers in separate threads

    threading.Thread(
        target=MonitoringServer, daemon=True
    ).start()  # Start monitoring server in a separate thread

    StartRoutingServer()  # Start routing server on the main thread


# Entry point when script is run directly

if __name__ == "__main__":
    main()
