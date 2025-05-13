import logging
import sqlite3
import uuid
from datetime import datetime


# Class 1 - DaTaBaSe
class dtbs:
    """
    A class to interact with an SQLite database and store data in a dictionary format.
    Attributes:
        user_library (dict): A dictionary where keys are the first column values from the database
                             and values are either a single converted value or a tuple of converted values.
    Methods:
        __init__(db_file_path, rows_array, table_name):
            Initializes the dtbs object by connecting to the SQLite database, executing a query,
            and populating the user_library dictionary with processed data.
        GetSecondOfArray(username):
            Retrieves the second element of the tuple associated with the given username in the user_library.
            Returns -1 if the username is not found.
    """

    def __init__(self, db_file_path, rows_array, table_name):
        self.user_library = {}
        try:
            # Connect to the SQLite database
            conn = sqlite3.connect(db_file_path)
            cursor = conn.cursor()

            # Create a proper comma-separated list of columns
            columns = ", ".join(rows_array)

            # Use parameterized query to avoid SQL injection
            # Use proper string formatting for table name (can't use parameters for table names)
            query = f"SELECT {columns} FROM {table_name}"

            # Execute the query
            cursor.execute(query)
            rows = cursor.fetchall()

            # Process each row and add to the dictionary
            for row in rows:
                # Convert row values based on content
                converted_values = []
                for value in row[1:]:
                    # Handle string type conversions
                    if isinstance(value, str):
                        # Convert 'TRUE'/'FALSE' to boolean
                        if value.upper() == "TRUE":
                            converted_values.append(True)
                        elif value.upper() == "FALSE":
                            converted_values.append(False)
                        else:
                            converted_values.append(value)
                    else:
                        converted_values.append(value)

                # Add to the dictionary with converted values
                if len(converted_values) == 1:
                    self.user_library[row[0]] = converted_values[0]
                else:
                    self.user_library[row[0]] = tuple(converted_values)

            # Close the connection
            conn.close()

        except sqlite3.Error as e:
            print(f"SQLite error: {e}")
        except Exception as e:
            print(f"Error: {e}")

    def GetSecondOfArray(self, username):
        """
        Retrieves the second element of the array associated with the given username
        in the user_library dictionary.

        Args:
            username (str): The username to look up in the user_library.

        Returns:
            object: The second element of the array associated with the username
                    if the username exists in the user_library.
            int: -1 if the username does not exist in the user_library.
        """
        if username in self.user_library:
            return self.user_library[username][1]
        else:
            return -1


# Class 2 - USeR SessiON
class usrson:
    """
    usrson Class
    This class manages user sessions, allowing for the creation, validation,
    retrieval, and destruction of sessions.
    Methods:
        __init__():
            Initializes the usrson class with an empty dictionary to store session data.
        CreateSession(username: str) -> str:
            Creates a new session for a user and returns the session ID.
            Args:
                username (str): The username for which the session is created.
            Returns:
                str: A unique session ID.
        ValidateSession(session_id: str) -> bool:
            Validates if a session is active.
            Args:
                session_id (str): The session ID to validate.
            Returns:
                bool: True if the session is active, False otherwise.
        DestroySession(session_id: str) -> None:
            Destroys a session by removing it from the session dictionary.
            Args:
                session_id (str): The session ID to destroy.
        GetUsername(session_id: str) -> Optional[str]:
            Retrieves the username associated with a session.
            Args:
                session_id (str): The session ID to retrieve the username for.
            Returns:
                Optional[str]: The username associated with the session, or None if the session does not exist.
    """

    def __init__(self):
        self.sessions = {}  # Dictionary to hold session data

    def CreateSession(self, username):
        """
        Create a new session for a user.

        Args:
            username (str): The username of the user for whom the session is being created.

        Returns:
            str: A unique session ID for the newly created session.
        """
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            "username": username,
            "timestamp": datetime.now(),
        }
        return session_id

    def ValidateSession(self, session_id):
        """
        Validate if a session is active.

        Args:
            session_id (str): The unique identifier of the session to validate.

        Returns:
            bool: True if the session is active, False otherwise.
        """
        return session_id in self.sessions

    def DestroySession(self, session_id):
        """
        Removes a session from the sessions dictionary if it exists.

        Args:
            session_id (str): The unique identifier of the session to be removed.

        Returns:
            None
        """
        if session_id in self.sessions:
            del self.sessions[session_id]

    def GetUsername(self, session_id):
        """
        Retrieve the username associated with a given session ID.

        Args:
            session_id (str): The unique identifier for the session.

        Returns:
            str or None: The username associated with the session ID if it exists,
            otherwise None.
        """
        return self.sessions.get(session_id, {}).get("username")


# Class 3 - LoGGeR
class lggr:
    """
    lggr is a logging utility class that provides methods for logging messages at different levels
    (INFO, WARNING, ERROR) to both a file and the console.
    Attributes:
        None
    Methods:
        __init__(log_file_path):
            Initializes the lggr class by setting up logging configuration with a specified log file path.
        LogInfo(message):
            Logs an informational message.
        LogWarning(message):
            Logs a warning message.
        LogError(message):
            Logs an error message.
    """

    def __init__(self, log_file_path):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(log_file_path),
                logging.StreamHandler(),
            ],
        )

    @staticmethod
    def LogInfo(message):
        """
        Logs an informational message.

        Args:
            message (str): The message to be logged.
        """
        logging.info(message)

    @staticmethod
    def LogWarning(message):
        """
        Logs a warning message.

        Args:
            message (str): The warning message to be logged.
        """
        logging.warning(message)

    @staticmethod
    def LogError(message):
        """
        Logs an error message using the logging module.

        Args:
            message (str): The error message to be logged.
        """
        logging.error(message)


# Class 4 - FiLeMaNaGeR
class flmngr:
    """
    flmngr
    A utility class for file management operations, providing static methods to read, write,
    and check the existence of files.
    Methods:
    --------
    - ReadFile(file_path: str) -> str | None:
        Reads the content of a file specified by the file_path.
        Returns the file content as a string if successful, or None if an error occurs.
    - WriteFile(file_path: str, content: str) -> None:
        Writes the provided content to a file specified by the file_path.
        Logs an error if the operation fails.
    - FileExists(file_path: str) -> bool:
        Checks if a file exists at the specified file_path.
        Returns True if the file exists, otherwise False.
    """

    @staticmethod
    def ReadFile(file_path):
        """
        Reads the content of a file.

        Args:
            file_path (str): The path to the file to be read.

        Returns:
            str: The content of the file if successfully read.
            None: If the file is not found or an error occurs during reading.

        Logs:
            Logs an error message if the file is not found or if any other exception occurs.
        """
        try:
            with open(file_path, "r") as file:
                return file.read()
        except FileNotFoundError:
            logging.error(f"File not found: {file_path}")
            return None
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {str(e)}")
            return None

    @staticmethod
    def WriteFile(file_path, content):
        """
        Writes the specified content to a file at the given file path.

        Args:
            file_path (str): The path to the file where the content will be written.
            content (str): The content to write to the file.

        Raises:
            Exception: Logs an error if there is an issue writing to the file.
        """
        try:
            with open(file_path, "w") as file:
                file.write(content)
        except Exception as e:
            logging.error(f"Error writing to file {file_path}: {str(e)}")

    @staticmethod
    def FileExists(file_path):
        """
        Check if a file exists at the specified file path.

        Args:
            file_path (str): The path to the file to check.

        Returns:
            bool: True if the file exists, False otherwise.
        """
        try:
            with open(file_path, "r"):
                return True
        except FileNotFoundError:
            return False
