import logging
import sqlite3
import uuid
from datetime import datetime


# Class 1
class Database:
    def __init__(self, db_file_path):
        self.user_library = {}
        try:
            # Connect to the SQLite database
            conn = sqlite3.connect(db_file_path)
            cursor = conn.cursor()

            # Query all user records from the UserPassPerm table
            cursor.execute("SELECT Username, Password, Perm FROM UserPassPerm")
            rows = cursor.fetchall()

            # Process each row and add to the dictionary
            for row in rows:
                username = row[0]
                password = row[1]
                permission = row[2]

                # Add to the dictionary with the required format
                self.user_library[username] = [password, permission]

            # Close the connection
            conn.close()

        except sqlite3.Error as e:
            print(f"SQLite error: {e}")
        except Exception as e:
            print(f"Error: {e}")


# Class 2
class UserSession:
    def __init__(self):
        self.sessions = {}  # Dictionary to hold session data

    def create_session(self, username):
        """Create a new session for a user."""
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            "username": username,
            "timestamp": datetime.now(),
        }
        return session_id

    def validate_session(self, session_id):
        """Validate if a session is active."""
        return session_id in self.sessions

    def destroy_session(self, session_id):
        """Destroy a session."""
        if session_id in self.sessions:
            del self.sessions[session_id]

    def get_username(self, session_id):
        """Get the username associated with a session."""
        return self.sessions.get(session_id, {}).get("username")


# Class 3
class Logger:
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
    def log_info(message):
        """Log an info message."""
        logging.info(message)

    @staticmethod
    def log_warning(message):
        """Log a warning message."""
        logging.warning(message)

    @staticmethod
    def log_error(message):
        """Log an error message."""
        logging.error(message)


# Class 4
class FileManager:
    @staticmethod
    def read_file(file_path):
        """Read the content of a file."""
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
    def write_file(file_path, content):
        """Write content to a file."""
        try:
            with open(file_path, "w") as file:
                file.write(content)
        except Exception as e:
            logging.error(f"Error writing to file {file_path}: {str(e)}")

    @staticmethod
    def file_exists(file_path):
        """Check if a file exists."""
        try:
            with open(file_path, "r"):
                return True
        except FileNotFoundError:
            return False
