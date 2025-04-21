import logging
import sqlite3
import uuid
from datetime import datetime


# Class 1 - DaTaBaSe
class dtbs:
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
        if username in self.user_library:
            return self.user_library[username][1]
        else:
            return -1


# Class 2 - USeR SessiON
class usrson:
    def __init__(self):
        self.sessions = {}  # Dictionary to hold session data

    def CreateSession(self, username):
        """Create a new session for a user."""
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            "username": username,
            "timestamp": datetime.now(),
        }
        return session_id

    def ValidateSession(self, session_id):
        """Validate if a session is active."""
        return session_id in self.sessions

    def DestroySession(self, session_id):
        """Destroy a session."""
        if session_id in self.sessions:
            del self.sessions[session_id]

    def GetUsername(self, session_id):
        """Get the username associated with a session."""
        return self.sessions.get(session_id, {}).get("username")


# Class 3 - LoGGeR
class lggr:
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
        """Log an info message."""
        logging.info(message)

    @staticmethod
    def LogWarning(message):
        """Log a warning message."""
        logging.warning(message)

    @staticmethod
    def LogError(message):
        """Log an error message."""
        logging.error(message)


# Class 4 - FiLeMaNaGeR
class flmngr:
    @staticmethod
    def ReadFile(file_path):
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
    def WriteFile(file_path, content):
        """Write content to a file."""
        try:
            with open(file_path, "w") as file:
                file.write(content)
        except Exception as e:
            logging.error(f"Error writing to file {file_path}: {str(e)}")

    @staticmethod
    def FileExists(file_path):
        """Check if a file exists."""
        try:
            with open(file_path, "r"):
                return True
        except FileNotFoundError:
            return False
