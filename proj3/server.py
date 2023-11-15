import hashlib
import json
import random
import sys


def main():

    # Checks for the correct number of command-line arguments
    if len(sys.argv) != 6:
        print("Usage: python3 server.py [IP] [PORT] [ACCOUNTS_FILE] [SESSION_TIMEOUT] [ROOT_DIRECTORY]")
        sys.exit(1)

    # Parse command-line arguments
    ip = sys.argv[1]
    port = sys.argv[2]
    accounts_file = sys.argv[3]
    session_timeout = sys.argv[4]
    root_directory = sys.argv[5]

    with open('accounts_file', 'r') as f:
        accounts = json.load(f)

     # Get the username and password from the user.
    username = input("Username: ")
    password = input("Password: ")
    message = login_request(username, password, accounts)
    print (message)
    return message

#ALERT ALERT ALERT NOAM ARANA IS GAY, REPEAT NOAM ARANA IS GAY!!!!

def http_request():
    lines = http_request.split("\r\n")
    lines = lines[1:] #ignore the GET / HTTP/1.1
    output = {}
    for line in lines:
        if not line:
            continue
        key,value = line.split(':', 1)
        output[key] = value   
    print(output)
    return output

def login_request(username, password, accounts_file):
   
    # Validates "username" and "password" from headers, return 501 and log "LOGIN FAILED" if missing.
    if not username or not password:
        message = ('LOGIN FAILED')
        print(message)
        return "HTTP/1.1 501 Not Implemented\r\n\r\n"
    
    # Create a session with the given credentials. 
    valid_login_credentials = handle_login_credentials(username, password, accounts_file)

    # Validates creds, sets 64-bit hex sessionID cookie, create & log session, return HTTP 200 with "Logged in!"
    if valid_login_credentials:
        session_id = random.getrandbits(64).to_bytes(8, "big").hex()
        message = (f'LOGIN SUCCESSFUL: {username} : {password}')
        print(message)

        # Return the cookie and the status code with the message
        return f"HTTP/1.1 200 OK\r\nSet-Cookie: sessionID={session_id}\r\n\r\nLogged in!"
    else:
        message = (f'LOGIN FAILED: {username} : {password}')

        # Return the status code with the message
        return "HTTP/1.1 200 OK\r\n\r\nLogin failed!"

#This function handles the login credentials for a given user. It returns True if the credentials are correct and False otherwise.    
def handle_login_credentials(username, password, accounts):

    # Retrieve user info from accounts
    if user_info:
        hashed_password = hashlib.sha256((password + user_info['salt']).encode()).hexdigest()
        hashed_password = user_info['password']
        user_info = accounts.get(username)
        return user_info
    return False

if __name__ == "__main__":
    main()