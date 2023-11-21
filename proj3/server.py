import hashlib, json, random, sys, socket, datetime


# Initializes the server, listens for connections, and routes HTTP requests to appropriate handlers.
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
    sessionCookies = {}

    with open(accounts_file, 'r') as f:
        accounts = json.load(f)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as httpSocket:
        httpSocket.bind((ip,int(port)))
        httpSocket.listen(5)
        httpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        httpSocket.settimeout(2*float(session_timeout))
        while True:
            try:
                client,clientPort = httpSocket.accept()
            except socket.timeout:
                break
            except socket.error as e:
                break
            else:
                with client:
                    
                    encoded_message = client.recv(1024)
                    if not encoded_message:
                        client.close()
                        continue

                    decoded_message = encoded_message.decode()
                    lines = decoded_message.split("\r\n")
                    command = lines[0]
                    valid_request = True 
                    
                    if "POST" in command:
                        okMessage = post_command(lines,accounts,sessionCookies)
                        client.send(okMessage.encode())
                        client.close()
                    elif "GET" in command:
                        okMessage,works = get_command(lines,root_directory,session_timeout,sessionCookies)
                        client.send(okMessage.encode())
                        client.close()
                    else:
                        break

                    print("--------------------------------\r\noutput: {}\r\n--------------------------".format(okMessage))
                    if not valid_request:
                        client.close()
        
# Logs server events with a timestamp
def print_server_log (message):
    t= datetime.datetime.now()
    time_string =  "{}-{}-{}-{}-{}-{}".format(t.year,t.month,t.day,t.hour,t.minute,t.day)
    print("SERVER LOG: " + time_string + " " + message)
    return t

# Handles GET requests by validating sessions and serving requested files.
def get_command(lines,root_directory,session_timeout,sessionCookies):
    split_command = lines[0].split(" ")
    if(len(lines) >= 4):
         lines[3] = lines[3].strip()
         target = split_command[1]
         sessionID = lines[4][19:len(lines[4])].strip()
    else:
        okMessage = "401 unauthorized"
        return okMessage, False
    

   
    if sessionID in sessionCookies:
        current_time = datetime.datetime.now()
        username, last_time = sessionCookies[sessionID]
        if((current_time-last_time).seconds > float(session_timeout)):
            print_server_log("SESSION EXPIRED: {} : {} ".format(username,target))
            return "401 Unauthorized",False
        
        sessionCookies[sessionID] = (username, current_time)
        file_path = f"{root_directory}/{username}/{target}"
        
        try:
            with open(file_path, 'r') as file:
                file_contents = file.read()
                sessionCookies[sessionID] = (username,current_time)
                print_server_log("GET SUCCEEDED: {} : {} ".format(username,target))
                return "HTTP/1.1 200 OK\r\n\r\n" + file_contents, True
        except FileNotFoundError:
            print_server_log("GET FAILED: {} : {} ".format(username,target))
            return "404 NOT FOUND",False
    else:
        print_server_log("COOKIE INVALID: {}".format(sessionID))
        return "HTTP/1.1 401 Unauthorized\r\n\r\n", False
    
#Processes POST requests for user authentication and session initialization.
def post_command(lines,accounts,sessionCookies):
    #get username
    okMessage = ""
    if(len(lines) < 5 or len(lines[4]) < 10 or len(lines[5]) < 10):
        print_server_log("LOGIN FAILED ")
        okMessage = "501 Not Implemented"
    else:
        username = lines[4][10:len(lines[4])]
        password = lines[5][10:len(lines[5])]
        
        okMessage, logged_in,cookie = login_request(username, password, accounts)
        if(logged_in):
            print_server_log("LOGIN SUCCESSFUL: {} : {} ".format(username,password))
        else:
            print_server_log("LOGIN FAILED: {} : {} ".format(username,password))
        t = datetime.datetime.now()
        sessionCookies[cookie] = (username,t)
    return okMessage

# Validates user credentials and returns appropriate HTTP responses for login attempts.
def login_request(username, password, accounts_file):
    # Validates "username" and "password" from headers, return 501 and log "LOGIN FAILED" if missing.
    session_id = random.getrandbits(64).to_bytes(8, "big").hex()

    if not username or not password:
        return "HTTP/1.1 501 Not Implemented", False, session_id
    # Create a session with the given credentials. 
    valid_login_credentials = handle_login_credentials(username, password, accounts_file)
    # Validates creds, sets 64-bit hex sessionID cookie, create & log session, return HTTP 200 with "Logged in!"
    if valid_login_credentials:
        session_id = random.getrandbits(64).to_bytes(8, "big").hex()

        # Return the cookie and the status code with the message
        return f"HTTP/1.1 200 OK\r\nSet-Cookie: sessionID={session_id}\r\n\r\nLogged in!", True, session_id
    else:

        # Return the status code with the message
        return "HTTP/1.1 200 OK\r\n\r\nLogin failed!", False, session_id
    
#This function handles the login credentials for a given user. It returns True if the credentials are correct and False otherwise.    
def handle_login_credentials(username, password, accounts):
    # Retrieve user info from accounts
    if username in accounts:
        recorded_hashed_password,salt = accounts[username]
        hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
        return hashed_password == recorded_hashed_password
    return False

if __name__ == "__main__":
    main()
