import hashlib, json, random, sys, socket, datetime


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

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as httpSocket:
    
        httpSocket.bind((ip,int(port)))
        httpSocket.listen(5)
        client,clientPort = httpSocket.accept()

        with client:
            while True:
                message = client.recv(1024)
                if(message.decode() != ""):
                    print("works")
                    break; 

        

    with open(accounts_file, 'r') as f:
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
    t= datetime.datetime.now()
    output = "SERVER LOG: {}-{}-{}-{}-{}-{} ".format(t.year,t.month,t.day,t.hour,t.minute,t.day)
    # Validates "username" and "password" from headers, return 501 and log "LOGIN FAILED" if missing.
    if not username or not password:
        message = ('LOGIN FAILED')
        print(output+message)
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
        print(output + message)
        # Return the status code with the message
        return "HTTP/1.1 200 OK\r\n\r\nLogin failed!"

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