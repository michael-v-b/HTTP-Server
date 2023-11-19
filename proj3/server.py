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
    sessionCookies = {}

    with open(accounts_file, 'r') as f:
        accounts = json.load(f)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as httpSocket:
    
        httpSocket.bind((ip,int(port)))
        httpSocket.listen(5)

        httpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reusing the address
        while True:
            print("recieve message")
            client,clientPort = httpSocket.accept()

            with client:
                client.settimeout(10.0)
                while True:
                    try:
                        print("recieve message")
                        encoded_message = client.recv(1024)

                        if not encoded_message:
                            print("no message received")
                            break

                        decoded_message = encoded_message.decode()
                        print("MESSAGE: " + decoded_message)
                        
                        lines = decoded_message.split("\r\n")
                        command = lines[0]

                        if "POST" in command:
                            okMessage = post_command(lines,accounts,sessionCookies)
                            client.send(okMessage.encode())
                        elif "GET" in command:
                            getMessage = get_command(lines,root_directory,session_timeout,sessionCookies)
                            client.send(getMessage.encode())
                        else:
                            print("happens : {}".format(command))
                            break

                    except socket.timeout:
                        print("Timeout!")
                        break
                    except socket.error as e:
                        print(f"Socket error: {e}")
                        break

                client.close()
                print("client closed")

        

 

    # Get the username and password from the user.
def print_server_log (message):
    t= datetime.datetime.now()
    time_string =  "{}-{}-{}-{}-{}-{}".format(t.year,t.month,t.day,t.hour,t.minute,t.day)
    print("SERVER LOG: " + time_string + " " + message)
    return t

def get_command(lines,root_directory,session_timeout,sessionCookies):
    okMessage = ""
    split_command = lines[0].split(" ")
    target = None
    if(len(lines) >= 4):
         lines[3] = lines[3].strip()
         target = lines[3][len(lines[3])-1]
         sessionID = lines[4][15:len(lines[4])]
         
    else:
        print_server_log("COOKIE INVALID")
        okMessage = "401 unauthorized"

    if sessionID in sessionCookies:
        current_time = datetime.datetime.now()
        username, last_time = sessionCookies[sessionID]
        
        #if timed out
        if((current_time-last_time).seconds > session_timeout):
            print_server_log("SESSION EXPIRED: {} : {}".format(username,target))
            return "401 Unauthorized"
        
        sessionCookies[sessionID] = (username, current_time)
        file_path = f"{root_directory}/{username}/{target}"
        
        try:
            with open(file_path, 'r') as file:
                file_contents = file.read()
                print_server_log("GET SUCCEEDED: {} : {}".format(username,target))
                return "200 OK", file_contents
        except FileNotFoundError:
            print_server_log("GET FAILED: {} : {}".format(username,target))
            return "404 NOT FOUND"
    else:
        print_server_log("COOKIE INVALID: {}".format(target))
        return "401 Unauthorized"
   

    
    
def post_command(lines,accounts,sessionCookies):
    #get username
    okMessage = ""
    if(len(lines) < 5 or len(lines[4]) < 10 or len(lines[5]) < 10):
        print_server_log("LOGIN FAILED")
        okMessage = "501 Not Implemented"
    else: 
        username = lines[4][10:len(lines[4])]
        password = lines[5][10:len(lines[5])]
        print_server_log("LOGIN SUCCESSFUL: {} : {}".format(username,password))
        okMessage, mess,cookie = login_request(username, password, accounts)
        t = datetime.datetime.now()
        sessionCookies.update({cookie:(username,t)})
        

    return okMessage


        



#ALERT ALERT ALERT NOAM ARANA IS GAY, REPEAT NOAM ARANA IS GAY!!!!


def login_request(username, password, accounts_file):
    
    # Validates "username" and "password" from headers, return 501 and log "LOGIN FAILED" if missing.
    if not username or not password:
        message = ('LOGIN FAILED')
        return "HTTP/1.1 501 Not Implemented\r\n\r\n", message
    
    # Create a session with the given credentials. 
    valid_login_credentials = handle_login_credentials(username, password, accounts_file)

    # Validates creds, sets 64-bit hex sessionID cookie, create & log session, return HTTP 200 with "Logged in!"
    if valid_login_credentials:
        session_id = random.getrandbits(64).to_bytes(8, "big").hex()
        message = (f'LOGIN SUCCESSFUL: {username} : {password}')

        # Return the cookie and the status code with the message
        return f"HTTP/1.1 200 OK\r\nSet-Cookie: sessionID={session_id}\r\n\r\nLogged in!\r\n\r\n", message,session_id
    else:
        message = (f'LOGIN FAILED: {username} : {password}')
        # Return the status code with the message
        return "HTTP/1.1 200 OK\r\n\r\nLogin failed!\r\n\r\n", message, session_id

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

#def http_request():
#    lines = http_request.split("\r\n")
#    lines = lines[1:] #ignore the GET / HTTP/1.1
#    output = {}
#    for line in lines:
#        if not line:
#            continue
#        key,value = line.split(':', 1)
#        output[key] = value   
#    print(output)
#    return output
