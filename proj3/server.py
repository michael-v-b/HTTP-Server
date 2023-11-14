import hashlib
import json
import random
import sys


def main(accounts):
     # Get the username and password from the user.
    username = inpunt("Username: ")
    password = inpunt("Password: ")
    message = login_request(username, password, accounts)
    print message

#ALERT ALERT ALERT NOAM ARANA IS GAY, REPEAT NOAM ARANA IS GAY!!!!

def login_request(username, password, accounts):
   
    # Validates "username" and "password" from headers, return 501 and log "LOGIN FAILED" if missing.
    if not username or not password:
        message = (501, 'LOGIN FAILED')
        print(message)
        return message
    
    # Create a session with the given credentials. 
    valid_login_credentials = handle_login_credentials(username, password)

    # Validates creds, sets 64-bit hex sessionID cookie, create & log session, return HTTP 200 with "Logged in!"
    if valid_login_credentials:
        session_id = random.getrandbits(64).to_bytes(8, "big").hex()
        message = (f'LOGIN SUCCESSFUL: {username} : {password}')
        print(message)

        #Set the cookie and the status code with the message
        # response = requests.Response()
        # logging.info(f'LOGIN SUCCESSFUL: {username} : {password}')
        # response.set_cookie("session_id", session_id)
        # response.status_code = 200
        # response.content('Logged in!')

        return message
    else:
        message = (f'LOGIN FAILED: {username} : {password}')

        #Set the status code with the message
        # response = requests.Response()
        # logging.error(f'LOGIN FAILED: {username} : {password}')
        # response.content('Login failed!')
        # response.status_code = 200
        return message


#This function handles the login credentials for a given user. It returns True if the credentials are correct and False otherwise.    
def handle_login_credentials():

    with open('accounts, 'r') as f:
        accounts = json.load(f)

    hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
    accounts.get(username) == hashed_password
    return accounts

if __main__ == "__main__":
    main()
        