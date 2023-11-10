import json
import logging
import random
import requests

def login_request():
    # Get the username and password from the user.
    username = requests.get('username')
    password = requests.get('password')  

    # Validates "username" and "password" from headers, return 501 and log "LOGIN FAILED" if missing.
    if not username or not password:
        response = requests.Response()
        response.status_code = 501
        response.content('LOGIN FAILED')
        return response
    
    # Create a session with the given credentials.
    
    valid_login_credentials = handle_login_credentials(username, password)

    # Validates creds, sets 64-bit hex sessionID cookie, create & log session, return HTTP 200 with "Logged in!"
    if valid_login_credentials:
        session_id = random.getrandbits(64).to_bytes(8, "big").hex()
        response = requests.Response()
        logging.info(f'LOGIN SUCCESSFUL: {username} : {password}')
        response.set_cookie("session_id", session_id)
        response.status_code = 200
        response.content('Logged in!')
        return response
    else:
        response = requests.Response()
        logging.error(f'LOGIN FAILED: {username} : {password}')
        response.content('Login failed!')
        response.status_code = 200


#This function handles the login credentials for a given user. It returns True if the credentials are correct and False otherwise.    
def handle_login_credentials():
    
    with open('accounts.json', 'r') as f:
        accounts = json.load(f)

        