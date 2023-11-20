# Set your server IP and port
SERVER_IP="127.0.0.1"
SERVER_PORT="8080"

# Variables for storing session cookies
SESSION_COOKIE=""

# Common curl options for HTTP/1.0 and connection close
CURL_OPTIONS="--http1.0 --connect-timeout 5 --max-time 10 --fail --silent"



curl $CURL_OPTIONS -v -X GET -H "Cookies: sessionID=e7c986ef7e2020b7" "http://${SERVER_IP}:${SERVER_PORT}/file.txt"


