# Set your server IP and port
SERVER_IP="127.0.0.1"
SERVER_PORT="8080"

# Variables for storing session cookies
SESSION_COOKIE=""

# Common curl options for HTTP/1.0 and connection close
CURL_OPTIONS="--http1.0 --connect-timeout 5 --max-time 10 --fail --silent"


#test 1 no username
    SESSION_COOKIE1=$(curl -i -v -X POST -H "username:" -H "password: 4W61E0D8P37GLLX" "http://${SERVER_IP}:${SERVER_PORT}/" | grep -i 'Set-Cookie' | cut -d ' ' -f 2 | cut -d '=' -f 2)
    echo "\\nCookie (sessionID) for user: $SESSION_COOKIE1"

#test 2 no password
    SESSION_COOKIE2=$(curl -i -v -X POST -H "username: Jerry" -H "password:" "http://${SERVER_IP}:${SERVER_PORT}/" | grep -i 'Set-Cookie' | cut -d ' ' -f 2 | cut -d '=' -f 2)
    echo "\\nCookie (sessionID) for user: $SESSION_COOKIE2"

#test 3 wrong username
    SESSION_COOKIE3=$(curl -i -v -X POST -H "username: erry" -H "password: 4W61E0D8P37GLLX" "http://${SERVER_IP}:${SERVER_PORT}/" | grep -i 'Set-Cookie' | cut -d ' ' -f 2 | cut -d '=' -f 2)
    echo "\\nCookie (sessionID) for user: $SESSION_COOKIE3"

#test 4 wrong password
    SESSION_COOKIE4=$(curl -i -v -X POST -H "username: Jerry" -H "password: 461E0D8P37GLLX" "http://${SERVER_IP}:${SERVER_PORT}/" | grep -i 'Set-Cookie' | cut -d ' ' -f 2 | cut -d '=' -f 2)
    echo "\\nCookie (sessionID) for user: $SESSION_COOKIE4"

#test 5 correct POST and 6 generate cookie
    SESSION_COOKIE5=$(curl -i -v -X POST -H "username: Jerry" -H "password: 4W61E0D8P37GLLX" "http://${SERVER_IP}:${SERVER_PORT}/" | grep -i 'Set-Cookie' | cut -d ' ' -f 2 | cut -d '=' -f 2)
    echo "\\nCookie (sessionID) for user: $SESSION_COOKIE2"

#test 7 wrong cookie
    output=$(curl $CURL_OPTIONS -v -X GET -H "Cookies: sessionID=ea9394181" "http://${SERVER_IP}:${SERVER_PORT}/file.txt")
    echo "output: $output"
#test 8 one user at a time
    SESSION_COOKIE8=$(curl -i -v -X POST -H "username: Vincent" -H "password: U647U9X9Q1XMVXH" "http://${SERVER_IP}:${SERVER_PORT}/" | grep -i 'Set-Cookie' | cut -d ' ' -f 2 | cut -d '=' -f 2)
    echo "\\nCookie (sessionID) for user: $SESSION_COOKIE8"

#test 9
    SESSION_COOKIE9=$(curl -i -v -X POST -H "username: Ben" -H "password: PXMAZPRE0H0U0OD" "http://${SERVER_IP}:${SERVER_PORT}/" | grep -i 'Set-Cookie' | cut -d ' ' -f 2 | cut -d '=' -f 2)
    echo "\\nCookie (sessionID) for user: $SESSION_COOKIE9"

#test 10
    output=$(curl $CURL_OPTIONS -v -X GET -H "Cookies: sessionID=$SESSION_COOKIE9" "http://${SERVER_IP}:${SERVER_PORT}/file.txt")
    echo "output: $output"
#test 11
    output=$(curl $CURL_OPTIONS -v -X GET -H "Cookies: sessionID=$SESSION_COOKIE9" "http://${SERVER_IP}:${SERVER_PORT}/file.tt")
    echo "output: $output"
    sleep 6
#test 12
    output=$(curl $CURL_OPTIONS -v -X GET -H "Cookies: sessionID=$SESSION_COOKIE9" "http://${SERVER_IP}:${SERVER_PORT}/file.txt")
    echo "output: $output"








