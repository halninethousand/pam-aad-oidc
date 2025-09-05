#!/bin/bash

# MySQL Azure AD Authentication Script
# Combines JWT token auth in an MySQL connection via PAM
#
# Usage: ./connect_mysql.sh RESOURCE MYSQL_HOST MYSQL_USER
#
# Arguments:
#   RESOURCE    - Azure AD application URI (required)
#   MYSQL_HOST  - MySQL server hostname or IP (required)
#   MYSQL_USER  - MySQL username (required)

# az login --identity --allow-no-subscriptions #### first auth

set -e  # exit on any error

if [ $# -ne 3 ]; then
    echo "ERROR: Missing required arguments"
    echo "Usage: $0 RESOURCE MYSQL_HOST MYSQL_USER"
    echo
    echo "Example:"
    echo "  $0 api://d24e142a-8920-4ccf-8412-6ddcf3cdb679 10.0.4.5 id-tdoc-mysqlentraauth-clnt"
    exit 1
fi

RESOURCE="$1"
MYSQL_HOST="$2"
MYSQL_USER="$3"

echo "=== MySQL Azure AD Authentication ==="
echo "Getting JWT token from managed identity..."

JWT_TOKEN=$(curl -s -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=${RESOURCE}" \
    | jq -r '.access_token')

if [ -z "$JWT_TOKEN" ] || [ "$JWT_TOKEN" == "null" ]; then
    echo "ERROR: Failed to get JWT token from managed identity"
    exit 1
fi

echo "✓ JWT token retrieved successfully"
echo "Token length: ${#JWT_TOKEN} characters"
echo

echo "Connecting to MySQL server..."
echo "Host: $MYSQL_HOST"
echo "User: $MYSQL_USER"
echo

mysql -h "$MYSQL_HOST" -u "$MYSQL_USER" -p"$JWT_TOKEN"
