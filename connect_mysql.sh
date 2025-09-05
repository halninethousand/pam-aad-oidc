#!/bin/bash

# MySQL Azure AD Authentication Script
# Combines JWT token auth in an MySQL connection via PAM

# az login --identity --allow-no-subscriptions #### first auth

set -e  # Exit on any error

RESOURCE="api://d24e142a-8920-4ccf-8412-6ddcf3cdb679"
MYSQL_HOST="10.0.4.5"
MYSQL_USER="id-tdoc-mysqlentraauth-clnt"

echo "=== MySQL Azure AD Authentication ==="
echo "Getting JWT token from managed identity..."

# imds call
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
