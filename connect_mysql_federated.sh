#!/bin/bash

# MySQL AWS→Azure AD Federated Authentication Script
# Combines AWS Cognito JWT → Azure AD access token → MySQL PAM authentication
#
# Usage: ./connect_mysql_federated.sh COGNITO_POOL_ID AZURE_CLIENT_ID TENANT_ID MYSQL_HOST MYSQL_USER
#
# Arguments:
#   COGNITO_POOL_ID - AWS Cognito Identity Pool ID (required)
#   AZURE_CLIENT_ID - Azure AD App/Managed Identity Client ID (required)
#   TENANT_ID      - Azure AD Tenant ID (required)
#   MYSQL_HOST     - MySQL server hostname or IP (required)
#   MYSQL_USER     - MySQL username (required)

set -e  # exit on any error

if [ $# -ne 5 ]; then
    echo "ERROR: Missing required arguments"
    echo "Usage: $0 COGNITO_POOL_ID AZURE_CLIENT_ID TENANT_ID MYSQL_HOST MYSQL_USER"
    echo
    echo "Example:"
    echo "  $0 eu-west-2:9937d6dc-ccaa-4097-9760-886658452cc0 7ae70a4d-ceb3-45cc-b15b-1c3aba6ef231 f976abbe-fa68-4d4f-bcf7-7038d98c8385 10.0.4.5 id-tdoc-mysqlentraauth-srv"
    exit 1
fi

COGNITO_POOL_ID="$1"
AZURE_CLIENT_ID="$2"
TENANT_ID="$3"
MYSQL_HOST="$4"
MYSQL_USER="$5"

echo "=== AWS → Azure AD Federated MySQL Authentication ==="
echo "Step 1: Getting AWS Cognito developer identity token..."

# Get Cognito Identity ID for developer identity
COGNITO_JWT=$(aws cognito-identity get-open-id-token-for-developer-identity \
    --identity-pool-id "$COGNITO_POOL_ID" \
    --logins azure-access="$AZURE_CLIENT_ID" \
    --region eu-west-2 \
    --query 'Token' --output text)

if [ -z "$COGNITO_JWT" ] || [ "$COGNITO_JWT" == "null" ]; then
    echo "ERROR: Failed to get Cognito JWT token"
    exit 1
fi

echo "✓ AWS Cognito JWT token obtained"
echo "Token length: ${#COGNITO_JWT} characters"
echo

echo "Step 2: Exchanging Cognito JWT for Azure AD access token..."

# az login with the Cognito JWT token to get Azure AD access
az login --allow-no-subscriptions \
    --federated-token "$COGNITO_JWT" \
    --tenant "$TENANT_ID" \
    --service-principal \
    -u "$AZURE_CLIENT_ID" > /dev/null

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to authenticate with Azure AD using Cognito token"
    exit 1
fi

AZURE_ACCESS_TOKEN=$(az account get-access-token --resource "api://755d3f85-e44b-4e2a-ab88-55b0c7689017" --query 'accessToken' --output tsv)

if [ -z "$AZURE_ACCESS_TOKEN" ] || [ "$AZURE_ACCESS_TOKEN" == "null" ]; then
    echo "ERROR: Failed to get Azure AD access token"
    exit 1
fi

echo "✓ Azure AD access token obtained"
echo "Token length: ${#AZURE_ACCESS_TOKEN} characters"
echo

echo "Step 3: Connecting to MySQL with Azure AD token..."
echo "Host: $MYSQL_HOST"
echo "User: $MYSQL_USER"
echo "Note: PAM module will regenerate Cognito JWT internally for Graph API access"
echo

# Connect to MySQL using the Azure AD access token as password
mysql -h "$MYSQL_HOST" -u "$MYSQL_USER" -p"$AZURE_ACCESS_TOKEN"
