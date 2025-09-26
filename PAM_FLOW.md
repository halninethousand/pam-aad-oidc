PAM AAD OIDC Authentication Flow 

  🏗️ Architecture Overview

This PAM module provides dual-environment authentication - it works seamlessly on both Azure VMs and AWS EC2 instances using Azure AD as the identity provider, with automatic environment detection and fallback mechanisms.

  1. Entry Point & Token Detection

  ValidateCredentials(configPath, username, password)
  - Loads TOML configuration with Azure AD, AWS Cognito, and audience settings
  - Detects authentication method:
    - isJWT(password) → JWT token authentication (federated scenario)
    - Otherwise → OAuth2 password grant flow (traditional scenario)

  2. JWT vs Password Authentication Paths

  🔐 JWT Path (validateJWTCredentials)

  Used when client passes an Azure AD JWT token as the password:
  - Cryptographically validates JWT signature against Azure AD public keys
  - Verifies claims: issuer, audience, expiration
  - Extracts OID (Object ID) from JWT claims
  - Resolves identity name and checks group memberships

  🔑 Password Path (validatePasswordCredentials)

  Traditional OAuth2 password grant flow:
  - Direct authentication against Azure AD with username/password
  - Gets access token for Microsoft Graph API
  - Checks group memberships using the access token

  ---
   Environment Detection & Token Retrieval

  The Core Innovation: getGraphToken()

  This is the heart of the dual-environment support:

  getGraphToken(pamConfig, tenantID, clientID) → Graph API Token

  Flow:
  1. Try Azure IMDS first → getGraphTokenFromAzureIMDS()
    - Attempts: http://169.254.169.254/metadata/identity/oauth2/token
    - Success → Running on Azure VM, use managed identity
    - Failure → Not on Azure, try AWS federation
  2. Fallback to AWS Federation:
    - Generate Cognito JWT → getCognitoJWTWithAWSSDK()
    - Exchange for Graph token → getAzureTokenWithCognitoJWT()

  ---
  AWS → Azure Federation Flow (The Complex Part)

  AWS EC2 instances need to authenticate users against Azure AD, but:
  - No direct trust relationship between AWS EC2 and Azure AD
  - No Azure managed identity on AWS instances
  - Need Microsoft Graph API access for user/group lookups

  Solution: Workload Identity Federation

  Step 1: Client-Side Token Exchange (via connect_mysql_federated.sh)

  # 1. Get Cognito JWT from AWS
  COGNITO_JWT=$(aws cognito-identity get-open-id-token-for-developer-identity \
      --identity-pool-id "$COGNITO_POOL_ID" \
      --logins azure-access="$AZURE_CLIENT_ID")

  # 2. Use Cognito JWT to authenticate with Azure AD
  az login --federated-token "$COGNITO_JWT" --service-principal -u "$AZURE_CLIENT_ID"

  # 3. Get Azure AD token for our application
  AZURE_ACCESS_TOKEN=$(az account get-access-token --resource "") # insert as resource your api endpoint of the app

  # 4. Use Azure token as MySQL password
  mysql -u "$MYSQL_USER" -p"$AZURE_ACCESS_TOKEN"

  Step 2: PAM-Side Token Exchange (within the module)

  // When IMDS fails, PAM module does its own federation:
  cognitoJWT := getCognitoJWTWithAWSSDK(pamConfig, clientID)
  graphToken := getAzureTokenWithCognitoJWT(cognitoJWT, tenantID, pamConfig.MiID, "https://graph.microsoft.com")

  The Double Token Exchange Pattern

  1. Client-side exchange: Gets Azure AD token with app audience (for PAM authentication)
  2. PAM-side exchange: Gets Azure AD token with Graph audience (for identity/group lookups)

  Key Insight: We need two different tokens:
  - Authentication token: Audience = application (api client id)
  - Graph API token: Audience = Microsoft Graph (https://graph.microsoft.com)

  ---
  Infrastructure Requirements

  Azure Side:

  # Managed Identity with federated credential
  resource "azurerm_federated_identity_credential" "aws_cognito_federation" {
    audience  = ["<<AWS_cognito_identity_pool"]  # Cognito Pool ID
    issuer    = "https://cognito-identity.amazonaws.com"
    subject   = "<<AWS identity>>"   # Cognito Identity ID
  }

  # App Registration for MySQL authentication
  resource "azuread_application_registration" "mysql_srv" {
    display_name = "mysql_srv"
  }

  AWS Side:

  # Cognito Identity Pool configured as OIDC provider for Azure
  resource "aws_cognito_identity_pool" "azure_federation" {
    developer_provider_name = "azure-access"  # Key used in login mapping
    allow_unauthenticated_identities = false
  }

  ---
  Identity Resolution Process

  Unified Function: getDirectoryObjectInfo()

  objectType, identityName, err := getDirectoryObjectInfo(oid, pamConfig, tenantID, clientID)

  What it does:
  1. Gets Graph token (via automatic environment detection)
  2. Queries Microsoft Graph: https://graph.microsoft.com/v1.0/directoryObjects/{oid}
  3. Determines object type: #microsoft.graph.user vs #microsoft.graph.servicePrincipal
  4. Extracts appropriate identifier:
    - Users: UPN (User Principal Name) → extracts username part before @ or _
    - Managed Identities/Service Principals: DisplayName

  Group Membership Resolution: getGroupMemberships()

  groupNames, err := getGroupMemberships(userOID, pamConfig, tenantID, clientID)

  What it does:
  1. Gets Graph token (automatic environment detection)
  2. Determines object type (user vs service principal)
  3. Queries appropriate endpoint:
    - Users: https://graph.microsoft.com/v1.0/users/{oid}/memberOf
    - Service Principals: https://graph.microsoft.com/v1.0/servicePrincipals/{oid}/memberOf
  4. Filters for groups (#microsoft.graph.group type only)

  ---
  Authentication Decision Logic

  Three-Tier Validation:

  Primary Check: JWT Validation

  Secondary Check: Direct Identity Match

  if identityName == username {
      return PAM_SUCCESS  // Direct match - grant access
  }

  Tertiary Check: Group Membership

  for _, groupName := range aadGroupNames {
      if groupName == username {
          return PAM_SUCCESS  // User is member of group named 'username'
      }
  }
  return PAM_PERM_DENIED  // No match found

  Use Cases:

  - Direct identity authentication: mysql -u id-tdoc-mysqlentraauth-srv -p<JWT>
  - Group-based authentication: mysql -u mysql-admins -p<JWT> (where user is member of mysql-admins group)

  ---
  Key Peculiarities & Design Decisions

  1. Audience Strategy

  - App token audience: api token (for authentication)
  - Graph token audience: https://graph.microsoft.com (for API access)

  2. MiID Usage

  - Azure-only: Uses VM's assigned managed identity automatically via IMDS
  - AWS federated: Must explicitly specify managed identity via MiID config
  - Why? → AWS has no concept of Azure managed identities, need explicit mapping

  3. Double JWT Generation

  - Client generates: Cognito JWT → Azure app token (for auth)
  - PAM generates: Cognito JWT → Azure Graph token (for lookups)
  - Why not reuse? → Different audiences require separate token requests

  4. Environment Detection

  - Detection method: Try Azure IMDS, fallback if fails
  - No explicit config needed: Automatic based on infrastructure availability
  - Timeout considerations: Quick IMDS timeout prevents delays on AWS

  5. JWT Validation Robustness

  - Accepts both v1.0 and v2.0 issuers: https://login.microsoftonline.com/{tenant}/v2.0 and https://sts.windows.net/{tenant}/
  - Crypto verification: Full RSA signature validation against Azure AD public keys
  - Claims validation: Issuer, audience, expiration all verified

  6. Error Handling Philosophy

  - Graceful degradation: Azure IMDS failure doesn't break AWS functionality
  - Detailed logging: Every step logged for troubleshooting
  - Specific error codes: Different PAM return codes for different failure types

  ---
  Deployment Scenarios

  Scenario 1: Pure Azure VM

  tenant-id = "UUID of tenant"
  audience = "app client id"
  # No AWS config needed - IMDS handles everything

  Scenario 2: AWS EC2 with Federation

  tenant-id = "tenant id"
  audience = "app client id"
  mi_id = "managed identity id"     # Azure managed identity
  cognito-pool-id = "cognito pool id"
  cognito-region = "aws region"

  Scenario 3: Hybrid Multi-Cloud

  Same PAM module works on both environments with same config - automatic detection handles the differences.
