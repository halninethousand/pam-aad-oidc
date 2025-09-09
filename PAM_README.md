# PAM Azure AD OIDC Module

A PAM (Pluggable Authentication Module) for Linux systems that authenticates users against Azure Active Directory using OpenID Connect/OAuth2. This module supports both traditional password authentication and JWT token-based authentication for managed identities.

## Features

- **Password Authentication**: Traditional OAuth2 password grant flow
- **JWT Token Authentication**: Validate Azure AD JWT tokens for managed identities
- **Group-based Authorization**: Support for both direct identity matching and group delegation
- **Flexible Configuration**: TOML-based configuration with support for multiple authentication flows

## Prerequisites

### Percona MySQL Server Installation

Install Percona MySQL Server on both the MySQL server and client machines:

```bash
# Follow the official Percona documentation
# https://docs.percona.com/percona-server/8.0/apt-repo.html
```

### Azure Requirements

- **Entra App Registration** with client secret and respective Entra API permissions
- **Managed Identities** configured for both server and client VMs
- **Microsoft Graph API Permissions**: `User.Read.All`, `GroupMember.Read.All`, `Application.Read.All`

## Azure Infrastructure Setup

### Terraform Configuration

```hcl

resource "azuread_application_identifier_uri" "api_uri" {
  application_id = "/applications/${azuread_application_registration.mysql_srv.object_id}"
  identifier_uri = "api://${azuread_application_registration.mysql_srv.client_id}"
}

# User Impersonation Scope
resource "random_uuid" "user_impersonation" {}

resource "azuread_application_permission_scope" "user_impersonation" {
  application_id = azuread_application_registration.mysql_srv.id
  scope_id       = random_uuid.user_impersonation.id
  value          = "user_impersonation"

  admin_consent_description  = "User Impersonation"
  admin_consent_display_name = "Impersonation"
}

resource "azuread_application_pre_authorized" "user_impersonation_cli" {
  application_id       = azuread_application_registration.mysql_srv.id
  authorized_client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
  permission_ids       = [random_uuid.user_impersonation.id]
}

# Assign Graph API Permissions to Server Managed Identity
resource "azuread_app_role_assignment" "user_read_all" {
  principal_object_id = azurerm_user_assigned_identity.vm_server.principal_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
  app_role_id         = local.user_read_all_role_id
}

resource "azuread_app_role_assignment" "group_member_read_all" {
  principal_object_id = azurerm_user_assigned_identity.vm_server.principal_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
  app_role_id         = local.group_member_read_all_role_id
}

resource "azuread_app_role_assignment" "application_read_all" {
  principal_object_id = azurerm_user_assigned_identity.vm_server.principal_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
  app_role_id         = local.application_read_all_role_id
}
```

## Installation

### Install PAM Module

```bash
# Download the latest release
VER="0.2.3" # check the repo for newer tags
curl -L -o /tmp/pam_aad_oidc.so \
  https://github.com/halninethousand/pam-aad-oidc/releases/download/$VER/pam_aad_oidc.so

# Install to system
sudo install -o root -g root -m 0644 /tmp/pam_aad_oidc.so /lib/x86_64-linux-gnu/security/
```

## Configuration

### Step 1: Configure PAM for MySQL

Create `/etc/pam.d/mysql`:

```
#%PAM-1.0
# Authenticate via Entra ID (OIDC) using pam_aad_oidc
auth required pam_aad_oidc.so config=/etc/pam-aad-oidc.toml

# MySQL primarily uses 'auth'. If you need an 'account' stanza, allow it:
account required pam_permit.so
```

### Step 2: Enable Percona's PAM Plugin

Connect to MySQL and run:

```sql
INSTALL PLUGIN auth_pam SONAME 'auth_pam.so';

-- Verify installation:
SELECT PLUGIN_NAME, PLUGIN_STATUS
FROM information_schema.PLUGINS
WHERE PLUGIN_NAME='auth_pam';
```

### Step 3: Create Database Users

```sql
-- Your application database and roles
CREATE DATABASE IF NOT EXISTS appdb;
CREATE ROLE IF NOT EXISTS app_ro, app_rw;
GRANT SELECT ON appdb.* TO app_ro;
GRANT SELECT, INSERT, UPDATE, DELETE ON appdb.* TO app_rw;

-- Entra user 'jdoe@contoso.com' authenticates via PAM service 'mysql'
CREATE USER 'jdoe'@'%' IDENTIFIED WITH auth_pam AS 'mysql';
GRANT app_ro TO 'jdoe'@'%';
SET DEFAULT ROLE app_ro FOR 'jdoe'@'%';
```

### Step 4: Create Module Configuration

Create `/etc/pam-aad-oidc.toml`:

```toml
# Tenant (GUID) from Entra
tenant-id = "your-tenant-id-here"

# Audience (Application/Client ID)
audience = "your-client-id-here"

# Optional: Entra group whose members are allowed to authenticate
# Required for password authentication only
# group-name = "tdoc-test-poc"

# Default UPN domain appended if user types just 'jdoe'
domain = "contoso.com"

# Client secret (required for password authentication only)
# client-secret = "your-client-secret-here"
```

## Authentication Methods

### 1. Password Authentication (Traditional Users)

For regular Azure AD users with username and password:

```bash
mysql -h mysql-server.contoso.com -u jdoe -p
# Enter password when prompted
```

**Authentication Flow:**
1. Module performs OAuth2 password grant flow
2. Validates user credentials against Azure AD
3. Checks group membership (if `group-name` is configured)
4. Grants access if user belongs to specified group

### 2. JWT Token Authentication (Managed Identities)

For managed identities using JWT tokens:

```bash
# Get JWT token from managed identity
JWT_TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=api://your-client-id" \
  | jq -r '.access_token')

# Connect using JWT as password
mysql -h mysql-server.contoso.com -u id-tdoc-mysqlentraauth-clnt -p"$JWT_TOKEN"
```

**Authentication Flow:**
1. **Primary Check**: JWT managed identity name matches username → Success
2. **Secondary Check**: Username is a group that JWT managed identity belongs to → Success
3. Module validates JWT signature using Azure AD JWKS
4. Extracts managed identity details via Microsoft Graph API
5. Performs identity/group matching logic

## Authentication Logic

### JWT Token Validation

1. **Signature Verification**: Validates JWT using Azure AD's public keys (JWKS)
2. **Claims Validation**: Checks issuer, audience, and expiration
3. **Identity Extraction**: Gets managed identity OID and display name

### Authorization Logic

The module supports two authorization models:

#### Direct Identity Match
```
JWT managed identity name == MySQL username → Success
```

#### Group Delegation
```
MySQL username == Group name that JWT managed identity belongs to → Success
```

This allows managed identities to authenticate as groups they belong to, enabling flexible delegation scenarios.

## Security Considerations

- **JWT Validation**: Full cryptographic verification using Azure AD public keys
- **Token Scope**: Validates audience claim matches your application ID
- **Group Membership**: Uses Microsoft Graph API for real-time group validation
- **Managed Identity**: Server uses its own managed identity to query Graph API
- **No Token Storage**: Tokens are validated but never stored

## Troubleshooting

### Enable Debug Logging

Check system logs for PAM module output:

```bash
sudo tail -f /var/log/mysql/error.log
sudo tail -f /var/log/auth.log
# or
sudo journalctl -f -u mysql
```

### Common Issues

1. **JWT Validation Fails**: Check audience configuration in TOML file
2. **Graph API Errors**: Verify managed identity has required Graph permissions
3. **Group Not Found**: Ensure group names match exactly (case-sensitive)
4. **Token Expired**: JWT tokens have limited lifetime, regenerate as needed

## Architecture

```
┌─────────────────┐    JWT Token     ┌──────────────────┐
│   Client VM     │ ───────────────> │   MySQL Server   │
│  (Managed ID)   │                  │   (Managed ID)   │
└─────────────────┘                  └──────────────────┘
                                              │
                                              │ PAM Module
                                              ▼
                                     ┌─────────────────┐
                                     │  Azure AD /     │
                                     │ Microsoft Graph │
                                     └─────────────────┘
```

The PAM module acts as a bridge between MySQL's authentication system and Azure AD, providing secure, token-based authentication for cloud-native applications.
