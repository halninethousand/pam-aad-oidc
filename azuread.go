package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/BurntSushi/toml"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type Config struct {
	ClientID      string `toml:"client-d"`
	TenantID      string `toml:"tenant-id"`
	MiID          string `toml:"mi_id"` // Managed identity client ID for Azure SDK auth(used only in AWS federated flow)
	ClientSecret  string `toml:"client-secret"`
	GroupName     string `toml:"group-name"`
	Audience      string `toml:"audience"` // App registration client ID for token validation
	Domain        string `toml:"domain"`
	CognitoPoolID string `toml:"cognito-pool-id"` // AWS Cognito Identity Pool ID
	CognitoRegion string `toml:"cognito-region"`  // AWS Cognito region
}

type MicrosoftGraphResponse struct {
	Context string `json:"@odata.context"`
	Groups  []struct {
		Name string `json:"displayName"`
		Type string `json:"@odata.type"`
	} `json:"value"`
}

type ServicePrincipalResponse struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	AppID       string `json:"appId"`
}

type DirectoryObjectResponse struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	Type              string `json:"@odata.type"`
	UserPrincipalName string `json:"userPrincipalName,omitempty"` // Only present for users
}

// load config file
func LoadConfig(configPath string) (*Config, error) {
	if _, err := os.Stat(configPath); err != nil {
		return nil, fmt.Errorf("Unable locate config file. Error: %s", err)
	}
	var config Config
	if _, err := toml.DecodeFile(configPath, &config); err != nil {
		// log.Fatal(log_prefix, "Unable to load config file. Error: ", err)
		return nil, fmt.Errorf("Unable to load config file. Error: %s", err)
	}
	// tenant fallback
	if config.TenantID == "" {
		config.TenantID = "common"
	}
	return &config, nil
}

func ValidateCredentials(configPath string, username string, password string) int {
	var log_prefix = fmt.Sprintf("[%s] ", username)

	config, err := LoadConfig(configPath)
	if err != nil {
		log.Println(log_prefix, strings.ReplaceAll(err.Error(), "\n", ". "))
		return 4 // PAM_SYSTEM_ERR
	}

	if isJWT(password) {
		log.Println(log_prefix, "Azure AD JWT token detected, validating...")
		return validateJWTCredentials(config, username, password, log_prefix)
	}

	// password grant flow
	log.Println(log_prefix, "Using OAuth2 password grant flow...")
	return validatePasswordCredentials(config, username, password, log_prefix)
}

// password is JWT token
func isJWT(token string) bool {
	_, err := jwt.ParseInsecure([]byte(token))
	isValid := err == nil
	log.Printf("JWT Detection: length=%d, parts=%d, isJWT=%v", len(token), len(strings.Split(token, ".")), isValid)
	return isValid
}

// validate JWT token and check group membership
func validateJWTCredentials(config *Config, username string, token string, log_prefix string) int {
	log.Printf("%s DEBUG: Starting JWT validation for username: %s", log_prefix, username)
	log.Printf("%s DEBUG: Token length: %d characters", log_prefix, len(token))
	log.Printf("%s DEBUG: Config - TenantID: %s, Audience: %s", log_prefix, config.TenantID, config.Audience)

	claims, err := validateJWTSignature(token, config.TenantID, config.Audience)
	if err != nil {
		log.Println(log_prefix, "JWT validation failed:", err)
		return 7 // PAM_AUTH_ERR
	}

	log.Printf("%s DEBUG: JWT signature validation successful", log_prefix)

	log.Printf("%s DEBUG: JWT claims: %+v", log_prefix, claims)

	jwtOID, ok := claims["oid"].(string)
	if !ok {
		log.Println(log_prefix, "JWT missing 'oid' claim")
		return 7 // PAM_AUTH_ERR
	}

	log.Printf("%s DEBUG: JWT OID extracted: %s", log_prefix, jwtOID)

	// primary check: Get identity name (UPN for users, display name for managed identities) and compare with username
	_, identityName, err := getDirectoryObjectInfo(jwtOID, config, config.TenantID, getClientIDFromJWT(claims))
	if err != nil {
		log.Println(log_prefix, "Failed to get identity name:", err)
		return 8 // PAM_CRED_INSUFFICIENT
	}

	log.Println(log_prefix, "JWT identity:", identityName, "Username:", username)

	if identityName == username {
		log.Println(log_prefix, "JWT authentication succeeded - direct match")
		return 0 // PAM_SUCCESS
	}

	// secondary check: check if username is a group that the JWT identity belongs to
	log.Println(log_prefix, "No direct match, checking if username is a group that JWT identity belongs to")

	aadGroupNames, err := getGroupMemberships(jwtOID, config, config.TenantID, getClientIDFromJWT(claims))
	if err != nil {
		log.Println(log_prefix, "Failed to retrieve JWT identity group memberships:", err)
		return 8 // PAM_CRED_INSUFFICIENT
	}

	log.Println(log_prefix, "identityName:", identityName, "username:", username)
	log.Println(log_prefix, "aadGroupNames:", aadGroupNames)

	// check if username matches any group that the JWT identity belongs to
	for _, aadGroupName := range aadGroupNames {
		if aadGroupName == username {
			log.Println(log_prefix, "JWT authentication succeeded - username is a group that JWT identity belongs to")
			return 0 // PAM_SUCCESS
		}
	}

	log.Println(log_prefix, "JWT authentication failed - no match found")
	return 6 // PAM_PERM_DENIED
}

// password authentication
func validatePasswordCredentials(config *Config, username string, password string, log_prefix string) int {
	// Generate the OAuth2 config
	oauth2Config := oauth2.Config{
		ClientID:     config.Audience,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.microsoftonline.com/" + config.TenantID + "/oauth2/v2.0/authorize",
			TokenURL: "https://login.microsoftonline.com/" + config.TenantID + "/oauth2/v2.0/token",
		},
		RedirectURL: "urn:ietf:wg:oauth:2.0:oob",                      // this is the "no redirect" URL
		Scopes:      []string{"https://graph.microsoft.com/.default"}, // use the default scopes registered with the application
	}

	// If there is no suffix then use the default domain
	if !strings.Contains(username, "@") {
		username = username + "@" + config.Domain
	}

	// Retrieve an OAuth token from AzureAD
	// The "password" grant type should only be used "when there is a high degree
	// of trust between the resource owner and the client (e.g., the client is
	// part of the device operating system or a highly privileged application),
	// and when other authorization grant types are not available."
	// See https://tools.ietf.org/html/rfc6749#section-4.3 for more info.
	oauthToken, err := oauth2Config.PasswordCredentialsToken(
		context.Background(),
		username,
		password,
	)
	// Note that we do not perform further validity checks as we are not using
	// this token directly but instead using it to make a further request against
	// the Microsoft Graph API that will fail if the token is invalid.
	if err != nil {
		log.Println(log_prefix, strings.ReplaceAll(err.Error(), "\n", ". "))
		return 7 // PAM_AUTH_ERR
	}

	// Use the access token to retrieve group memberships for the user in question
	// We compare these against the specified group name to determine whether
	// authentication is successful.
	aadGroupNames, err := RetrieveAADGroupMemberships(oauthToken.AccessToken)
	if err != nil {
		log.Println(log_prefix, "AzureAD groups could not be loaded for this user")
		return 8 // PAM_CRED_INSUFFICIENT
	}
	for _, aadGroupName := range aadGroupNames {
		if aadGroupName == config.GroupName {
			log.Println(log_prefix, "OAuth2 authentication succeeded")
			return 0 // PAM_SUCCESS
		}
	}

	log.Println(log_prefix, "OAuth2 authentication was successful but authorization failed")
	return 6 // PAM_PERM_DENIED
}

func validateJWTSignature(token string, tenantID string, audience string) (map[string]interface{}, error) {
	log.Printf("DEBUG: validateJWTSignature starting - tenantID: %s, audience: %s", tenantID, audience)

	jwksURL := fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", tenantID)
	log.Printf("DEBUG: Fetching JWKS from: %s", jwksURL)

	// fetch JWKS
	set, err := jwk.Fetch(context.Background(), jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %v", err)
	}

	log.Printf("DEBUG: JWKS fetched successfully, contains %d keys", set.Len())

	// extract key ID from JWT header
	parts := strings.Split(token, ".")
	var tokenKid string
	if len(parts) >= 1 {
		headerData, headerErr := base64.RawURLEncoding.DecodeString(parts[0])
		if headerErr == nil {
			var header map[string]interface{}
			if json.Unmarshal(headerData, &header) == nil {
				if kid, ok := header["kid"].(string); ok {
					tokenKid = kid
					log.Printf("DEBUG: Token expects kid: %s", tokenKid)
				}
			}
		}
	}

	if tokenKid == "" {
		return nil, fmt.Errorf("JWT header missing key ID (kid)")
	}

	// find and use the specific key
	log.Printf("DEBUG: Looking for key: %s", tokenKid)
	key, found := set.LookupKeyID(tokenKid)
	if !found {
		return nil, fmt.Errorf("JWKS does not contain key with ID: %s", tokenKid)
	}

	// parse and verify token with the specific key
	log.Printf("DEBUG: Verifying JWT signature with key: %s", tokenKid)
	verifiedToken, err := jwt.Parse([]byte(token), jwt.WithKey(jwa.RS256, key))
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %v", err)
	}

	// expiration
	if time.Now().After(verifiedToken.Expiration()) {
		return nil, fmt.Errorf("token expired")
	}

	log.Printf("DEBUG: JWT signature and expiration verification successful")
	log.Printf("DEBUG: Token issuer: %s", verifiedToken.Issuer())
	log.Printf("DEBUG: Token audience: %v", verifiedToken.Audience())
	log.Printf("DEBUG: Token expiration: %s", verifiedToken.Expiration())

	// check issuer - accept both v1.0 and v2.0 formats
	actualIssuer := verifiedToken.Issuer()
	expectedIssuerV2 := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)
	expectedIssuerV1 := fmt.Sprintf("https://sts.windows.net/%s/", tenantID)

	log.Printf("DEBUG: Checking issuer - actual: %s", actualIssuer)
	log.Printf("DEBUG: Expected issuers - v2.0: %s, v1.0: %s", expectedIssuerV2, expectedIssuerV1)

	if actualIssuer != expectedIssuerV2 && actualIssuer != expectedIssuerV1 {
		return nil, fmt.Errorf("invalid issuer: got %s, expected %s or %s", actualIssuer, expectedIssuerV2, expectedIssuerV1)
	}

	log.Printf("DEBUG: Issuer validation passed")

	// Check audience (validate token is for our application)
	expectedAud := audience
	tokenAuds := verifiedToken.Audience()

	log.Printf("DEBUG: Checking audience - expected: %s", expectedAud)
	log.Printf("DEBUG: Token audiences: %v", tokenAuds)

	validAud := false
	for _, aud := range tokenAuds {
		if aud == expectedAud {
			validAud = true
			break
		}
	}
	if !validAud {
		return nil, fmt.Errorf("invalid audience: token not issued for this application - expected %s, got %v", expectedAud, tokenAuds)
	}

	log.Printf("DEBUG: Audience validation passed")

	// map conversion
	claims := make(map[string]interface{})
	for iter := verifiedToken.Iterate(context.Background()); iter.Next(context.Background()); {
		pair := iter.Pair()
		claims[pair.Key.(string)] = pair.Value
	}

	return claims, nil
}

// group membership lookup with automatic token retrieval
func getGroupMemberships(userOID string, pamConfig *Config, tenantID, clientID string) ([]string, error) {
	// get Graph token with fallback
	graphToken, err := getGraphToken(pamConfig, tenantID, clientID)
	if err != nil {
		return []string{}, fmt.Errorf("failed to get Graph token: %v", err)
	}

	return getGroupMembershipsWithToken(userOID, graphToken)
}

// get group memberships with provided Graph token
func getGroupMembershipsWithToken(userOID, graphToken string) ([]string, error) {
	groupNames := []string{}

	// determine the type of object (oid)
	objectType, _, err := getDirectoryObjectInfoWithToken(userOID, graphToken)
	if err != nil {
		return groupNames, fmt.Errorf("failed to determine object type: %v", err)
	}

	log.Printf("DEBUG: Directory Object Type: %s, OID: %s", objectType, userOID)

	// determine the correct Graph API endpoint based on object type
	var graphURL string
	if objectType == "#microsoft.graph.user" {
		graphURL = "https://graph.microsoft.com/v1.0/users/" + userOID + "/memberOf"
	} else {
		// default to servicePrincipals endpoint for managed identities
		graphURL = "https://graph.microsoft.com/v1.0/servicePrincipals/" + userOID + "/memberOf"
	}

	// get object's group memberships
	req, err := http.NewRequest("GET", graphURL, nil)
	if err != nil {
		return groupNames, err
	}
	req.Header.Add("Authorization", "Bearer "+graphToken)

	log.Printf("DEBUG: Graph API URL for group memberships: %s", graphURL)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return groupNames, err
	}
	defer resp.Body.Close()

	log.Printf("DEBUG: Graph API Response Status: %d", resp.StatusCode)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return groupNames, err
	}

	log.Printf("DEBUG: Graph API Response Body: %s", string(body))

	var response MicrosoftGraphResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return groupNames, err
	}

	// group names
	for _, group := range response.Groups {
		if group.Type == "#microsoft.graph.group" {
			groupNames = append(groupNames, group.Name)
		}
	}

	return groupNames, nil
}

// identity resolution
// unified directory object lookup with automatic token retrieval
func getDirectoryObjectInfo(oid string, pamConfig *Config, tenantID, clientID string) (string, string, error) {
	// get Graph token with automatic fallback
	graphToken, err := getGraphToken(pamConfig, tenantID, clientID)
	if err != nil {
		return "", "", fmt.Errorf("failed to get Graph token: %v", err)
	}

	return getDirectoryObjectInfoWithToken(oid, graphToken)
}

// get directory object info using provided Graph token
func getDirectoryObjectInfoWithToken(oid, graphToken string) (string, string, error) {
	graphURL := "https://graph.microsoft.com/v1.0/directoryObjects/" + oid
	req, err := http.NewRequest("GET", graphURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Add("Authorization", "Bearer "+graphToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	log.Printf("DEBUG: Graph API Response Status: %d", resp.StatusCode)
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("Graph API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var response DirectoryObjectResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", "", fmt.Errorf("failed to parse directory object response: %v", err)
	}

	// for users, return UPN; for managed identities and others return DisplayName
	var identifier string
	if response.Type == "#microsoft.graph.user" {
		// extract just the username part before the @ or _
		identifier = response.UserPrincipalName
		if strings.Contains(identifier, "_") {
			parts := strings.Split(identifier, "_")
			identifier = parts[0]
		}
	} else {
		identifier = response.DisplayName
	}

	log.Printf("DEBUG: Resolved identity: type=%s, identifier=%s", response.Type, identifier)
	return response.Type, identifier, nil
}

// get Graph token with automatic fallback from Azure IMDS to AWS federated flow
func getGraphToken(pamConfig *Config, tenantID, clientID string) (string, error) {
	// first try IMDS for Azure VMs
	log.Printf("DEBUG: Trying IMDS for Graph token")
	token, err := getGraphTokenFromAzureIMDS()
	if err == nil {
		log.Printf("DEBUG: Successfully got Graph token from Azure IMDS")
		return token, nil
	}

	log.Printf("DEBUG: IMDS failed (%v), trying AWS→Azure SDK chain", err)

	// fallback: AWS→Azure federated chain
	// AWS SDK generate Cognito JWT
	cognitoJWT, err := getCognitoJWTWithAWSSDK(pamConfig, clientID)
	if err != nil {
		return "", fmt.Errorf("failed to generate Cognito JWT via AWS SDK: %v", err)
	}

	// Cognito JWT with Azure SDK to get Graph token
	graphToken, err := getAzureTokenWithCognitoJWT(cognitoJWT, tenantID, pamConfig.MiID, "https://graph.microsoft.com")
	if err != nil {
		return "", fmt.Errorf("failed to get Graph token via Azure SDK: %v", err)
	}

	log.Printf("DEBUG: Successfully got Graph token via AWS→Azure SDK chain")
	return graphToken, nil
}

func getGraphTokenFromAzureIMDS() (string, error) {
	// IMDS token url
	imdsURL := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com"

	req, err := http.NewRequest("GET", imdsURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Metadata", "true")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	log.Printf("DEBUG: IMDS Response Status: %d", resp.StatusCode)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("IMDS returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}

	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("failed to parse IMDS response: %v", err)
	}

	return tokenResponse.AccessToken, nil
}

// get Graph token using Azure SDK with the provided JWT token
func getGraphTokenWithAzureSDK(jwtToken, tenantID, clientID string) (string, error) {
	log.Printf("DEBUG: Using Azure SDK to get Graph token")

	// create a client assertion credential using the JWT token
	cred, err := azidentity.NewClientAssertionCredential(
		tenantID,
		clientID,
		func(ctx context.Context) (string, error) {
			return jwtToken, nil
		},
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create Azure credential: %v", err)
	}

	// get graph token
	ctx := context.Background()
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://graph.microsoft.com/.default"},
	})
	if err != nil {
		return "", fmt.Errorf("failed to get Graph token: %v", err)
	}

	log.Printf("DEBUG: Successfully got Graph token via Azure SDK")
	return token.Token, nil
}

// get Azure AD token using Cognito JWT for specific resource
func getAzureTokenWithCognitoJWT(cognitoJWT, tenantID, clientID, resource string) (string, error) {
	log.Printf("DEBUG: Using Cognito JWT to get Azure token for resource: %s", resource)

	// create a client assertion credential using the Cognito JWT
	cred, err := azidentity.NewClientAssertionCredential(
		tenantID,
		clientID,
		func(ctx context.Context) (string, error) {
			return cognitoJWT, nil
		},
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create Azure credential: %v", err)
	}

	// determine the scope based on resource
	var scopes []string
	if resource == "https://graph.microsoft.com" {
		scopes = []string{"https://graph.microsoft.com/.default"}
	} else {
		// For app-specific resources, use the resource as scope
		scopes = []string{resource + "/.default"}
	}

	// get token for the specified resource
	ctx := context.Background()
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: scopes,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get Azure token for %s: %v", resource, err)
	}

	log.Printf("DEBUG: Successfully got Azure token for %s", resource)
	return token.Token, nil
}

func getCognitoJWTWithAWSSDK(pamConfig *Config, azureClientID string) (string, error) {
	log.Printf("DEBUG: Using AWS SDK to generate Cognito JWT")
	log.Printf("DEBUG: Cognito Pool ID: %s, Region: %s", pamConfig.CognitoPoolID, pamConfig.CognitoRegion)

	// Load AWS configuration
	ctx := context.Background()
	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(pamConfig.CognitoRegion))
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %v", err)
	}

	client := cognitoidentity.NewFromConfig(awsConfig)

	// GetOpenIdTokenForDeveloperIdentity (equivalent to aws cognito-identity get-open-id-token-for-developer-identity)
	input := &cognitoidentity.GetOpenIdTokenForDeveloperIdentityInput{
		IdentityPoolId: aws.String(pamConfig.CognitoPoolID),
		Logins: map[string]string{
			"azure-access": azureClientID, // azure-access is the key that specifies the ClientID in the AWS connection
		},
	}

	result, err := client.GetOpenIdTokenForDeveloperIdentity(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to get Cognito JWT: %v", err)
	}

	if result.Token == nil {
		return "", fmt.Errorf("Cognito JWT token is nil")
	}

	token := *result.Token
	log.Printf("DEBUG: Successfully generated Cognito JWT, length: %d", len(token))

	return token, nil
}

func getClientIDFromJWT(claims map[string]interface{}) string {
	if azp, ok := claims["azp"].(string); ok {
		return azp
	}
	return ""
}

// RetrieveAADGroupMemberships returns a []string containing the names
// of Azure AD groups that this user belongs to, using the provided
// bearer token.
func RetrieveAADGroupMemberships(bearerToken string) ([]string, error) {
	groupNames := []string{}

	// AzureAD access tokens are *NOT* verifiable JWTs and can only be validated by Microsoft Graph
	// See https://stackoverflow.com/questions/60778634/failing-signature-validation-of-jwt-tokens-from-azure-ad
	// and https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/609#issuecomment-529537264
	parsedToken, err := jwt.ParseInsecure([]byte(bearerToken))
	if err != nil {
		return groupNames, err
	}

	// Instead of verifying the token via its signature, we verify it by its capabilities
	// Namely, we extract the userId and use this, to to make a call to the Microsoft Graph API
	userId := parsedToken.PrivateClaims()["oid"].(string)

	// Create a new request using http with correct authorization header
	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/users/"+userId+"/memberOf", nil)
	req.Header.Add("Authorization", "Bearer "+bearerToken)

	// Use http Client to send the request, closing when finished
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return groupNames, err
	}
	defer resp.Body.Close()

	// Read response and unmarshal JSON into a struct
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return groupNames, err
	}
	var response MicrosoftGraphResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return groupNames, err
	}

	// Look through the struct for Microsoft Graph groups
	for _, group := range response.Groups {
		if group.Type == "#microsoft.graph.group" {
			groupNames = append(groupNames, group.Name)
		}
	}
	return groupNames, nil
}
