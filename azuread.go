package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

type Config struct {
	TenantID     string `toml:"tenant-id"`
	ClientSecret string `toml:"client-secret"`
	GroupName    string `toml:"group-name"`
	Audience     string `toml:"audience"`
	Domain       string `toml:"domain"`
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

type OpenIDConfig struct {
	Issuer  string `json:"issuer"`
	JwksUri string `json:"jwks_uri"`
}

type JWKSResponse struct {
	Keys []struct {
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
		Kty string `json:"kty"`
	} `json:"keys"`
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
		log.Println(log_prefix, "JWT token detected, validating...")
		return validateJWTCredentials(config, username, password, log_prefix)
	}

	// password grant flow
	log.Println(log_prefix, "Using OAuth2 password grant flow...")
	return validatePasswordCredentials(config, username, password, log_prefix)
}

// password is JWT token
func isJWT(token string) bool {
	parts := strings.Split(token, ".")
	isJWT := len(parts) == 3 && len(token) > 100
	log.Printf("JWT Detection: length=%d, parts=%d, isJWT=%v", len(token), len(parts), isJWT)
	return isJWT
}

// validate JWT token and check group membership
func validateJWTCredentials(config *Config, username string, token string, log_prefix string) int {
	claims, err := validateJWTSignature(token, config.TenantID)
	if err != nil {
		log.Println(log_prefix, "JWT validation failed:", err)
		return 7 // PAM_AUTH_ERR
	}

	jwtOID, ok := claims["oid"].(string)
	if !ok {
		log.Println(log_prefix, "JWT missing 'oid' claim")
		return 7 // PAM_AUTH_ERR
	}

	// primary check: Get managed identity display name and compare with username
	managedIdentityName, err := getManagedIdentityDisplayName(jwtOID)
	if err != nil {
		log.Println(log_prefix, "Failed to get managed identity name:", err)
		return 8 // PAM_CRED_INSUFFICIENT
	}

	log.Println(log_prefix, "JWT managed identity:", managedIdentityName, "Username:", username)

	if managedIdentityName == username {
		log.Println(log_prefix, "JWT authentication succeeded - direct match")
		return 0 // PAM_SUCCESS
	}

	// secondary check: check if username is a group that the JWT managed identity belongs to
	log.Println(log_prefix, "No direct match, checking if username is a group that JWT managed identity belongs to")

	aadGroupNames, err := RetrieveAADGroupMembershipsViaIMDS(jwtOID)
	if err != nil {
		log.Println(log_prefix, "Failed to retrieve JWT managed identity group memberships:", err)
		return 8 // PAM_CRED_INSUFFICIENT
	}

	// check if username matches any group that the JWT managed identity belongs to
	for _, aadGroupName := range aadGroupNames {
		if aadGroupName == username {
			log.Println(log_prefix, "JWT authentication succeeded - username is a group that JWT managed identity belongs to")
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
		RedirectURL: "urn:ietf:wg:oauth:2.0:oob", // this is the "no redirect" URL
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

func validateJWTSignature(token string, tenantID string) (map[string]interface{}, error) {
	wellKnownURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration", tenantID)
	resp, err := http.Get(wellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get OpenID config: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OpenID config: %v", err)
	}

	var config OpenIDConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("failed to parse OpenID config: %v", err)
	}

	// parse token to get key ID from header
	parsedToken, err := jwt.ParseInsecure([]byte(token))
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	// get key ID from private claims (jwx library stores header info differently)
	keyID, ok := parsedToken.PrivateClaims()["kid"].(string)
	if !ok {
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid JWT format")
		}

		headerData, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, fmt.Errorf("failed to decode JWT header: %v", err)
		}

		var header map[string]interface{}
		if err := json.Unmarshal(headerData, &header); err != nil {
			return nil, fmt.Errorf("failed to parse JWT header: %v", err)
		}

		keyID, ok = header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("no kid found in token header")
		}
	}

	// Get JWKS
	resp, err = http.Get(config.JwksUri)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %v", err)
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS: %v", err)
	}

	var jwks JWKSResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %v", err)
	}

	// Find matching key
	var publicKey *rsa.PublicKey
	for _, key := range jwks.Keys {
		if key.Kid == keyID && key.Kty == "RSA" {
			// Convert JWK to RSA public key
			n, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				continue
			}
			e, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				continue
			}

			publicKey = &rsa.PublicKey{
				N: new(big.Int).SetBytes(n),
				E: int(new(big.Int).SetBytes(e).Int64()),
			}
			break
		}
	}

	if publicKey == nil {
		return nil, fmt.Errorf("no matching key found for kid: %s", keyID)
	}

	// create JWK from RSA public key
	rsaKey, err := jwk.FromRaw(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK: %v", err)
	}

	// verify token using RS256 algorithm
	verifiedToken, err := jwt.Parse([]byte(token), jwt.WithKey(jwa.RS256, rsaKey))
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %v", err)
	}

	// check expiration
	if time.Now().After(verifiedToken.Expiration()) {
		return nil, fmt.Errorf("token expired")
	}

	// check issuer
	expectedIssuer := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)
	if verifiedToken.Issuer() != expectedIssuer {
		return nil, fmt.Errorf("invalid issuer: got %s, expected %s", verifiedToken.Issuer(), expectedIssuer)
	}

	// check audience (validate token is for our application)
	expectedAud := config.Audience
	tokenAuds := verifiedToken.Audience()
	validAud := false
	for _, aud := range tokenAuds {
		if aud == expectedAud {
			validAud = true
			break
		}
	}
	if !validAud {
		return nil, fmt.Errorf("invalid audience: token not issued for this application")
	}

	// convert to map for easier access
	claims := make(map[string]interface{})
	for iter := verifiedToken.Iterate(context.Background()); iter.Next(context.Background()); {
		pair := iter.Pair()
		claims[pair.Key.(string)] = pair.Value
	}

	return claims, nil
}

// uses server's managed identity to get Graph API token
// and check group memberships for the given client OID
func RetrieveAADGroupMembershipsViaIMDS(userOID string) ([]string, error) {
	groupNames := []string{}

	// get Graph API token from IMDS using server's managed identity
	graphToken, err := getGraphTokenFromIMDS()
	if err != nil {
		return groupNames, fmt.Errorf("failed to get Graph API token: %v", err)
	}

	// Create request to get service principal's group memberships
	graphURL := "https://graph.microsoft.com/v1.0/servicePrincipals/" + userOID + "/memberOf"
	req, err := http.NewRequest("GET", graphURL, nil)
	if err != nil {
		return groupNames, err
	}
	req.Header.Add("Authorization", "Bearer "+graphToken)

	log.Printf("Graph API URL: %s", graphURL)
	log.Printf("Service Principal OID being queried: %s", userOID)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return groupNames, err
	}
	defer resp.Body.Close()

	log.Printf("Graph API Response Status: %d", resp.StatusCode)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return groupNames, err
	}

	log.Printf("Graph API Response Body: %s", string(body))

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

func getGraphTokenFromIMDS() (string, error) {
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

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}

	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", err
	}

	return tokenResponse.AccessToken, nil
}

// gets the display name of a managed identity using its OID
func getManagedIdentityDisplayName(oid string) (string, error) {
	graphToken, err := getGraphTokenFromIMDS()
	if err != nil {
		return "", fmt.Errorf("failed to get Graph API token: %v", err)
	}

	graphURL := "https://graph.microsoft.com/v1.0/servicePrincipals/" + oid
	req, err := http.NewRequest("GET", graphURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Authorization", "Bearer "+graphToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Graph API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var response ServicePrincipalResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to parse service principal response: %v", err)
	}

	return response.DisplayName, nil
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
