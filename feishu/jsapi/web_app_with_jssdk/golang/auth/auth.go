package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// Constants for API URIs
const (
	TenantAccessTokenURI = "/open-apis/auth/v3/tenant_access_token/internal"
	JSAPITicketURI       = "/open-apis/jssdk/ticket/get"
)

// Auth struct to hold authentication details
type Auth struct {
	FeishuHost        string
	AppID             string
	AppSecret         string
	TenantAccessToken string
}

// NewAuth initializes a new Auth instance
func NewAuth(feishuHost, appID, appSecret string) *Auth {
	return &Auth{
		FeishuHost: feishuHost,
		AppID:      appID,
		AppSecret:  appSecret,
	}
}

// GetTicket retrieves the JSAPI ticket
func (a *Auth) GetTicket() (string, error) {
	err := a.authorizeTenantAccessToken()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s%s", a.FeishuHost, JSAPITicketURI)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+a.TenantAccessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if err := checkErrorResponse(resp); err != nil {
		return "", err
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	ticket, ok := result["data"].(map[string]interface{})["ticket"].(string)
	if !ok {
		return "", fmt.Errorf("ticket not found in response")
	}

	return ticket, nil
}

// authorizeTenantAccessToken retrieves the tenant access token
func (a *Auth) authorizeTenantAccessToken() error {
	url := fmt.Sprintf("%s%s", a.FeishuHost, TenantAccessTokenURI)
	reqBody := map[string]string{
		"app_id":     a.AppID,
		"app_secret": a.AppSecret,
	}
	jsonReqBody, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonReqBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := checkErrorResponse(resp); err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	tenantAccessToken, ok := result["tenant_access_token"].(string)
	if !ok {
		return fmt.Errorf("tenant_access_token not found in response")
	}

	a.TenantAccessToken = tenantAccessToken
	return nil
}

// checkErrorResponse checks for error responses
func checkErrorResponse(resp *http.Response) error {
	if resp.StatusCode != http.StatusOK {
		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return err
		}
		return fmt.Errorf("error response: %v", result)
	}
	return nil
}
