package pkg

type OpenIDConfiguration struct {
	Issuer                        string   `json:"issuer"`
	AuthEndpoint                  string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                 string   `json:"token_endpoint,omitempty"`
	UserInfoEndpoint              string   `json:"userinfo_endpoint,omitempty"`
	CheckSessionIframe            string   `json:"check_session_iframe,omitempty"`
	EndSessionEndpoint            string   `json:"end_session_endpoint,omitempty"`
	JWKSUri                       string   `json:"jwks_uri"`
	RegistrationEndpoint          string   `json:"registration_endpoint,omitempty"`
	ScopesSupported               []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported,omitempty"`
	ACRValuesSupported            []string `json:"acr_values_supported,omitempty"`
	SubjectTypesSupported         []string `json:"subject_types_supported"`
	UserInfoSignAlgSupported      []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserInfoEncAlgSupported       []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	IDTokenSignAlgSupported       []string `json:"id_token_signing_alg_values_supported"`
	IDTokenEncAlgSupported        []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	RequestObjectSignAlgSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`
	RequestObjectEncAlgSupported  []string `json:"request_object_encryption_alg_values_supported,omitempty"`
	TokenAuthMethodSupported      []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenAuthSignAlgSupported     []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	DisplayValuesSupported        []string `json:"display_values_supported,omitempty"`
	ClaimTypesSupported           []string `json:"claim_types_supported,omitempty"`
	ClaimsSupported               []string `json:"claims_supported,omitempty"`
	ServiceDocumentation          []string `json:"service_documentation,omitempty"`
	ClaimsLocalesSupported        []string `json:"claims_locales_supported,omitempty"`
	UiLocalesSupported            []string `json:"ui_locales_supported,omitempty"`
	ClaimsParameterSupported      []string `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported     []string `json:"request_parameter_supported,omitempty"`
	RequestUriParameterSupported  []string `json:"request_uri_parameter_supported,omitempty"`
	RequestUriRegistration        []string `json:"require_request_uri_registration,omitempty"`
	OpPolicyUri                   []string `json:"op_policy_uri,omitempty"`
	OpTosUri                      []string `json:"op_tos_uri,omitempty"`
}

type Oauth2TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    string `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type Oauth2TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorUri         string `json:"error_uri,omitempty"`
}
