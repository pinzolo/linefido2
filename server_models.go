package linefido2

import "fmt"

// ServerError contains error information raised by the FIDO2 server.
type ServerError struct {
	ServerResponse *ServerResponse
}

// Error returns error message for ServerError.
func (err ServerError) Error() string {
	return fmt.Sprintf("fido2 server error: %s (%d)",
		err.ServerResponse.InternalError,
		err.ServerResponse.InternalErrorCode)
}

// ServerResponse represents the result of processing by the FIDO2 server.
type ServerResponse struct {
	Description                  string `json:"description"`
	InternalError                string `json:"internalError"`
	InternalErrorCode            int    `json:"internalErrorCode"`
	InternalErrorCodeDescription string `json:"internalErrorCodeDescription"`
}

func (res *ServerResponse) hasError() bool {
	return res.InternalErrorCode != 0
}

// RegistrationOptionsRequest represents a request to call Get Reg Challenge API.
type RegistrationOptionsRequest struct {
	Rp                     *PublicKeyCredentialRpEntity    `json:"rp"`
	User                   *PublicKeyCredentialUserEntity  `json:"user"`
	AuthenticatorSelection *AuthenticatorSelectionCriteria `json:"authenticatorSelection"`
	Attestation            AttestationConveyancePreference `json:"attestation"`
	CredProtect            *CredProtect                    `json:"credProtect"`
}

// RegistrationOptionsResponse represents the response of Get Reg Challenge API.
type RegistrationOptionsResponse struct {
	ServerResponse         *ServerResponse                       `json:"serverResponse,omitempty"`
	Rp                     *PublicKeyCredentialRpEntity          `json:"rp,omitempty"`
	User                   *PublicKeyCredentialUserEntity        `json:"user,omitempty"`
	Challenge              string                                `json:"challenge,omitempty"`
	PubKeyCredParams       []PublicKeyCredentialParameters       `json:"pubKeyCredParams,omitempty"`
	Timeout                uint64                                `json:"timeout,omitempty"`
	ExcludeCredentials     []PublicKeyCredentialDescriptor       `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection *AuthenticatorSelectionCriteria       `json:"authenticatorSelection,omitempty"`
	Attestation            *AttestationConveyancePreference      `json:"attestation,omitempty"`
	SessionId              string                                `json:"sessionId,omitempty"`
	Extensions             *AuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
}

func (res *RegistrationOptionsResponse) hasError() bool {
	return res.ServerResponse.hasError()
}

func (res *RegistrationOptionsResponse) publish() (*RegistrationOptions, error) {
	if res.hasError() {
		return nil, ServerError{ServerResponse: res.ServerResponse}
	}

	return &RegistrationOptions{
		Rp:                     res.Rp,
		User:                   res.User,
		Challenge:              res.Challenge,
		PubKeyCredParams:       res.PubKeyCredParams,
		Timeout:                res.Timeout,
		ExcludeCredentials:     res.ExcludeCredentials,
		AuthenticatorSelection: res.AuthenticatorSelection,
		Attestation:            res.Attestation,
		SessionId:              res.SessionId,
		Extensions:             res.Extensions,
	}, nil
}

// AuthenticationOptionsRequest represents a request to call Get Auth Challenge API.
type AuthenticationOptionsRequest struct {
	RpId             string                      `json:"rpId"`
	UserId           string                      `json:"userId"`
	UserVerification UserVerificationRequirement `json:"userVerification"`
}

// AuthenticationOptionsResponse represents the response of Get Auth Challenge API.
type AuthenticationOptionsResponse struct {
	ServerResponse   *ServerResponse                       `json:"serverResponse,omitempty"`
	Challenge        string                                `json:"challenge"`
	Timeout          uint64                                `json:"timeout"`
	RpId             string                                `json:"rpId"`
	AllowCredentials []PublicKeyCredentialDescriptor       `json:"allowCredentials"`
	UserVerification UserVerificationRequirement           `json:"userVerification"`
	SessionId        string                                `json:"sessionId"`
	Extensions       *AuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
}

func (res *AuthenticationOptionsResponse) hasError() bool {
	return res.ServerResponse.hasError()
}

func (res *AuthenticationOptionsResponse) publish() (*AuthenticationOptions, error) {
	if res.hasError() {
		return nil, ServerError{ServerResponse: res.ServerResponse}
	}

	return &AuthenticationOptions{
		Challenge:        res.Challenge,
		Timeout:          res.Timeout,
		RpId:             res.RpId,
		AllowCredentials: res.AllowCredentials,
		UserVerification: res.UserVerification,
		SessionId:        res.SessionId,
		Extensions:       res.Extensions,
	}, nil
}

// RegisterCredentialRequest represents a request to call Send Reg Response API.
type RegisterCredentialRequest struct {
	PublicKeyCredential *RegistrationPublicKeyCredential `json:"serverPublicKeyCredential"`
	SessionId           string                           `json:"sessionId"`
	Origin              string                           `json:"origin"`
	RpId                string                           `json:"rpId"`
	TokenBinding        *TokenBinding                    `json:"tokenBinding"`
}

type RegistrationPublicKeyCredential struct {
	Id         string                                 `json:"id"`
	Type       PublicKeyCredentialType                `json:"type"`
	Response   *AuthenticatorAttestationResponse      `json:"response"`
	Extensions *AuthenticationExtensionsClientOutputs `json:"extensions"`
}

// RegisterCredentialResultResponse represents the response of Send Reg Response API.
type RegisterCredentialResultResponse struct {
	ServerResponse          *ServerResponse          `json:"serverResponse,omitempty"`
	Aaguid                  string                   `json:"aaguid,omitempty"`
	CredentialId            string                   `json:"credentialId,omitempty"`
	AuthenticatorAttachment AuthenticatorAttachment  `json:"authenticatorAttachment,omitempty"`
	AttestationType         AttestationType          `json:"attestationType,omitempty"`
	AuthenticatorTransports []AuthenticatorTransport `json:"authenticatorTransport,omitempty"`
	UserVerified            bool                     `json:"userVerified,omitempty"`
	Rk                      bool                     `json:"rk,omitempty"`
	CredProtect             int                      `json:"credProtect,omitempty"`
}

func (res *RegisterCredentialResultResponse) hasError() bool {
	return res.ServerResponse.hasError()
}

func (res *RegisterCredentialResultResponse) publish() (*RegisterCredentialResult, error) {
	if res.hasError() {
		return nil, ServerError{ServerResponse: res.ServerResponse}
	}

	return &RegisterCredentialResult{
		Aaguid:                  res.Aaguid,
		CredentialId:            res.CredentialId,
		AuthenticatorAttachment: res.AuthenticatorAttachment,
		AttestationType:         res.AttestationType,
		AuthenticatorTransports: res.AuthenticatorTransports,
		UserVerified:            res.UserVerified,
		Rk:                      res.Rk,
		CredProtect:             res.CredProtect,
	}, nil
}

type RegisterCredentialResult struct {
	Aaguid                  string                   `json:"aaguid,omitempty"`
	CredentialId            string                   `json:"credentialId,omitempty"`
	AuthenticatorAttachment AuthenticatorAttachment  `json:"authenticatorAttachment,omitempty"`
	AttestationType         AttestationType          `json:"attestationType,omitempty"`
	AuthenticatorTransports []AuthenticatorTransport `json:"authenticatorTransport,omitempty"`
	UserVerified            bool                     `json:"userVerified,omitempty"`
	Rk                      bool                     `json:"rk,omitempty"`
	CredProtect             int                      `json:"credProtect,omitempty"`
}

type AttestationType string

const (
	AttestationTypeBasic         = AttestationType("BASIC")
	AttestationTypeSelf          = AttestationType("SELF")
	AttestationTypeAttestationCa = AttestationType("ATTESTATION_CA")
	AttestationTypeAnonCa        = AttestationType("ANON_CA")
	AttestationTypeNone          = AttestationType("NONE")
)

// VerifyCredentialRequest represents a request to call Send Auth Response API.
type VerifyCredentialRequest struct {
	PublicKeyCredential *AuthenticationPublicKeyCredential `json:"serverPublicKeyCredential"`
	SessionId           string                             `json:"sessionId"`
	Origin              string                             `json:"origin"`
	RpId                string                             `json:"rpId"`
	TokenBinding        *TokenBinding                      `json:"tokenBinding"`
}

type AuthenticationPublicKeyCredential struct {
	Id         string                                 `json:"id"`
	Type       PublicKeyCredentialType                `json:"type"`
	Response   *AuthenticatorAssertionResponse        `json:"response"`
	Extensions *AuthenticationExtensionsClientOutputs `json:"extensions"`
}

// VerifyCredentialResultResponse represents the response of Send Auth Response API.
type VerifyCredentialResultResponse struct {
	ServerResponse *ServerResponse `json:"serverResponse,omitempty"`
	Aaguid         string          `json:"aaguid;"`
	UserId         string          `json:"userId"`
	UserVerified   bool            `json:"userVerified"`
	UserPresent    bool            `json:"userPresent"`
}

func (res *VerifyCredentialResultResponse) hasError() bool {
	return res.ServerResponse.hasError()
}

func (res *VerifyCredentialResultResponse) publish() (*VerifyCredentialResult, error) {
	if res.hasError() {
		return nil, ServerError{ServerResponse: res.ServerResponse}
	}

	return &VerifyCredentialResult{
		Aaguid:       res.Aaguid,
		UserId:       res.UserId,
		UserVerified: res.UserVerified,
		UserPresent:  res.UserPresent,
	}, nil
}

type VerifyCredentialResult struct {
	Aaguid       string `json:"aaguid;"`
	UserId       string `json:"userId"`
	UserVerified bool   `json:"userVerified"`
	UserPresent  bool   `json:"userPresent"`
}
