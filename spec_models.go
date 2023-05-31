package linefido2

// ClientDataJSON is a value type for the JSON-serialized client data.
type ClientDataJSON string

// AttestationObject is a value type for an attestation object.
type AttestationObject string

// AuthenticatorAttestationResponse represents the authenticator's response to a client’s request for the creation of
// a new public key credential.
// https://www.w3.org/TR/webauthn-1/#iface-authenticatorattestationresponse
type AuthenticatorAttestationResponse struct {
	ClientDataJSON    ClientDataJSON           `json:"clientDataJSON"`
	AttestationObject AttestationObject        `json:"attestationObject"`
	Transports        []AuthenticatorTransport `json:"transports"`
}

// AuthenticatorData is a value type for the authenticator data returned by the authenticator.
type AuthenticatorData string

// AuthenticatorAssertionResponse represents an authenticator's response to a client’s request for generation of
// a new authentication assertion given the WebAuthn Relying Party's challenge and OPTIONAL list of credentials it is aware of.
// https://www.w3.org/TR/webauthn-1/#iface-authenticatorassertionresponse
type AuthenticatorAssertionResponse struct {
	ClientDataJSON    ClientDataJSON    `json:"clientDataJSON"`
	AuthenticatorData AuthenticatorData `json:"authenticatorData"`
	Signature         string            `json:"signature"`
	UserHandle        string            `json:"userHandle"`
}

// PublicKeyCredentialParameters is used to supply additional parameters when creating a new credential.
// https://www.w3.org/TR/webauthn-1/#credential-params
type PublicKeyCredentialParameters struct {
	Type      PublicKeyCredentialType `json:"type"`
	Algorithm COSEAlgorithmIdentifier `json:"alg"`
}

// RegistrationOptions represents the response that the Relying Party returns to the user in order for
// the user's authenticator to create credentials.
// https://www.w3.org/TR/webauthn-1/#dictionary-makecredentialoptions
type RegistrationOptions struct {
	Rp                     *PublicKeyCredentialRpEntity          `json:"rp,omitempty"`
	User                   *PublicKeyCredentialUserEntity        `json:"user,omitempty"`
	Challenge              string                                `json:"challenge,omitempty"`
	PubKeyCredParams       []PublicKeyCredentialParameters       `json:"pubKeyCredParams,omitempty"`
	Timeout                uint64                                `json:"timeout,omitempty"`
	ExcludeCredentials     []PublicKeyCredentialDescriptor       `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection *AuthenticatorSelectionCriteria       `json:"authenticatorSelection,omitempty"`
	Attestation            AttestationConveyancePreference       `json:"attestation,omitempty"`
	SessionId              string                                `json:"sessionId,omitempty"`
	Extensions             *AuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
}

// PublicKeyCredentialRpEntity is used to supply additional Relying Party attributes when creating a new credential.
// https://www.w3.org/TR/webauthn-1/#sctn-rp-credential-params
type PublicKeyCredentialRpEntity struct {
	Id   string `json:"id"`
	Name string `json:"name"`
	Icon string `json:"icon"`
}

// PublicKeyCredentialUserEntity is used to supply additional user account attributes when creating a new credential.
// https://www.w3.org/TR/webauthn-1/#sctn-user-credential-params
type PublicKeyCredentialUserEntity struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Icon        string `json:"icon"`
}

// AuthenticatorSelectionCriteria is used to specify their requirements regarding authenticator attributes.
// https://www.w3.org/TR/webauthn-1/#authenticatorSelection
type AuthenticatorSelectionCriteria struct {
	AuthenticatorAttachment AuthenticatorAttachment     `json:"authenticatorAttachment,omitempty"`
	RequireResidentKey      bool                        `json:"requireResidentKey"`
	UserVerification        UserVerificationRequirement `json:"userVerification,omitempty"`
}

// AuthenticatorAttachment is a value to describe authenticators' attachment modalities.
// https://www.w3.org/TR/webauthn-1/#attachment
type AuthenticatorAttachment string

const (
	// AuthenticatorAttachmentPlatform indicates platform attachment.
	// Platform attachment is a platform authenticator is attached using a client device-specific transport,
	// and is usually not removable from the client device.
	AuthenticatorAttachmentPlatform = AuthenticatorAttachment("platform")
	// AuthenticatorAttachmentCrossPlatform indicates cross-platform attachment.
	// Cross-platform attachment is a roaming authenticator is attached using cross-platform transports,
	// and can "roam" among, client devices.
	AuthenticatorAttachmentCrossPlatform = AuthenticatorAttachment("cross-platform")
)

// AttestationConveyancePreference is a value type to specify their preference regarding attestation conveyance during credential generation.
// https://www.w3.org/TR/webauthn-1/#attestation-convey
type AttestationConveyancePreference string

const (
	// AttestationConveyancePreferenceNone indicates that the Relying Party is not interested in authenticator attestation.
	AttestationConveyancePreferenceNone = AttestationConveyancePreference("none")
	// AttestationConveyancePreferenceIndirect indicates that the Relying Party prefers an attestation conveyance yielding verifiable attestation statements,
	// but allows the client to decide how to obtain such attestation statements.
	AttestationConveyancePreferenceIndirect = AttestationConveyancePreference("indirect")
	// AttestationConveyancePreferenceDirect indicates that the Relying Party wants to receive the attestation statement as generated by the authenticator.
	AttestationConveyancePreferenceDirect = AttestationConveyancePreference("direct")
)

// AuthenticationOptions supplies get() with the data it needs to generate an assertion.
// https://www.w3.org/TR/webauthn-1/#assertion-options
type AuthenticationOptions struct {
	Challenge        string                                `json:"challenge"`
	Timeout          uint64                                `json:"timeout"`
	RpId             string                                `json:"rpId"`
	AllowCredentials []PublicKeyCredentialDescriptor       `json:"allowCredentials"`
	UserVerification UserVerificationRequirement           `json:"userVerification"`
	SessionId        string                                `json:"sessionId"`
	Extensions       *AuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
}

// AuthenticationExtensionsClientInputs containing the client extension input values for zero or more WebAuthn extensions.
// https://www.w3.org/TR/webauthn-1/#iface-authentication-extensions-client-inputs
type AuthenticationExtensionsClientInputs struct {
	AppId                             string                            `json:"appid,omitempty"`
	TxAuthSimple                      string                            `json:"txAuthSimple,omitempty"`
	TxAuthGeneric                     *TxAuthGenericArg                 `json:"txAuthGeneric,omitempty"`
	AuthnSel                          []string                          `json:"authnSel,omitempty"`
	LineAuthnSel                      []string                          `json:"line_authnSel,omitempty"`
	Exts                              *bool                             `json:"exts,omitempty"`
	Uvi                               *bool                             `json:"uvi,omitempty"`
	Loc                               *bool                             `json:"loc,omitempty"`
	BiometricPerfBounds               *AuthenticatorBiometricPerfBounds `json:"biometricPerfBounds,omitempty"`
	CredProps                         *bool                             `json:"credProps,omitempty"`
	CredentialProtectionPolicy        *CredentialProtectionPolicy       `json:"credentialProtectionPolicy,omitempty"`
	EnforceCredentialProtectionPolicy *bool                             `json:"enforceCredentialProtectionPolicy,omitempty"`
}

// AuthenticationExtensionsClientOutputs containing the client extension output values for zero or more WebAuthn extensions.
// https://www.w3.org/TR/webauthn-1/#iface-authentication-extensions-client-outputs
type AuthenticationExtensionsClientOutputs struct {
	AppId               *bool                       `json:"appid,omitempty"`
	TxAuthSimple        string                      `json:"txAuthSimple,omitempty"`
	TxAuthGeneric       string                      `json:"txAuthGeneric,omitempty"`
	AuthnSel            *bool                       `json:"authnSel,omitempty"`
	Exts                []string                    `json:"exts,omitempty"`
	Uvi                 string                      `json:"uvi,omitempty"`
	Loc                 *Coordinates                `json:"loc,omitempty"`
	BiometricPerfBounds *bool                       `json:"biometricPerfBounds,omitempty"`
	CredProps           *CredentialPropertiesOutput `json:"credProps,omitempty"`
}

// TokenBinding contains information about the state of the Token Binding protocol used when
// communicating with the Relying Party.
type TokenBinding struct {
	Status TokenBindingStatus `json:"status"`
	Id     string             `json:"id"`
}

// TokenBindingStatus is a value type to represents whether the client supports token binding.
type TokenBindingStatus string

const (
	// TokenBindingStatusPresent indicates token binding was used when communicating with the Relying Party.
	TokenBindingStatusPresent = TokenBindingStatus("present")
	// TokenBindingStatusSupported indicates the client supports token binding,
	// but it was not negotiated when communicating with the Relying Party.
	TokenBindingStatusSupported = TokenBindingStatus("supported")
	// TokenBindingStatusNotSupported indicates the client does not support token binding.
	TokenBindingStatusNotSupported = TokenBindingStatus("not-supported")
)

// PublicKeyCredentialType is a value type to define the valid credential types that are used for
// versioning the Authentication Assertion and attestation structures according to the type of the authenticator.
// https://www.w3.org/TR/webauthn-1/#credentialType
type PublicKeyCredentialType string

const (
	// PublicKeyCredentialTypePublicKey indicates the use of a public key as the credential type.
	// This is the only valid credential type currently defined.
	PublicKeyCredentialTypePublicKey = PublicKeyCredentialType("public-key")
)

// PublicKeyCredentialDescriptor contains the attributes that are specified by a caller
// when referring to a public key credential as an input parameter to the create() or get() methods.
// https://www.w3.org/TR/webauthn-1/#credential-dictionary
type PublicKeyCredentialDescriptor struct {
	Type       PublicKeyCredentialType  `json:"type"`
	Id         string                   `json:"id"`
	Transports []AuthenticatorTransport `json:"transports,omitempty"`
}

// AuthenticatorTransport is a value type for defines hints as to how clients might communicate with a particular authenticator
// in order to obtain an assertion for a specific credential.
// https://www.w3.org/TR/webauthn-1/#transport
type AuthenticatorTransport string

const (
	// AuthenticatorTransportUSB indicates the respective authenticator can be contacted over removable USB.
	AuthenticatorTransportUSB = AuthenticatorTransport("usb")
	// AuthenticatorTransportNFC indicates the respective authenticator can be contacted over Near Field Communication (NFC).
	AuthenticatorTransportNFC = AuthenticatorTransport("nfc")
	// AuthenticatorTransportBLE indicates the respective authenticator can be contacted over Bluetooth Smart (Bluetooth Low Energy / BLE).
	AuthenticatorTransportBLE = AuthenticatorTransport("ble")
	// AuthenticatorTransportInternal indicates the respective authenticator is contacted using a client device-specific transport.
	AuthenticatorTransportInternal = AuthenticatorTransport("internal")
)

// COSEAlgorithmIdentifier is a value type for identifying a cryptographic algorithm.
// The values are registered in the IANA  COSE Algorithms registry.
// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
// https://www.w3.org/TR/webauthn-1/#alg-identifier
type COSEAlgorithmIdentifier int64

const (
	// COSEAlgorithmIdentifierES256 indicates the algorithm is "ES256" (ECDSA w/ SHA-256).
	COSEAlgorithmIdentifierES256 = COSEAlgorithmIdentifier(-7)
	// COSEAlgorithmIdentifierEdDSA indicates the algorithm is "EdDSA".
	COSEAlgorithmIdentifierEdDSA = COSEAlgorithmIdentifier(-8)
	// COSEAlgorithmIdentifierES384 indicates the algorithm is "ES384" (ECDSA w/ SHA-384).
	COSEAlgorithmIdentifierES384 = COSEAlgorithmIdentifier(-35)
	// COSEAlgorithmIdentifierES512 indicates the algorithm is "ES512" (ECDSA w/ SHA-512).
	COSEAlgorithmIdentifierES512 = COSEAlgorithmIdentifier(-36)
	// COSEAlgorithmIdentifierPS256 indicates the algorithm is "PS256" (RSASSA-PSS w/ SHA-256).
	COSEAlgorithmIdentifierPS256 = COSEAlgorithmIdentifier(-37)
	// COSEAlgorithmIdentifierPS384 indicates the algorithm is "PS384" (RSASSA-PSS w/ SHA-384).
	COSEAlgorithmIdentifierPS384 = COSEAlgorithmIdentifier(-38)
	// COSEAlgorithmIdentifierPS512 indicates the algorithm is "PS512" (RSASSA-PSS w/ SHA-512).
	COSEAlgorithmIdentifierPS512 = COSEAlgorithmIdentifier(-39)
	// COSEAlgorithmIdentifierES256K indicates the algorithm is "ES256K" (ECDSA using secp256k1 curve and SHA-256).
	COSEAlgorithmIdentifierES256K = COSEAlgorithmIdentifier(-47)
	// COSEAlgorithmIdentifierRS256 indicates the algorithm is "RS256" (RSASSA-PKCS1-v1_5 using SHA-256).
	COSEAlgorithmIdentifierRS256 = COSEAlgorithmIdentifier(-257)
	// COSEAlgorithmIdentifierRS384 indicates the algorithm is "RS384" (RSASSA-PKCS1-v1_5 using SHA-384).
	COSEAlgorithmIdentifierRS384 = COSEAlgorithmIdentifier(-258)
	// COSEAlgorithmIdentifierRS512 indicates the algorithm is "RS512" (RSASSA-PKCS1-v1_5 using SHA-512).
	COSEAlgorithmIdentifierRS512 = COSEAlgorithmIdentifier(-259)
	// COSEAlgorithmIdentifierRS1 indicates the algorithm is "RS1" (RSASSA-PKCS1-v1_5 using SHA-1).
	COSEAlgorithmIdentifierRS1 = COSEAlgorithmIdentifier(-65535)
)

// UserVerificationRequirement is a value to describe the Relying Party's requirements regarding user verification.
// https://www.w3.org/TR/webauthn-1/#userVerificationRequirement
type UserVerificationRequirement string

const (
	// UserVerificationRequirementRequired indicates that the Relying Party requires user verification for the operation
	// and will fail the operation if the response does not have the UV flag set.
	UserVerificationRequirementRequired = UserVerificationRequirement("required")
	// UserVerificationRequirementPreferred indicates that the Relying Party prefers user verification for the operation if possible,
	// but will not fail the operation if the response does not have the UV flag set.
	UserVerificationRequirementPreferred = UserVerificationRequirement("preferred")
	// UserVerificationRequirementDiscouraged indicates that the Relying Party does not want user verification employed during the operation.
	UserVerificationRequirementDiscouraged = UserVerificationRequirement("discouraged")
)

// TxAuthGenericArg contains information for using the image as a prompt for transaction authentication.
// https://www.w3.org/TR/webauthn-1/#sctn-generic-txauth-extension
type TxAuthGenericArg struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

// AuthenticatorBiometricPerfBounds represents Biometric performance bounds.
// https://www.w3.org/TR/webauthn-1/#sctn-authenticator-biometric-criteria-extension
type AuthenticatorBiometricPerfBounds struct {
	FAR float32 `json:"FAR"`
	FRR float32 `json:"FRR"`
}

// Coordinates represents geolocation information.
// https://www.w3.org/TR/geolocation/#coordinates_interface
type Coordinates struct {
	Accuracy         float64  `json:"accuracy"`
	Latitude         float64  `json:"latitude"`
	Longitude        float64  `json:"longitude"`
	Altitude         *float64 `json:"altitude"`
	AltitudeAccuracy *float64 `json:"altitudeAccuracy"`
	Heading          *float64 `json:"heading"`
	Speed            *float64 `json:"speed"`
}

// CredProtect contains enhanced protection mode for the credentials created on the authenticator.
// https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#sctn-credProtect-extension
type CredProtect struct {
	CredentialProtectionPolicy        CredentialProtectionPolicy `json:"credentialProtectionPolicy,omitempty"`
	EnforceCredentialProtectionPolicy *bool                      `json:"enforceCredentialProtectionPolicy,omitempty"`
}

// CredentialProtectionPolicy is a value type to describe the policy for credential protection.
type CredentialProtectionPolicy string

const (
	// CredentialProtectionPolicyUserVerificationOptional indicates user verification is optional with or without credentialID list.
	CredentialProtectionPolicyUserVerificationOptional = CredentialProtectionPolicy("userVerificationOptional")
	// CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList indicates credential is discovered only when its credentialID is provided by the platform or when user verification is performed.
	CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList = CredentialProtectionPolicy("userVerificationOptionalWithCredentialIDList")
	// CredentialProtectionPolicyUserVerificationRequired indicates that discovery and usage of the credential MUST be preceeded by user verification.
	CredentialProtectionPolicyUserVerificationRequired = CredentialProtectionPolicy("userVerificationRequired")
)

// CredentialPropertiesOutput contains properties for credential.
// https://www.w3.org/TR/webauthn-2/#dictdef-credentialpropertiesoutput
type CredentialPropertiesOutput struct {
	Rk *bool `json:"rk"`
}
