package linefido2_test

import (
	"context"
	"fmt"
	"github.com/pinzolo/linefido2"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"
)

func boolPointer(b bool) *bool {
	return &b
}

func intPointer(i int32) *int32 {
	return &i
}

var (
	truePtr         = boolPointer(true)
	defaultLocation = time.FixedZone("", 0)
)

func TestClient_GetRegistrationOptions(t *testing.T) {
	tests := []struct {
		name      string
		resStatus int
		resFile   string
		want      *linefido2.RegistrationOptions
		wantErr   bool
	}{
		{
			name:      "success",
			resStatus: http.StatusOK,
			resFile:   "get_reg_challenge.json",
			want: &linefido2.RegistrationOptions{
				Rp: &linefido2.PublicKeyCredentialRpEntity{
					Name: "example1",
					Id:   "localhost",
				},
				User: &linefido2.PublicKeyCredentialUserEntity{
					Name:        "TestUser",
					Id:          "65fUCTlqPlOSk22tkrkJ2m8I2MEhpF4fCI_pdosMAzk",
					DisplayName: "Test Display Name",
				},
				Challenge: "TXgZfiz2B88oNbksOpC4GjNQ8YNaFzntXMBTMdN3K1XgIgKRr3FoXltAhV1zNmmdF4WJhxnoQDeq4s0bARhtRg",
				PubKeyCredParams: []linefido2.PublicKeyCredentialParameters{
					{
						Type:      linefido2.PublicKeyCredentialTypePublicKey,
						Algorithm: linefido2.COSEAlgorithmIdentifierRS1,
					},
					{
						Type:      linefido2.PublicKeyCredentialTypePublicKey,
						Algorithm: linefido2.COSEAlgorithmIdentifierRS256,
					},
					{
						Type:      linefido2.PublicKeyCredentialTypePublicKey,
						Algorithm: linefido2.COSEAlgorithmIdentifierRS384,
					},
					{
						Type:      linefido2.PublicKeyCredentialTypePublicKey,
						Algorithm: linefido2.COSEAlgorithmIdentifierRS512,
					},
					{
						Type:      linefido2.PublicKeyCredentialTypePublicKey,
						Algorithm: linefido2.COSEAlgorithmIdentifierPS256,
					},
					{
						Type:      linefido2.PublicKeyCredentialTypePublicKey,
						Algorithm: linefido2.COSEAlgorithmIdentifierPS384,
					},
					{
						Type:      linefido2.PublicKeyCredentialTypePublicKey,
						Algorithm: linefido2.COSEAlgorithmIdentifierPS512,
					},
					{
						Type:      linefido2.PublicKeyCredentialTypePublicKey,
						Algorithm: linefido2.COSEAlgorithmIdentifierES256,
					},
					{
						Type:      linefido2.PublicKeyCredentialTypePublicKey,
						Algorithm: linefido2.COSEAlgorithmIdentifierES384,
					},
					{
						Type:      linefido2.PublicKeyCredentialTypePublicKey,
						Algorithm: linefido2.COSEAlgorithmIdentifierES512,
					},
					{
						Type:      linefido2.PublicKeyCredentialTypePublicKey,
						Algorithm: linefido2.COSEAlgorithmIdentifierEdDSA,
					},
				},
				Timeout:            180000,
				ExcludeCredentials: []linefido2.PublicKeyCredentialDescriptor{},
				AuthenticatorSelection: &linefido2.AuthenticatorSelectionCriteria{
					AuthenticatorAttachment: linefido2.AuthenticatorAttachmentPlatform,
					RequireResidentKey:      true,
					UserVerification:        linefido2.UserVerificationRequirementPreferred,
				},
				Attestation: linefido2.AttestationConveyancePreferenceNone,
				SessionId:   "8bfc693e-8582-45e1-ad08-e2b71901cc97",
				Extensions: &linefido2.AuthenticationExtensionsClientInputs{
					CredProps: truePtr,
				},
			},
			wantErr: false,
		},
		{
			name:      "error",
			resStatus: http.StatusInternalServerError,
			resFile:   "error_server_response.json",
			want:      nil,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t, tt.resStatus, tt.resFile)
			defer s.Close()
			c := linefido2.NewClient(linefido2.WithBaseUrl(s.URL))
			got, err := c.GetRegistrationOptions(context.Background(), &linefido2.RegistrationOptionsRequest{})
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRegistrationOptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetRegistrationOptions() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_RegisterCredential(t *testing.T) {
	tests := []struct {
		name      string
		resStatus int
		resFile   string
		want      *linefido2.RegisterCredentialResult
		wantErr   bool
	}{
		{
			name:      "success",
			resStatus: http.StatusOK,
			resFile:   "send_reg_response.json",
			want: &linefido2.RegisterCredentialResult{
				Aaguid:          "adce0002-35bc-c60a-648b-0b25f1f05503",
				CredentialId:    "AYF-hoBThKTDPlpZs5i-xXCmPppyXuqEf8g0PpBclsJaSqnxOkC3qa3QVAdLeyBav-1cqnRhhB34YPsjQuN2DlH0AlGDNisTU6mi3TQRnOUSqodRkZKAPKnwx6s",
				AttestationType: linefido2.AttestationTypeNone,
				AuthenticatorTransports: []linefido2.AuthenticatorTransport{
					linefido2.AuthenticatorTransportInternal,
				},
				UserVerified: true,
				Rk:           true,
			},
			wantErr: false,
		},
		{
			name:      "error",
			resStatus: http.StatusInternalServerError,
			resFile:   "error_server_response.json",
			want:      nil,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t, tt.resStatus, tt.resFile)
			defer s.Close()
			c := linefido2.NewClient(linefido2.WithBaseUrl(s.URL))
			got, err := c.RegisterCredential(context.Background(), &linefido2.RegisterCredentialRequest{})
			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterCredential() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RegisterCredential() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_GetAuthenticationOptions(t *testing.T) {
	tests := []struct {
		name      string
		resStatus int
		resFile   string
		want      *linefido2.AuthenticationOptions
		wantErr   bool
	}{
		{
			name:      "success",
			resStatus: http.StatusOK,
			resFile:   "get_auth_challenge.json",
			want: &linefido2.AuthenticationOptions{
				Challenge: "7ZKNccKcYL0Rky0YqVx-_-yHDudCPScBayiw17arUfzpAfqa-A8nv-OmQbSLMHtpEE0rp0MbblIzLw-bE5x6zQ",
				Timeout:   180000,
				RpId:      "localhost",
				AllowCredentials: []linefido2.PublicKeyCredentialDescriptor{
					{
						Type: "public-key",
						Id:   "AUTjvBgL29DEg4aoRVchh4KSi9cLUmNuL4JqH4H8RTvKaBVDu88CnXGHDTkpIag5ODydvM-UP5FgqzDzzM3A_tzLSeoWc7hnkQK3g0N0jifjatDHgXX6YmMVAJc",
					},
				},
				UserVerification: linefido2.UserVerificationRequirementPreferred,
				SessionId:        "3d310653-8d7a-449e-975e-30a467dfbe9a",
				Extensions:       &linefido2.AuthenticationExtensionsClientInputs{},
			},
			wantErr: false,
		},
		{
			name:      "error",
			resStatus: http.StatusInternalServerError,
			resFile:   "error_server_response.json",
			want:      nil,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t, tt.resStatus, tt.resFile)
			defer s.Close()
			c := linefido2.NewClient(linefido2.WithBaseUrl(s.URL))
			got, err := c.GetAuthenticationOptions(context.Background(), &linefido2.AuthenticationOptionsRequest{})
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAuthenticationOptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetAuthenticationOptions() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_VerifyCredential(t *testing.T) {
	tests := []struct {
		name      string
		resStatus int
		resFile   string
		want      *linefido2.VerifyCredentialResult
		wantErr   bool
	}{
		{
			name:      "success",
			resStatus: http.StatusOK,
			resFile:   "send_auth_response.json",
			want: &linefido2.VerifyCredentialResult{
				Aaguid:       "adce0002-35bc-c60a-648b-0b25f1f05503",
				UserId:       "65fUCTlqPlOSk22tkrkJ2m8I2MEhpF4fCI_pdosMAzk",
				UserVerified: true,
				UserPresent:  true,
			},
			wantErr: false,
		},
		{
			name:      "error",
			resStatus: http.StatusInternalServerError,
			resFile:   "error_server_response.json",
			want:      nil,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t, tt.resStatus, tt.resFile)
			defer s.Close()
			c := linefido2.NewClient(linefido2.WithBaseUrl(s.URL))
			got, err := c.VerifyCredential(context.Background(), &linefido2.VerifyCredentialRequest{})
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyCredential() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VerifyCredential() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_GetCredentialById(t *testing.T) {
	tests := []struct {
		name      string
		resStatus int
		resFile   string
		want      *linefido2.UserKey
		wantErr   bool
	}{
		{
			name:      "success",
			resStatus: http.StatusOK,
			resFile:   "get_credential_by_credential_id.json",
			want: &linefido2.UserKey{
				RpId:            "localhost",
				Id:              "65fUCTlqPlOSk22tkrkJ2m8I2MEhpF4fCI_pdosMAzk",
				Name:            "TestUser",
				DisplayName:     "Test Display Name",
				Aaguid:          "adce0002-35bc-c60a-648b-0b25f1f05503",
				CredentialId:    "AUTjvBgL29DEg4aoRVchh4KSi9cLUmNuL4JqH4H8RTvKaBVDu88CnXGHDTkpIag5ODydvM-UP5FgqzDzzM3A_tzLSeoWc7hnkQK3g0N0jifjatDHgXX6YmMVAJc",
				PublicKey:       "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6A7PJ7L7xHAP3wrd1i6Th9ep8KmOi8slCeT2SjREtuFDJfoF1L42dzgww2adGGq7cjYspbjl9YvJA-sr9R2sOg",
				Algorithm:       "ES256",
				SignCounter:     1634711283,
				AttestationType: linefido2.AttestationTypeNone,
				Rk:              truePtr,
				CredProtect:     intPointer(1),
				RegisteredAt:    time.Date(2021, time.October, 20, 6, 27, 17, 0, defaultLocation),
				AuthenticatedAt: time.Date(2021, time.October, 20, 6, 28, 8, 0, defaultLocation),
			},
			wantErr: false,
		},
		{
			name:      "error",
			resStatus: http.StatusInternalServerError,
			resFile:   "error_server_response.json",
			want:      nil,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t, tt.resStatus, tt.resFile)
			defer s.Close()
			c := linefido2.NewClient(linefido2.WithBaseUrl(s.URL))
			got, err := c.GetCredentialById(context.Background(), "credential-id")
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCredentialById() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetCredentialById() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_GetCredentialsByUserId(t *testing.T) {
	tests := []struct {
		name      string
		resStatus int
		resFile   string
		want      []*linefido2.UserKey
		wantErr   bool
	}{
		{
			name:      "success",
			resStatus: http.StatusOK,
			resFile:   "get_credential_by_user_id.json",
			want: []*linefido2.UserKey{
				{
					RpId:            "localhost",
					Id:              "65fUCTlqPlOSk22tkrkJ2m8I2MEhpF4fCI_pdosMAzk",
					Name:            "TestUser",
					DisplayName:     "Test Display Name",
					Aaguid:          "adce0002-35bc-c60a-648b-0b25f1f05503",
					CredentialId:    "AUTjvBgL29DEg4aoRVchh4KSi9cLUmNuL4JqH4H8RTvKaBVDu88CnXGHDTkpIag5ODydvM-UP5FgqzDzzM3A_tzLSeoWc7hnkQK3g0N0jifjatDHgXX6YmMVAJc",
					PublicKey:       "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6A7PJ7L7xHAP3wrd1i6Th9ep8KmOi8slCeT2SjREtuFDJfoF1L42dzgww2adGGq7cjYspbjl9YvJA-sr9R2sOg",
					Algorithm:       "ES256",
					SignCounter:     1634711283,
					AttestationType: linefido2.AttestationTypeNone,
					Rk:              truePtr,
					CredProtect:     intPointer(1),
					RegisteredAt:    time.Date(2021, time.October, 20, 6, 27, 17, 0, defaultLocation),
					AuthenticatedAt: time.Date(2021, time.October, 20, 6, 28, 8, 0, defaultLocation),
				},
			},
			wantErr: false,
		},
		{
			name:      "error",
			resStatus: http.StatusInternalServerError,
			resFile:   "error_server_response.json",
			want:      nil,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t, tt.resStatus, tt.resFile)
			defer s.Close()
			c := linefido2.NewClient(linefido2.WithBaseUrl(s.URL))
			got, err := c.GetCredentialsByUserId(context.Background(), "user-id")
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCredentialsByUserId() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetCredentialsByUserId() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_DeleteCredentialById(t *testing.T) {
	tests := []struct {
		name      string
		resStatus int
		resFile   string
		wantErr   bool
	}{
		{
			name:      "success",
			resStatus: http.StatusOK,
			resFile:   "success_server_response.json",
			wantErr:   false,
		},
		{
			name:      "error",
			resStatus: http.StatusInternalServerError,
			resFile:   "error_server_response.json",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t, tt.resStatus, tt.resFile)
			defer s.Close()
			c := linefido2.NewClient(linefido2.WithBaseUrl(s.URL))
			err := c.DeleteCredentialById(context.Background(), "credential-id")
			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteCredentialById() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestClient_DeleteCredentialsByUserId(t *testing.T) {
	tests := []struct {
		name      string
		resStatus int
		resFile   string
		wantErr   bool
	}{
		{
			name:      "success",
			resStatus: http.StatusOK,
			resFile:   "success_server_response.json",
			wantErr:   false,
		},
		{
			name:      "error",
			resStatus: http.StatusInternalServerError,
			resFile:   "error_server_response.json",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t, tt.resStatus, tt.resFile)
			defer s.Close()
			c := linefido2.NewClient(linefido2.WithBaseUrl(s.URL))
			err := c.DeleteCredentialsByUserId(context.Background(), "user-id")
			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteCredentialsByUserId() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestClient_CheckHealth(t *testing.T) {
	s := newTestServer(t, http.StatusOK, "ok.txt")
	defer s.Close()
	c := linefido2.NewClient(linefido2.WithBaseUrl(s.URL))
	err := c.CheckHealth(context.Background())
	if err != nil {
		t.Error(err)
	}
}

func newTestServer(t *testing.T, status int, file string) *httptest.Server {
	bytes, err := os.ReadFile("./testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		fmt.Fprintln(w, string(bytes))
	})
	return httptest.NewServer(h)
}
