package vault

type SyncResponse struct {
	Ciphers []Cipher `json:"ciphers"`
	// Collections string  `json:"collections"`
	// Domains     string  `json:"domains"`
	// Folders     string  `json:"folders"`
	// Object      string  `json:"object"`
	// Policies    string  `json:"policies"`
	Profile Profile `json:"profile"`
	// Sends       string  `json:"sends"`
}

type Cipher struct {
	ID                  string     `json:"id"`
	OrganizationID      string     `json:"organizationId"`
	FolderID            string     `json:"folderId"`
	Edit                bool       `json:"edit"`
	ViewPassword        bool       `json:"viewPassword"`
	OrganizationUseTotp bool       `json:"organizationUseTotp"`
	Favorite            bool       `json:"favorite"`
	RevisionDate        string     `json:"revisionDate"`
	Type                CipherType `json:"type"`
	Name                string     `json:"name"`
	Notes               string     `json:"notes"`
	CollectionIDs       []*string  `json:"collectionIds"`
	CreationDate        string     `json:"creationDate"`
	DeletedDate         string     `json:"deletedDate"`
	Key                 *string    `json:"key"`
	Login               *LoginData `json:"login"`
	// SecureNote       *SecureNoteData        `json:"secureNote"`
	// Card             *CardData              `json:"card"`
	// Identity         *IdentityData          `json:"identity"`
	// SshKey           *SshKeyData            `json:"sshKey"`
	// Fields           []*FieldData           `json:"fields"`
	// Attachments      []*AttachmentData      `json:"attachments"`
	// PasswordHistory  []*PasswordHistoryData `json:"passwordHistory"`
	// Reprompt         CipherRepromptType     `json:"reprompt"`
}

type EncryptionType int

const (
	AesCbc256_B64                     EncryptionType = 0
	AesCbc128_HmacSha256_B64          EncryptionType = 1
	AesCbc256_HmacSha256_B64          EncryptionType = 2
	Rsa2048_OaepSha256_B64            EncryptionType = 3
	Rsa2048_OaepSha1_B64              EncryptionType = 4
	Rsa2048_OaepSha256_HmacSha256_B64 EncryptionType = 5
	Rsa2048_OaepSha1_HmacSha256_B64   EncryptionType = 6
)

type CipherType int

const (
	Login      CipherType = 1
	SecureNote CipherType = 2
	Card       CipherType = 3
	Identity   CipherType = 4
	SshKey     CipherType = 5
)

type LoginData struct {
	Uris                 []LoginUriData        `json:"uris"`
	Username             *string               `json:"username"`
	Password             *string               `json:"password"`
	PasswordRevisionDate string                `json:"passwordRevisionDate"`
	Totp                 string                `json:"totp"`
	AutofillOnPageLoad   bool                  `json:"autofillOnPageLoad"`
	Fido2Credentials     []Fido2CredentialData `json:"fido2Credentials"`
}

type Fido2CredentialData struct {
	CredentialID    string `json:"credentialId"`
	KeyType         string `json:"keyType"`
	KeyAlgorithm    string `json:"keyAlgorithm"`
	KeyCurve        string `json:"keyCurve"`
	KeyValue        string `json:"keyValue"`
	RpID            string `json:"rpId"`
	UserHandle      string `json:"userHandle"`
	UserName        string `json:"userName"`
	Counter         string `json:"counter"`
	RpName          string `json:"rpName"`
	UserDisplayName string `json:"userDisplayName"`
	Discoverable    string `json:"discoverable"`
	CreationDate    string `json:"creationDate"`
}

type LoginUriData struct {
	URI         string           `json:"uri"`
	URIChecksum string           `json:"uriChecksum"`
	Match       URIMatchStrategy `json:"match"`
}

type URIMatchStrategy int

const (
	Domain            URIMatchStrategy = 0
	Host              URIMatchStrategy = 1
	StartsWith        URIMatchStrategy = 2
	Exact             URIMatchStrategy = 3
	RegularExpression URIMatchStrategy = 4
	Never             URIMatchStrategy = 5
)

type Profile struct {
	Key           string         `json:"key"`
	PrivateKey    string         `json:"privateKey"`
	Organizations []Organization `json:"organizations"`
	//	[
	//		"_status",
	//			"avatarColor",
	//			"creationDate",
	//			"culture",
	//			"email",
	//			"emailVerified",
	//			"forcePasswordReset",
	//			"id",
	//			"key",
	//			"masterPasswordHint",
	//			"name",
	//			"object",
	//			"organizations",
	//			"premium",
	//			"premiumFromOrganization",
	//			"privateKey",
	//			"providerOrganizations",
	//			"providers",
	//			"securityStamp",
	//			"twoFactorEnabled",
	//			"usesKeyConnector"
	//
	// ]
}

type Organization struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Name string `json:"name"`
}
