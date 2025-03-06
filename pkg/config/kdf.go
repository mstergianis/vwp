package config

type KdfType int

const (
	PBKDF2_SHA256 = 0
	// currently unsupported
	Argon2id = 1
)

type KdfConfig struct {
	Kdf            int32  `json:"kdf"`
	KdfIterations  int32  `json:"kdfIterations"`
	KdfMemory      *int32 `json:"kdfMemory"`
	KdfParallelism *int32 `json:"kdfParallelism"`
}
