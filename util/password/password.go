package password

type (
	BCryptCost uint8
	Interface  interface {
		// Verify compares password and the hashed password
		Verify(passwordHash, password []byte) error

		// Hash creates a password hash
		Hash(password string) ([]byte, error)
	}
)
