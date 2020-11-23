package password

import "golang.org/x/crypto/bcrypt"

const (
	LowBCryptCost     BCryptCost = 4
	DefaultBcryptCost BCryptCost = 10
	HighBCryptCost    BCryptCost = 15
	Extreme           BCryptCost = 25
)

type bcryptService struct {
	cost int
}

func NewBcryptHasher(cost BCryptCost) Interface {
	if cost < 4 || cost > 32 {
		panic("cost must be greater than 4 and less than 32")
	}
	return bcryptService{cost: int(cost)}
}

func (b bcryptService) Verify(passwordHash, password []byte) error {
	return bcrypt.CompareHashAndPassword(passwordHash, password)
}

func (b bcryptService) Hash(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), b.cost)
}
