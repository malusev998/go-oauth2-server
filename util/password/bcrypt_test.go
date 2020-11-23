package password_test

import (
	"github.com/RichardKnop/go-oauth2-server/util/password"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewBcryptHasher(t *testing.T) {
	t.Parallel()
	assert := require.New(t)

	t.Run("Success", func(t *testing.T) {
		service := password.NewBcryptHasher(password.LowBCryptCost)
		assert.NotNil(service)
	})

	t.Run("TooLowCost", func(t *testing.T) {
		assert.Panics(func() {
			_ = password.NewBcryptHasher(password.BCryptCost(1))
		})
	})
	t.Run("CostTooHigh", func(t *testing.T) {
		assert.Panics(func() {
			_ = password.NewBcryptHasher(password.BCryptCost(35))
		})
	})
}

func TestBCryptPasswordHashing(t *testing.T) {
	t.Parallel()
	assert := require.New(t)
	service := password.NewBcryptHasher(password.LowBCryptCost)

	hash, err := service.Hash("password")
	assert.Nil(err)
	assert.Regexp("^\\$2a\\$\\d{2}\\$", string(hash))
	assert.Len(hash, 60)
}

func TestBCryptSuccessfulPasswordVerification(t *testing.T) {
	t.Parallel()
	assert := require.New(t)
	service := password.NewBcryptHasher(password.LowBCryptCost)
	assert.Nil(service.Verify(
		[]byte("$2a$10$CUoGytf1pR7CC6Y043gt/.vFJUV4IRqvH5R6F0VfITP8s2TqrQ.4e"),
		[]byte("test_secret"),
	))

	assert.Nil(service.Verify(
		[]byte("$2a$10$4J4t9xuWhOKhfjN0bOKNReS9sL3BVSN9zxIr2.VaWWQfRBWh1dQIS"),
		[]byte("test_password"),
	))
}

func TestBcryptInvalidPassword(t *testing.T) {
	t.Parallel()
	assert := require.New(t)
	service := password.NewBcryptHasher(password.LowBCryptCost)

	assert.NotNil(service.Verify([]byte("bogus"), []byte("password")))
}
