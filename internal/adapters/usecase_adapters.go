package adapters

import "github.com/hurtki/jwt/internal/wrappers"

type UseCaseAdapter struct {
	PayloadType wrappers.PayloadType
	HookWrapper wrappers.HookWrapper
}
