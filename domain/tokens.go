package domain

// domain structure for login usecase
type TokenPair struct {
	Access  string
	Refresh string
}

type AccessToken string
