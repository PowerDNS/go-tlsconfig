package tlsconfig

// Secret is a string that has "***" as its default string representation.
type Secret string

func (s *Secret) MarshalText() (text []byte, err error) {
	return []byte(*s), nil
}

func (s *Secret) UnmarshalText(text []byte) error {
	*s = Secret(text)
	return nil
}

func (s *Secret) String() string {
	return "***"
}
