package rpce

// 13.2.6.1

type AuthVerifier struct {
	Align         []byte // must be 4-byte aligned!!
	AuthType      SecurityProviders
	AuthLevel     AuthLevel
	AuthPadLength byte
	Reserved      byte
	ContextID     uint32
	AuthValue     []byte
}

func (a AuthVerifier) SizeOf() int {
	return 0
}

func (a AuthVerifier) Bytes() []byte {
	return []byte{}
}
