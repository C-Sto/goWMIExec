package rpce

import (
	"bytes"
	"encoding/binary"
)

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
	return len(a.Bytes())
}

func (a AuthVerifier) Bytes() []byte {
	buff := bytes.Buffer{}

	binary.Write(&buff, binary.LittleEndian, a.Align)
	binary.Write(&buff, binary.LittleEndian, a.AuthType)
	binary.Write(&buff, binary.LittleEndian, a.AuthLevel)
	binary.Write(&buff, binary.LittleEndian, a.AuthPadLength)
	binary.Write(&buff, binary.LittleEndian, a.Reserved)
	binary.Write(&buff, binary.LittleEndian, a.ContextID)
	binary.Write(&buff, binary.LittleEndian, a.AuthValue)

	return buff.Bytes()
}

func NewAuthVerifier(authType SecurityProviders, authLevel AuthLevel, contextID uint32, padLength byte, value []byte) AuthVerifier {
	r := AuthVerifier{
		Align:         make([]byte, padLength),
		AuthType:      authType,
		AuthLevel:     authLevel,
		AuthPadLength: padLength,
		ContextID:     contextID,
		AuthValue:     value,
	}

	return r
}
