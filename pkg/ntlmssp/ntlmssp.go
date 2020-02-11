package ntlmssp

import (
	"bytes"
	"encoding/binary"
)

type SSP_Negotiate struct {
	Signature        [8]byte
	MessageType      uint32
	NegotiateFlags   uint32
	DomainNameFields SSP_FeildInformation
}

type SSP_FeildInformation struct {
	Len          uint16
	MaxLen       uint16
	BufferOffset uint32
}

type SSP_Challenge struct {
	Signature        [8]byte
	MessageType      uint32
	TargetNameFields SSP_FeildInformation
	NegotiateFlags   uint32
	ServerChallenge  [8]byte
	Reserved         [8]byte
	TargetInfoFields SSP_FeildInformation
	Version          [8]byte
	Payload          ChallengePayload
}

type ChallengePayload struct {
	TargetName []byte
	TargetInfo []AV_Pair
}

func (c ChallengePayload) GetTargetInfoBytes() []byte {
	buff := bytes.Buffer{}
	for _, av := range c.TargetInfo {
		binary.Write(&buff, binary.LittleEndian, av.AvID)
		binary.Write(&buff, binary.LittleEndian, av.AvLen)
		buff.Write(av.Value)
	}

	return buff.Bytes()
}

func (c ChallengePayload) GetTimeBytes() []byte {
	for _, av := range c.TargetInfo {
		if av.AvID == MsvAvTimestamp {
			return av.Value
		}
	}
	return nil
}

func NewSSPChallenge(b []byte) SSP_Challenge {
	cursor := 0

	r := SSP_Challenge{}
	copy(r.Signature[:], b[:8])
	cursor += 8
	binary.Read(bytes.NewReader(b[cursor:]), binary.LittleEndian, &r.MessageType)
	cursor += 4
	binary.Read(bytes.NewReader(b[cursor:]), binary.LittleEndian, &r.TargetNameFields)
	cursor += 8
	binary.Read(bytes.NewReader(b[cursor:]), binary.LittleEndian, &r.NegotiateFlags)
	cursor += 4
	binary.Read(bytes.NewReader(b[cursor:]), binary.LittleEndian, &r.ServerChallenge)
	cursor += 8
	//reserved??
	copy(r.Reserved[:], b[cursor:cursor+8])
	cursor += 8
	binary.Read(bytes.NewReader(b[cursor:]), binary.LittleEndian, &r.TargetInfoFields)
	cursor += 8
	copy(r.Version[:], b[cursor:cursor+8])
	cursor += 8

	//complicated lol
	r.Payload = ChallengePayload{}
	r.Payload.TargetName = make([]byte, r.TargetNameFields.Len)
	copy(r.Payload.TargetName,
		b[r.TargetNameFields.BufferOffset:r.TargetNameFields.BufferOffset+uint32(r.TargetNameFields.Len)])

	tmpPairs := []AV_Pair{}
	avOffset := r.TargetInfoFields.BufferOffset

	//REALLY WHAT THE FUCK MS?
	for {
		if b[avOffset] == MsvAvEOL {
			break
		}
		tmpPair := AV_Pair{}
		binary.Read(bytes.NewReader(b[avOffset:]), binary.LittleEndian, &tmpPair.AvID)
		avOffset += 2
		binary.Read(bytes.NewReader(b[avOffset:]), binary.LittleEndian, &tmpPair.AvLen)
		avOffset += 2
		tmpPair.Value = make([]byte, tmpPair.AvLen)
		copy(tmpPair.Value, b[avOffset:avOffset+uint32(tmpPair.AvLen)])
		tmpPairs = append(tmpPairs, tmpPair)
		avOffset += uint32(tmpPair.AvLen)
	}
	tmpPairs = append(tmpPairs, AV_Pair{})
	r.Payload.TargetInfo = tmpPairs
	return r
}

type SSP_Authenticate struct {
	Signature                       [8]byte
	MessageType                     uint32
	LmChallengeResponseFields       SSP_FeildInformation
	NtChallengeResponseFields       SSP_FeildInformation
	DomainNameFields                SSP_FeildInformation
	UsernameFields                  SSP_FeildInformation
	WorkstationFields               SSP_FeildInformation
	EncryptedRandomSessionKeyFields SSP_FeildInformation
	NegotiateFlags                  uint32
	Version                         [8]byte
	MIC                             [16]byte
	Payload                         authenticatePayload
}

type authenticatePayload struct {
	LmChallengeResponse       []byte
	NtChallengeResponse       []byte
	DomainName                []byte
	UserName                  []byte
	Workstation               []byte
	EncryptedRandomSessionKey []byte
}
