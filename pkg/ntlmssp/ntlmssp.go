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

func NewSSPFeildInformation(len uint16, offset uint32) SSP_FeildInformation {
	return SSP_FeildInformation{Len: len, MaxLen: len, BufferOffset: offset}
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

func ParseSSPChallenge(b []byte) SSP_Challenge {
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
	Signature                       [8]byte              //8
	MessageType                     uint32               //12
	LmChallengeResponseFields       SSP_FeildInformation //20
	NtChallengeResponseFields       SSP_FeildInformation //28
	DomainNameFields                SSP_FeildInformation //36
	UsernameFields                  SSP_FeildInformation //44
	WorkstationFields               SSP_FeildInformation //52
	EncryptedRandomSessionKeyFields SSP_FeildInformation //60
	NegotiateFlags                  uint32               //64
	//Version                         [8]byte              //72
	//MIC     [16]byte //88 //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/a211d894-21bc-4b8b-86ba-b83d0c167b00#Appendix_A_12 HMMMM
	Payload authenticatePayload
}

func NewSSPAuthenticate(response, domainName, username, workstation, sessionkey []byte) SSP_Authenticate {
	r := SSP_Authenticate{
		Signature:   [8]byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00},
		MessageType: 3,
	}
	payloadOffset := 64                                                            //only because no MIC and no negotiate flag to do version
	r.LmChallengeResponseFields = NewSSPFeildInformation(0, uint32(payloadOffset)) //not supporting lm I guess
	r.NtChallengeResponseFields = NewSSPFeildInformation(uint16(len(response)), uint32(payloadOffset))
	r.Payload.NtChallengeResponse = response
	payloadOffset += len(response)
	r.DomainNameFields = NewSSPFeildInformation(uint16(len(domainName)), uint32(payloadOffset))
	r.Payload.DomainName = domainName
	payloadOffset += len(domainName)
	r.UsernameFields = NewSSPFeildInformation(uint16(len(username)), uint32(payloadOffset))
	r.Payload.UserName = username
	payloadOffset += len(username)
	r.WorkstationFields = NewSSPFeildInformation(uint16(len(workstation)), uint32(payloadOffset))
	r.Payload.Workstation = workstation
	payloadOffset += len(workstation)
	//r.WorkstationFields = NewSSPFeildInformation(uint16(len(workstation)), uint32(72+payloadOffset))
	r.Payload.EncryptedRandomSessionKey = sessionkey
	r.NegotiateFlags = 0xa2888215 // hard coded for now - flags should be selected sanely in the future

	//0x18, 0x00, 0x18, 0x00}

	return r
}

func (s SSP_Authenticate) Bytes() []byte {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.LittleEndian, s.Signature)
	binary.Write(&buff, binary.LittleEndian, s.MessageType)
	binary.Write(&buff, binary.LittleEndian, s.LmChallengeResponseFields)
	binary.Write(&buff, binary.LittleEndian, s.NtChallengeResponseFields)
	binary.Write(&buff, binary.LittleEndian, s.DomainNameFields)
	binary.Write(&buff, binary.LittleEndian, s.UsernameFields)
	binary.Write(&buff, binary.LittleEndian, s.WorkstationFields)
	binary.Write(&buff, binary.LittleEndian, s.EncryptedRandomSessionKeyFields)
	binary.Write(&buff, binary.LittleEndian, s.NegotiateFlags)

	buff.Write(s.Payload.LmChallengeResponse)
	buff.Write(s.Payload.NtChallengeResponse)
	buff.Write(s.Payload.DomainName)
	buff.Write(s.Payload.UserName)
	buff.Write(s.Payload.Workstation)
	buff.Write(s.Payload.EncryptedRandomSessionKey)

	return buff.Bytes()
}

type authenticatePayload struct {
	LmChallengeResponse       []byte
	NtChallengeResponse       []byte
	DomainName                []byte
	UserName                  []byte
	Workstation               []byte
	EncryptedRandomSessionKey []byte
}
