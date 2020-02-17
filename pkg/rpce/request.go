package rpce

import (
	"bytes"
	"encoding/binary"
)

type RequestReq struct { //poorly named, I'm aware
	CommonHead   CommonHead
	AllocHint    uint32
	PContextID   ContextID
	Opnum        uint16
	StubData     []byte
	AuthVerifier *AuthVerifier
}

func NewRequestReq(callID uint32, ctxID ContextID, opNum uint16, data []byte, auth *AuthVerifier) RequestReq {
	r := RequestReq{}
	//todo, don't hard code ptype
	r.CommonHead = NewCommonHeader(0, 0x03, callID)
	r.PContextID = ctxID
	r.Opnum = opNum
	r.StubData = make([]byte, len(data))
	copy(r.StubData, data)

	r.AllocHint = 0 //idfk, I guess this should be the length of the data segment?

	r.CommonHead.FragLength = 24 //length of common header
	r.CommonHead.FragLength += uint16(len(r.StubData))

	if r.AuthVerifier != nil {
		r.CommonHead.FragLength += uint16(r.AuthVerifier.SizeOf())
		r.CommonHead.AuthLength = uint16(len(r.AuthVerifier.AuthValue))
	}

	return r
}

func (r RequestReq) Bytes() []byte {
	buff := bytes.Buffer{}

	binary.Write(&buff, binary.LittleEndian, r.CommonHead)
	binary.Write(&buff, binary.LittleEndian, r.AllocHint)
	binary.Write(&buff, binary.LittleEndian, r.PContextID)
	binary.Write(&buff, binary.LittleEndian, r.Opnum)
	buff.Write(r.StubData)
	if r.AuthVerifier != nil {
		buff.Write(r.AuthVerifier.Bytes())
	}
	return buff.Bytes()
}
