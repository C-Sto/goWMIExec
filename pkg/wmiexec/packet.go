package wmiexec

import (
	"bytes"
	"encoding/binary"
)

type FaultStatus uint32

const (
	AccessDenied FaultStatus = 5
)

var statusmap = map[FaultStatus]string{5: "nca_s_fault_access_denied"}

type PacketFault struct {
	RPCHead     RPCHead
	AllocHint   uint32
	ContextID   uint16
	CancelCount byte
	FaultFlags  byte
	Status      FaultStatus
	Reserved    uint32
}

func (pf PacketFault) StatusString() string {
	return statusmap[pf.Status]
}

type StatusFlags byte

const PacketFlagFirstFrag StatusFlags = 1
const (
	_                              = iota //FirstFrag StatusFlags = iota
	PacketFlagLastFrag StatusFlags = iota << 1
	PacketFlagCancelPending
	PacketFlagReserved
	PacketFlagMultiplex
	PacketFlagDidNotExecute
	PacketFlagMaybe
	PacketFlagObject
)

type RPCHead struct {
	Version            byte
	VersionMinor       byte
	PacketType         byte
	PacketFlags        byte
	DataRepresentation [4]byte
	FragLength         uint16
	AuthLength         uint16
	CallID             uint32
}

type BindHead struct {
	MaxXmitFrag uint16
	MaxRecvFrag uint16
	AssocGroup  uint32
	NumCTXItems byte
	Unknown     [3]byte
}

type CTXItem struct {
	ContextID         uint16
	NumTransItems     byte
	Unkown2           byte
	Interface         [16]byte
	InterfaceVers     uint16
	InterfaceVerMinor uint16
	TransferSyntax    [16]byte
	TransferSyntaxVer uint32
}

type RPCBindTail struct {
	AuthType                 byte   // { 0x0a });
	AuthLevel                byte   // { 0x04 });
	AuthPadLength            byte   // { 0x00 });
	AuthReserved             byte   // { 0x00 });
	ContextID4               uint32 // { 0x00, 0x00, 0x00, 0x00 });
	Identifier               uint64 // { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 });
	MessageType              uint32 // { 0x01, 0x00, 0x00, 0x00 });
	NegotiateFlags           uint32 // { 0x97, 0x82, 0x08, 0xe2 });
	CallingWorkstationDomain uint64 // { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
	CallingWorkstationName   uint64 // { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
	OSVersion                uint64 // { 0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f });

}

type PacketRPCBind struct {
	RPCHead     RPCHead
	BindHead    BindHead
	CTXItems    []CTXItem
	RPCBindTail RPCBindTail
}

func NewPacketRPCBind(packetCallID uint32, packetMaxFrag uint16, packetNumCTXItems byte, packetContextID uint16, packetUUID [16]byte, packetUUIDVersion uint16) PacketRPCBind {
	ret := PacketRPCBind{}
	retH := RPCHead{}
	retC := []CTXItem{}
	retH.Version = 0x05
	retH.VersionMinor = 0x00
	retH.PacketType = 0x0b
	retH.PacketFlags = 0x03
	retH.DataRepresentation = [4]byte{0x10, 00, 00, 0x00}

	retH.FragLength = 0x4800
	retH.AuthLength = 0x00
	retH.CallID = packetCallID

	ret.RPCHead = retH
	retBH := BindHead{}
	retBH.MaxXmitFrag = 0x10b8
	retBH.MaxRecvFrag = 0x10b8
	retBH.AssocGroup = 0x00
	retBH.NumCTXItems = packetNumCTXItems
	retBH.Unknown = [3]byte{}
	ret.BindHead = retBH

	ctx1 := CTXItem{}
	ctx1.ContextID = packetContextID
	ctx1.NumTransItems = 1
	ctx1.Unkown2 = 0x00
	ctx1.Interface = packetUUID
	ctx1.InterfaceVers = packetUUIDVersion
	ctx1.InterfaceVerMinor = 0x00
	ctx1.TransferSyntax = [16]byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
	ctx1.TransferSyntaxVer = 0x02
	retC = append(retC, ctx1)

	if packetNumCTXItems >= 2 {
		ctx2 := CTXItem{}
		ctx2.ContextID = 0x0001
		ctx2.NumTransItems = 0x01
		ctx2.Unkown2 = 0x00
		ctx2.Interface = [16]byte{0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a}
		ctx2.InterfaceVers = 0x0000
		ctx2.InterfaceVerMinor = 0x0000
		ctx2.TransferSyntax = [16]byte{0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		ctx2.TransferSyntaxVer = 0x01000000
		retC = append(retC, ctx2)

		if packetNumCTXItems == 3 {
			retC[1].Interface = [16]byte{0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
			retC[1].TransferSyntax = [16]byte{0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36}
			ctx3 := CTXItem{}
			ctx3.ContextID = 0x0200
			ctx3.NumTransItems = 0x01
			ctx3.Unkown2 = 0x00
			ctx3.Interface = [16]byte{0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
			ctx3.InterfaceVers = 0x00
			ctx3.InterfaceVerMinor = 0x00
			ctx3.TransferSyntax = [16]byte{0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			ctx3.TransferSyntaxVer = 0x01000000
			retC = append(retC, ctx3)

			tail := RPCBindTail{}

			tail.AuthType = 0x0a
			tail.AuthLevel = 0x04
			tail.AuthPadLength = 0x00
			tail.AuthReserved = 0x00
			tail.ContextID4 = 0x00
			tail.Identifier = 0x005053534d4c544e
			tail.MessageType = 0x01
			tail.NegotiateFlags = 0xe2088297
			tail.CallingWorkstationDomain = 0x00
			tail.CallingWorkstationName = 0x00
			tail.OSVersion = 0x0f0000001db10106

			ret.RPCBindTail = tail
		}
	}

	if packetCallID == 3 {
		tail := RPCBindTail{}
		tail.AuthType = 0x0a
		tail.AuthLevel = 0x02
		tail.AuthPadLength = 0x00
		tail.AuthReserved = 0x00
		tail.ContextID4 = 0x00
		tail.Identifier = 0x005053534d4c544e
		tail.MessageType = 0x01
		tail.NegotiateFlags = 0xe2088297
		tail.CallingWorkstationDomain = 0x00
		tail.CallingWorkstationName = 0x00
		tail.OSVersion = 0x0f0000001db10106
		ret.RPCBindTail = tail
	}
	ret.CTXItems = retC
	return ret
}

func (p PacketRPCBind) Bytes() []byte {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.LittleEndian, p.RPCHead)
	binary.Write(&buff, binary.LittleEndian, p.BindHead)
	for _, ctx := range p.CTXItems {
		binary.Write(&buff, binary.LittleEndian, ctx)
	}

	if p.BindHead.NumCTXItems > 2 || p.RPCHead.CallID == 3 {
		binary.Write(&buff, binary.LittleEndian, p.RPCBindTail)
	}

	return buff.Bytes()
}

type ReqHead struct {
	AllocHint uint32
	ContextID uint16
	OpNum     uint16
}

type PacketRPCRequest struct {
	RPCHead RPCHead
	ReqHead ReqHead
	Data    []byte
}

func NewPacketRPCRequest(packetFlags byte, serviceLen, authLen, authPad uint16, callID uint32, contextID uint16, opNum uint16, data []byte) PacketRPCRequest {
	fullAuthLen := uint16(0)

	if authLen > 0 {
		fullAuthLen = authLen + authPad + 8
	}

	writeLen := serviceLen + 24 + fullAuthLen + uint16(len(data))
	allocHint := uint32(serviceLen) + uint32(len(data))

	ret := PacketRPCRequest{}

	ret.RPCHead.Version = 0x05
	ret.RPCHead.VersionMinor = 0
	ret.RPCHead.PacketType = 0
	ret.RPCHead.PacketFlags = packetFlags
	ret.RPCHead.DataRepresentation = [4]byte{0x10, 00, 00, 00}
	ret.RPCHead.FragLength = writeLen
	ret.RPCHead.AuthLength = authLen
	ret.RPCHead.CallID = callID

	ret.ReqHead.AllocHint = allocHint
	ret.ReqHead.ContextID = contextID
	ret.ReqHead.OpNum = opNum
	ret.Data = make([]byte, len(data))
	copy(ret.Data, data)

	return ret
}

func (p PacketRPCRequest) Bytes() []byte {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.LittleEndian, p.RPCHead)
	binary.Write(&buff, binary.LittleEndian, p.ReqHead)
	buff.Write(p.Data)
	return buff.Bytes()
}

type PacketRPCAuth3 struct {
	RPCHead    RPCHead
	RPCAuthBod RPCAuthBod
	SSPData    []byte
}

type RPCAuthBod struct {
	MaxXmitFrag   uint16
	MaxRecvFrag   uint16
	AuthType      byte
	AuthLevel     byte
	AuthPadLength byte
	AuthReserved  byte
	ContextID     uint32
}

func NewPacketRPCAuth3(ssp []byte) PacketRPCAuth3 {
	ret := PacketRPCAuth3{}

	ret.RPCHead.Version = 0x05
	ret.RPCHead.VersionMinor = 0
	ret.RPCHead.PacketType = 0x10
	ret.RPCHead.PacketFlags = 0x03
	ret.RPCHead.DataRepresentation = [4]byte{0x10, 00, 00, 00}
	ret.RPCHead.FragLength = uint16(len(ssp) + 28)
	ret.RPCHead.AuthLength = uint16(len(ssp))
	ret.RPCHead.CallID = 0x03

	ret.RPCAuthBod.MaxXmitFrag = 0x16d0
	ret.RPCAuthBod.MaxRecvFrag = 0x16d0
	ret.RPCAuthBod.AuthType = 0x0a
	ret.RPCAuthBod.AuthLevel = 0x02
	ret.RPCAuthBod.AuthPadLength = 0
	ret.RPCAuthBod.AuthReserved = 0
	ret.RPCAuthBod.ContextID = 0
	ret.SSPData = ssp

	return ret
}

func (p PacketRPCAuth3) Bytes() []byte {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.LittleEndian, p.RPCHead)
	binary.Write(&buff, binary.LittleEndian, p.RPCAuthBod)
	buff.Write(p.SSPData)
	return buff.Bytes()
}

type PacketNTLMSSPVerifier struct {
	Padding         []byte
	SSPVerifierBody SSPVerifierBody
}

type SSPVerifierBody struct {
	AuthType                      byte
	AuthLevel                     byte
	AuthPadLen                    byte
	AuthReserved                  byte
	ContextID                     uint32
	NTLMSSPVerifierVersionNumber  uint32
	NTLMSSPVerifierChecksum       [8]byte
	NTLMSSPVerifierSequenceNumber uint32
}

func NewPacketNTLMSSPVerifier(padLen, authlevel byte, seqNum uint32) PacketNTLMSSPVerifier {
	r := PacketNTLMSSPVerifier{}

	r.Padding = make([]byte, padLen)

	r.SSPVerifierBody = SSPVerifierBody{
		AuthType:                      0x0a,
		AuthLevel:                     authlevel,
		AuthPadLen:                    padLen,
		AuthReserved:                  0x00,
		ContextID:                     0x00,
		NTLMSSPVerifierVersionNumber:  0x01,
		NTLMSSPVerifierChecksum:       [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		NTLMSSPVerifierSequenceNumber: seqNum,
	}

	return r
}

func (p PacketNTLMSSPVerifier) Bytes() []byte {
	buff := bytes.Buffer{}
	buff.Write(p.Padding)
	binary.Write(&buff, binary.LittleEndian, p.SSPVerifierBody)
	return buff.Bytes()
}

type PacketRPCAlterContext struct {
	RPCHead  RPCHead
	BindHead BindHead
	CTXItem  CTXItem
}

func NewPacketRPCAlterContext(callID, assGroup uint32, ctxID uint16, ctxInterface []byte) PacketRPCAlterContext {
	r := PacketRPCAlterContext{}
	r.RPCHead = RPCHead{
		Version:            0x05,
		VersionMinor:       0x00,
		PacketType:         0x0e,
		PacketFlags:        0x03,
		DataRepresentation: [4]byte{0x10, 0, 0, 0},
		FragLength:         0x48,
		AuthLength:         0,
		CallID:             callID,
	}

	r.BindHead = BindHead{
		MaxXmitFrag: 0x16d0,
		MaxRecvFrag: 0x16d0,
		AssocGroup:  assGroup,
		NumCTXItems: 1,
		Unknown:     [3]byte{},
	}

	r.CTXItem = CTXItem{
		ContextID:         ctxID,
		NumTransItems:     1,
		Unkown2:           0,
		InterfaceVers:     0,
		InterfaceVerMinor: 0,
		TransferSyntax:    [16]byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60},
		TransferSyntaxVer: 2,
	}
	copy(r.CTXItem.Interface[:], ctxInterface)

	return r

}

func (p PacketRPCAlterContext) Bytes() []byte {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.LittleEndian, p)
	return buff.Bytes()
}
