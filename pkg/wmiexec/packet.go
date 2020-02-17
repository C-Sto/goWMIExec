package wmiexec

import (
	"bytes"
	"encoding/binary"

	"github.com/C-Sto/goWMIExec/pkg/rpce"

	"github.com/C-Sto/goWMIExec/pkg/uuid"
)

type FaultStatus uint32

const (
	AccessDenied FaultStatus = 5
)

var statusmap = map[FaultStatus]string{
	5:          "nca_s_fault_access_denied",
	0x1c00001b: "nca_s_fault_remote_no_memory",
	0x1c01000b: "nca_proto_error (The RPC client or server protocol has been violated.)",
	0x1c010003: "nca_unk_if (The server does not export the requested interface.)",
}

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

func NewCTXItem(
	id uint16,
	//numtransitems byte,
	interf uuid.UUID,
	//ifVersMaj,
	//ifVersMin uint16,
	tfsyn uuid.UUID,
	tfsVers uint32,
) CTXItem {
	return CTXItem{
		ContextID:         id,
		NumTransItems:     1,
		Unkown2:           0x00,
		Interface:         interf,
		InterfaceVers:     0,
		InterfaceVerMinor: 0,
		TransferSyntax:    tfsyn,
		TransferSyntaxVer: tfsVers,
	}
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

func NewPacketRPCBind(
	packetCallID uint32,
	packetCTXItems []CTXItem) PacketRPCBind {

	packetNumCTXItems := byte(len(packetCTXItems))

	ret := PacketRPCBind{}
	retH := RPCHead{}
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

	if packetNumCTXItems == 3 {

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
	ret.CTXItems = packetCTXItems
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
	RPCHead     RPCHead
	Pad         [4]byte
	Sec_trailer Sec_trailer
	SSPData     []byte
}

type Sec_trailer struct {
	//MaxXmitFrag   uint16
	//MaxRecvFrag   uint16
	AuthType      rpce.SecurityProviders
	AuthLevel     rpce.AuthLevel
	AuthPadLength byte
	AuthReserved  byte
	ContextID     uint32
}

func NewPacketRPCAuth3(callID uint32, authLevel rpce.AuthLevel, ssp []byte) PacketRPCAuth3 {
	ret := PacketRPCAuth3{}

	ret.RPCHead.Version = 0x05
	ret.RPCHead.VersionMinor = 0
	ret.RPCHead.PacketType = 0x10
	ret.RPCHead.PacketFlags = 0x03
	ret.RPCHead.DataRepresentation = [4]byte{0x10, 00, 00, 00}
	ret.RPCHead.FragLength = uint16(len(ssp) + 28)
	ret.RPCHead.AuthLength = uint16(len(ssp))
	ret.RPCHead.CallID = callID //0x03
	ret.Pad = [4]byte{0, 0, 0, 0}
	ret.Sec_trailer.AuthType = rpce.RPC_C_AUTHN_WINNT // 0x0a
	ret.Sec_trailer.AuthLevel = authLevel
	ret.Sec_trailer.AuthPadLength = 0
	ret.Sec_trailer.AuthReserved = 0
	ret.Sec_trailer.ContextID = 0
	ret.SSPData = ssp

	return ret
}

func (p PacketRPCAuth3) Bytes() []byte {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.LittleEndian, p.RPCHead)
	binary.Write(&buff, binary.LittleEndian, p.Pad)
	binary.Write(&buff, binary.LittleEndian, p.Sec_trailer)
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
		NTLMSSPVerifierChecksum:       [8]byte{},
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
		TransferSyntax:    uuid.NDRTransferSyntax_V2,
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
