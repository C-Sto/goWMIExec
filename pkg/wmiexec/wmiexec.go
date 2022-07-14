package wmiexec

import (
	"bytes"
	"errors"
	"io"

	"github.com/C-Sto/goWMIExec/pkg/ntlmssp"

	"github.com/C-Sto/goWMIExec/pkg/rpce"

	"github.com/C-Sto/goWMIExec/pkg/uuid"

	"go.uber.org/zap/zapcore"

	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/text/encoding/unicode"
)

var logger, logerr = zap.NewProduction()
var sugar = logger.Sugar()
var Timeout = 5

type WmiExecConfig struct {
	username, password, hash, domain string
	targetAddress, clientHostname    string

	verbose bool
	logger  *zap.Logger
}

func GetNetworkBindings(target string) (ret []string, err error) {

	tcpClient, err := net.DialTimeout("tcp", target, time.Duration(Timeout)*time.Second)
	if err != nil {
		return nil, err
	}
	err = tcpClient.SetReadDeadline(time.Now().Add(time.Duration(Timeout) * time.Second))
	if err != nil {
		return nil, err
	}
	defer tcpClient.Close()

	//Hello, please are you ok to connect?
	//we seem to be using the iobjectexporter abstract syntax... whatever that means?
	abs := rpce.NewPSyntaxID(uuid.IID_IObjectExporter, 0)

	ctxList := rpce.NewPcontextList()
	ctxList.AddContext( //I tried to make it neater... I failed :(
		rpce.NewPcontextElem(
			0,
			abs,
			[]rpce.PSyntaxID{
				rpce.NewPSyntaxID(uuid.NDRTransferSyntax_V2, 2),
			},
		),
	)

	ctxList.AddContext( //I tried to make it neater... I failed :(
		rpce.NewPcontextElem(
			0,
			abs,
			[]rpce.PSyntaxID{
				rpce.NewPSyntaxID(uuid.BindTimeFeatureReneg, 0x01000000),
			},
		),
	)
	packetRPC := rpce.NewBindReq(2, ctxList, nil)

	recv := make([]byte, 2048)

	tcpClient.Write(packetRPC.Bytes())
	tcpClient.Read(recv)
	recvHdr := rpce.CommonHead{}

	binary.Read(bytes.NewReader(recv), binary.LittleEndian, &recvHdr)

	if recvHdr.PacketType != 12 {
		return nil, fmt.Errorf("Got an unexpected response. Wanted 12 (0x0c) got %d (%x)", recvHdr.PacketType, recvHdr.PacketType)
	}

	//cool, can we auth?
	packetRPCReq := rpce.NewRequestReq(2, 0, 5, nil, nil)
	tcpClient.Write(packetRPCReq.Bytes())

	tcpClient.Read(recv)
	if err != nil {
		return nil, err
	}

	//	rsp := NewDCOMResponse(recv[:n])
	recvHdr = rpce.CommonHead{}
	readr := bytes.NewReader(recv)
	binary.Read(readr, binary.LittleEndian, &recvHdr)
	if recvHdr.PacketType != 2 {
		return nil, fmt.Errorf("Got an unexpected response. Wanted 0x02 got %x", recvHdr.PacketType)
	}
	rsp := rpce.ParseResponse(recv)

	resolved := NewDCOMOXIDResolver(rsp.StubData)

	for _, x := range resolved.StringBindings {
		//decode for output to user (this should probably be in main... whatever)
		dcoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		b, er := dcoder.Bytes(x.NetworkAddr)
		if er != nil {
			continue
		}
		ret = append(ret, string(b))
	}
	return
}

func NewExecConfig(username, password, hash, domain, target, clientHostname string, verbose bool, logger *zap.Logger, writer io.Writer) (WmiExecConfig, error) {
	r := WmiExecConfig{}

	if logger == nil && writer == nil {
		//default logger
		//r.logger = zap.new
		var err error
		cfg := zap.NewProductionConfig()
		cfg.Encoding = "console"
		logger, err = cfg.Build()
		if err != nil {
			return r, err
		}
		r.logger = logger
	} else if writer != nil && logger == nil {
		writeser := zapcore.AddSync(writer)
		customWriter := zapcore.Lock(writeser)
		c := zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig())
		core := zapcore.NewCore(c, customWriter, zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
			return lvl < zapcore.ErrorLevel
		}))
		logger = zap.New(core)

	}

	clientHostname = strings.ToUpper(clientHostname)
	if len(clientHostname) > 16 {
		clientHostname = clientHostname[:15]
		r.logger.Sugar().Infof("Hostname too long (over 16 chars). Using first 15 chars: %s", clientHostname)
	}

	unihn, err := toUnicodeS(clientHostname)
	if err != nil {
		return WmiExecConfig{}, err
	}

	r = WmiExecConfig{
		username: username, password: password, hash: hash, domain: domain,
		targetAddress: target, clientHostname: unihn,
		verbose: verbose,
		logger:  logger,
	}

	return r, nil
}

type wmiExecer struct {
	log       *zap.SugaredLogger
	logProper *zap.Logger
	config    *WmiExecConfig
	tcpClient net.Conn

	targetHostname   string
	TargetRPCPort    int
	assGroup         uint32
	objectUUID       []byte
	causality        []byte
	ipid             []byte
	clientSigningKey []byte
	oxid             []byte
	objUUID2         []byte

	stage string
}

func NewExecer(cfg *WmiExecConfig) *wmiExecer {
	r := wmiExecer{
		log:       cfg.logger.Sugar(),
		logProper: cfg.logger,
		config:    cfg,
		stage:     "exit",
	}

	return &r
}

func (e *wmiExecer) SetTargetBinding(binding string) error {
	if binding == "" {
		//e.log.Info("Getting network bindings from remote host")
		targets, err := GetNetworkBindings(e.config.targetAddress)
		if err != nil {
			return err
		}
		//e.log.Info("Resolved names, all network string bindings for host:")
		//for _, name := range targets {
		//	e.log.Info("\t", name)
		//}
		//e.log.Info("Using first value as target hostname: ", targets[0])
		e.targetHostname = targets[0]
		return nil
	}
	e.targetHostname = binding
	return nil
}

func (e *wmiExecer) Auth() error {
	var err error
	e.tcpClient, err = net.DialTimeout("tcp", e.config.targetAddress, time.Duration(Timeout)*time.Second)
	if err != nil {
		return err
	}
	defer e.tcpClient.Close()
	err = e.tcpClient.SetReadDeadline(time.Now().Add(time.Duration(Timeout) * time.Second))
	if err != nil {
		return err
	}
	//ey, can I please talk to SCM? I will use NTLM SSP to auth..
	ctxList := rpce.NewPcontextList()
	ctxList.AddContext(rpce.NewPcontextElem(
		1,
		rpce.NewPSyntaxID(uuid.IID_IRemoteSCMActivator, 0),
		[]rpce.PSyntaxID{
			rpce.NewPSyntaxID(uuid.NDRTransferSyntax_V2, 2),
		},
	))

	flags := ntlmssp.NTLMSSP_NEGOTIATE_UNICODE | ntlmssp.NTLM_NEGOTIATE_OEM |
		ntlmssp.NTLMSSP_REQUEST_TARGET | ntlmssp.NTLMSSP_NEGOTIATE_NTLM |
		ntlmssp.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | ntlmssp.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
		ntlmssp.NTLMSSP_NEGOTIATE_VERSION | ntlmssp.NTLMSSP_NEGOTIATE_128 |
		ntlmssp.NTLMSSP_NEGOTIATE_56
	n := ntlmssp.NewSSPNegotiate(flags) //todo: make this flags... value below

	auth := rpce.NewAuthVerifier(
		rpce.RPC_C_AUTHN_WINNT,
		rpce.RPC_C_AUTHN_LEVEL_CONNECT,
		0,
		n.Bytes(),
	)

	packetRPC := rpce.NewBindReq(3, ctxList, &auth)
	recv := make([]byte, 2048)
	e.tcpClient.Write(packetRPC.Bytes())

	e.tcpClient.Read(recv)

	//should probably check here that it's not an error
	bindAck := rpce.ParseBindAck(recv)

	challengeInfo := ntlmssp.ParseSSPChallenge(bindAck.AuthVerifier.AuthValue)
	ntlmChal := challengeInfo.ServerChallenge[:]
	deets := challengeInfo.Payload.GetTargetInfoBytes()
	timebytes := challengeInfo.Payload.GetTimeBytes()

	hostname := e.config.clientHostname

	domain := []byte(e.config.domain)
	uniuser, err := toUnicodeS(e.config.username)
	if err != nil {
		return err
	}
	username := []byte(uniuser)

	key1, err := ntlmssp.NTLMV2Hash(e.config.password, string(e.config.hash), e.config.username, string(e.config.domain))
	if err != nil {
		return err
	}

	ntlmResp := ntlmssp.NTLMV2Response(key1, ntlmChal, timebytes, deets)
	sspResp := ntlmssp.NewSSPAuthenticate(ntlmResp, domain, username, []byte(hostname), nil).Bytes()

	packetAuth := rpce.NewAuth3Req(3, rpce.RPC_C_AUTHN_LEVEL_CONNECT, sspResp)
	prepBytes2 := packetAuth.Bytes()
	e.tcpClient.Write(prepBytes2)

	cause_id_bytes := [16]byte{}
	rand.Seed(time.Now().UnixNano())
	rand.Read(cause_id_bytes[:])

	dcomThing := NewDCOMRemoteInstance(cause_id_bytes, e.config.targetAddress)

	p := rpce.NewRequestReq(3, 1, 4, dcomThing.Bytes(), nil)
	//fmt.Println(pp)
	prepBytes3 := p.Bytes()
	recv3 := make([]byte, 2048)
	e.tcpClient.Write(prepBytes3)
	e.tcpClient.Read(recv3)

	if recv3[2] == 3 {
		pf := rpce.ParseFault(recv3)
		e.log.Error("Error: ", pf.StatusString(), " ", pf.Status)
		return errors.New(pf.StatusString())
	}

	//should probably check here that it's not an error
	rsp := rpce.ParseResponse(recv3)

	if rsp.CommonHead.PacketType == 2 {
		e.log.Info("WMI Access possible!")
	}

	unihn, err := toUnicodeS(e.targetHostname + "[")
	if err != nil {
		return err
	}
	targ := "\x07\x00" + unihn
	tgtIndex := bytes.Index(rsp.StubData, []byte(targ))
	portString := rsp.StubData[tgtIndex+len(unihn)+2 : tgtIndex+len(unihn)+12]
	s, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().String(string(portString))
	if err != nil {
		return err
	}
	portNum, err := strconv.Atoi(s)
	if err != nil {
		e.log.Error("Error getting rpc port (possibly binding not found in target auth createinstance response)")
		return err
	}
	if portNum == 0 {
		e.log.Error("Got portNum 0.")
		return fmt.Errorf("did not expect port number to be 0")
	}

	//meow... MS must have been smoking crack when this was developed
	meowSig, _ := hex.DecodeString("4D454F570100000018AD09F36AD8D011A07500C04FB68820")
	meowIndex := bytes.Index(rsp.StubData, meowSig)
	ipid := rsp.StubData[meowIndex+48 : meowIndex+64]
	e.oxid = rsp.StubData[meowIndex+32 : meowIndex+40]
	oxid2Index := bytes.Index(rsp.StubData[meowIndex+100:], e.oxid)
	objUUID := rsp.StubData[meowIndex+100+oxid2Index+12 : meowIndex+100+oxid2Index+28]
	e.TargetRPCPort = portNum
	e.causality = cause_id_bytes[:]
	e.ipid = ipid
	e.objectUUID = objUUID

	return nil
}

func (e *wmiExecer) RPCConnect() error {
	var err error
	e.log.Infof("Connecting to %s:%d", e.config.targetAddress[:strings.Index(e.config.targetAddress, ":")], e.TargetRPCPort)

	//this is 'intentionally' left open (no deferred close!). This is the channel we send stuff on after RPC has been connected, so it needs to persist.
	//I should probably determine a better way to make sure it closes gracefully. Alas.
	e.tcpClient, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", e.config.targetAddress[:strings.Index(e.config.targetAddress, ":")], e.TargetRPCPort), time.Duration(Timeout)*time.Second)
	if err != nil {
		e.log.Error("Error: ", err.Error())
		return err
	}
	err = e.tcpClient.SetReadDeadline(time.Now().Add(time.Duration(Timeout) * time.Second))
	if err != nil {
		return err
	}
	ctxList := rpce.NewPcontextList()
	ctxList.AddContext(rpce.NewPcontextElem(
		0,
		rpce.NewPSyntaxID(uuid.IID_IRemUnknown2, 0),
		[]rpce.PSyntaxID{
			rpce.NewPSyntaxID(uuid.NDRTransferSyntax_V2, 2),
		},
	))

	ctxList.AddContext(rpce.NewPcontextElem(
		1,
		rpce.NewPSyntaxID(uuid.IID_IRemUnknown2, 0),
		[]rpce.PSyntaxID{
			rpce.NewPSyntaxID(uuid.NDR64TransferSyntax, 0x01000000),
		},
	))

	ctxList.AddContext(rpce.NewPcontextElem(
		0x0200, //unsure of the signifigance of this value..
		rpce.NewPSyntaxID(uuid.IID_IRemUnknown2, 0),
		[]rpce.PSyntaxID{
			rpce.NewPSyntaxID(uuid.BindTimeFeatureReneg, 0x01000000),
		},
	))

	flags := ntlmssp.NTLMSSP_NEGOTIATE_UNICODE | ntlmssp.NTLM_NEGOTIATE_OEM |
		ntlmssp.NTLMSSP_REQUEST_TARGET | ntlmssp.NTLMSSP_NEGOTIATE_SIGN |
		ntlmssp.NTLMSSP_NEGOTIATE_LM_KEY | ntlmssp.NTLMSSP_NEGOTIATE_NTLM |
		ntlmssp.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | ntlmssp.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
		ntlmssp.NTLMSSP_NEGOTIATE_VERSION | ntlmssp.NTLMSSP_NEGOTIATE_128 |
		ntlmssp.NTLMSSP_NEGOTIATE_56
	n := ntlmssp.NewSSPNegotiate(flags)

	auth := rpce.NewAuthVerifier(
		rpce.RPC_C_AUTHN_WINNT,
		rpce.RPC_C_AUTHN_LEVEL_PKT,
		0,
		n.Bytes(),
	)
	bindPacket := rpce.NewBindReq(2, ctxList, &auth)

	recv := make([]byte, 2048)
	e.tcpClient.Write(bindPacket.Bytes())
	e.tcpClient.Read(recv)

	rsp := rpce.ParseBindAck(recv)

	//e.assGroup = binary.LittleEndian.Uint32(recv[20:24])
	e.assGroup = rsp.AssocGroupID
	challengeInfo := ntlmssp.ParseSSPChallenge(rsp.AuthVerifier.AuthValue)
	ntlmChal := challengeInfo.ServerChallenge[:]
	deets := challengeInfo.Payload.GetTargetInfoBytes()
	timebytes := challengeInfo.Payload.GetTimeBytes()

	hostname := e.config.clientHostname

	domain := []byte(e.config.domain)
	uniuser, err := toUnicodeS(e.config.username)
	if err != nil {
		return err
	}
	username := []byte(uniuser)

	key1, err := ntlmssp.NTLMV2Hash(e.config.password, string(e.config.hash), e.config.username, string(e.config.domain))
	if err != nil {
		return err
	}

	ntlmResp := ntlmssp.NTLMV2Response(key1, ntlmChal, timebytes, deets)
	sspResp := ntlmssp.NewSSPAuthenticate(ntlmResp, domain, username, []byte(hostname), nil).Bytes()
	packetAuth := rpce.NewAuth3Req(3, rpce.RPC_C_AUTHN_LEVEL_PKT, sspResp)

	e.tcpClient.Write(packetAuth.Bytes())

	packetRemQ := NewPacketDCOMRemQueryInterface(e.causality, e.ipid, uuid.IID_IWbemLoginClientID[:])

	//the empty value at the end is a placeholder for the message signature struct, to ensure the length offsets are all correct.
	authv := rpce.NewAuthVerifier(0x0a, 4, 0, make([]byte, 16))

	packetRPC := rpce.NewRequestReq(2, 0, 3, append(e.objectUUID, packetRemQ.Bytes()...), &authv)
	packetRPC.CommonHead.PFCFlags = 0x83

	e.clientSigningKey = ntlmssp.GenerateClientSigningKey(key1, ntlmResp)

	messagesig := ntlmssp.NewMessageSignature(packetRPC.AuthBytes(), e.clientSigningKey, 0)

	authv.AuthValue = messagesig.Bytes()
	wmiClientSend := packetRPC.Bytes()
	e.tcpClient.Write(wmiClientSend)
	recv3 := make([]byte, 2048)
	e.tcpClient.Read(recv3)

	resp := rpce.ParseResponse(recv3)

	if resp.CommonHead.PacketType == 3 {
		pf := rpce.ParseFault(recv3)
		//log maybe
		e.log.Error("Error: ", pf.StatusString(), pf.Status)
		return errors.New(pf.StatusString())
	}

	e.objUUID2 = make([]byte, 16)
	if resp.CommonHead.PacketType == 2 {
		oxidInd := bytes.Index(resp.StubData, e.oxid)
		e.objUUID2 = resp.StubData[oxidInd+16 : oxidInd+32]
		e.stage = "AlterContext"
	} else {
		return fmt.Errorf("Did not receive expected value. Wanted 2, got %d", recv3[2])
	}

	return nil

}

func (e *wmiExecer) Exec(command string) error {

	sequence := uint32(0)

	var stubData, ipid2 []byte
	var callID uint32
	var contextID, opNum uint16
	var rqUUID []byte
	resp := make([]byte, 2048)
	for e.stage != "exit" {
		if resp[2] == 3 {
			pf := rpce.ParseFault(resp)
			e.log.Errorf("error: stage: %s call_id %d status: %s error code: %x", e.stage, callID, pf.StatusString(), pf.Status)
			return errors.New(pf.StatusString())
		}
		switch e.stage {
		case "AlterContext":
			acID := uint32(0)
			acConID := uint16(0)
			acUUID := uuid.UUID{}

			switch sequence {
			case 0:
				acID = 3
				acConID = 2
				acUUID = uuid.IID_IWbemLoginClientID
			case 1:
				acID = 4
				acConID = 3
				acUUID = uuid.CLSID_WbemLevel1Login

			case 6:
				acID = 9
				acConID = 4
				acUUID = uuid.IID_IWbemServices
			}

			ctxList := rpce.NewPcontextList()
			ctxList.AddContext(rpce.NewPcontextElem(
				acConID,
				rpce.NewPSyntaxID(acUUID, 0),
				[]rpce.PSyntaxID{
					rpce.NewPSyntaxID(uuid.NDRTransferSyntax_V2, 2),
				},
			))
			packetRPC := rpce.NewAlterContextReq(
				acID,
				e.assGroup,
				ctxList,
				nil)
			e.tcpClient.Write(packetRPC.Bytes())
			resp = make([]byte, 2048)
			e.tcpClient.Read(resp)
			e.stage = "Request"

		case "Request":
			nextStage := "Request"
			switch sequence {
			case 0:
				sequence = 1
				callID = 3
				contextID = 2
				opNum = 3
				rqUUID = e.objUUID2
				s, ee := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().String(e.config.clientHostname)
				if ee != nil {
					panic(e)
				}

				hnLen := uint32(len(s) + 1)
				hnBytes := append([]byte(e.config.clientHostname), 0, 0)
				//align to 4 bytes
				align := make([]byte, len(hnBytes)%4)
				hnBytes = append(hnBytes, align...)
				type setClientInfo struct {
					VersionMajor uint16
					VersionMinor uint16
				}
				stubData = []byte{
					0x05, 0x00, //version major
					0x07, 0x00, //version minor
					0x00, 0x00, 0x00, 0x00, //flags
					0x00, 0x00, 0x00, 0x00, //reserved
				}
				stubData = append(stubData, e.causality...) //causality (obviously), which is a 16 byte value

				//extent array? https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/87f24bd8-83dd-49a5-a9e8-bfb1b023abc0
				stubData = append(stubData,
					0, 0, 0, 0, //size?
					0, 0, 2, 0) // ??? reserved??
				hnLenByte := make([]byte, 4)
				binary.LittleEndian.PutUint32(hnLenByte, hnLen)
				//e.log.Infof("hn len %d (%x)", hnLen, hnLenByte)
				stubData = append(stubData, hnLenByte...) //32bit length (assume this is maxlen)
				stubData = append(stubData, 0, 0, 0, 0)   //32 bit nulls (pointer to first value)
				stubData = append(stubData, hnLenByte...) //32bit length (assume this is actuallen)
				stubData = append(stubData, hnBytes...)   //actual name
				//processID
				pid := []byte{0, 0}
				rand.Read(pid)
				stubData = append(stubData, pid...)           //pid (ofc)
				stubData = append(stubData, 0, 0, 0, 0, 0, 0) //6 bytes of null?
				nextStage = "AlterContext"

			case 1:
				sequence = 2
				callID = 4
				contextID = 3
				rqUUID = e.ipid
				stubData = []byte{
					0x05, 0x00, //version major
					0x07, 0x00, //version minor
					0x00, 0x00, 0x00, 0x00, //flags
					0x00, 0x00, 0x00, 0x00, //reserved
				}
				stubData = append(stubData, e.causality...)
				stubData = append(stubData, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

			case 2:
				sequence = 3
				callID = 5
				contextID = 3
				opNum = 6
				rqUUID = e.ipid

				hnVal := fmt.Sprintf(`\\%s\ROOT\CIMV2`, e.targetHostname)
				//hnVal := "\\\\" + e.targetHostname + "\\root\\cimv2"
				wmiNameStr, err := toUnicodeS(hnVal)
				if err != nil {
					return err
				}
				wmiNameUni := []byte(wmiNameStr)
				//append null
				wmiNameUni = append(wmiNameUni, 0, 0)
				//pad to 4 byte alignment duh :-(
				align := make([]byte, len(wmiNameUni)%4)
				wmiNameUni = append(wmiNameUni, align...)

				hnLenByte := make([]byte, 4)
				//len + 1 for appended null (we don't appear to have to include padding here)
				binary.LittleEndian.PutUint32(hnLenByte, uint32(len(hnVal)+1))
				stubData = []byte{
					0x05, 0x00, //version major
					0x07, 0x00, //version minor
					0x00, 0x00, 0x00, 0x00, //flags
					0x00, 0x00, 0x00, 0x00, //reserved
				}
				stubData = append(stubData, e.causality...)
				stubData = append(stubData, 0, 0, 0, 0, 0, 0, 2, 0)
				stubData = append(stubData, hnLenByte...)
				stubData = append(stubData, 0, 0, 0, 0)
				stubData = append(stubData, hnLenByte...)
				stubData = append(stubData, wmiNameUni...)
				stubData = append(stubData, 0x04, 0x00, 0x02, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x2d, 0x00, 0x55, 0x00, 0x53, 0x00, 0x2c, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

			case 3:
				sequence = 4
				contextID = 0
				callID = 6
				opNum = 5
				rqUUID = e.objectUUID
				oxidID := bytes.Index(resp, e.oxid)
				ipid2 = resp[oxidID+16 : oxidID+32]
				pktMemRelease := NewPacketDCOMMemRelease(e.causality, e.objUUID2, e.ipid)
				stubData = pktMemRelease.Bytes()

			case 4:
				sequence = 5
				contextID = 0
				callID = 7
				opNum = 3
				rqUUID = e.objectUUID
				remqry := NewPacketDCOMRemQueryInterface(e.causality, ipid2, []byte{0x9e, 0xc1, 0xfc, 0xc3, 0x70, 0xa9, 0xd2, 0x11, 0x8b, 0x5a, 0x00, 0xa0, 0xc9, 0xb7, 0xc9, 0xc4})
				stubData = remqry.Bytes()

			case 5:
				sequence = 6
				callID = 8
				contextID = 0
				opNum = 3
				rqUUID = e.objectUUID
				nextStage = "AlterContext"
				remqry := NewPacketDCOMRemQueryInterface(e.causality, ipid2, []byte{0x83, 0xb2, 0x96, 0xb1, 0xb4, 0xba, 0x1a, 0x10, 0xb6, 0x9c, 0x00, 0xaa, 0x00, 0x34, 0x1d, 0x07})
				stubData = remqry.Bytes()

			case 6:
				sequence = 7
				callID = 9
				contextID = 4
				opNum = 6
				rqUUID = ipid2
				stubData = []byte{0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
				stubData = append(stubData, e.causality...)
				stubData = append(stubData, 0x00, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x0d, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x77, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5f, 0x00, 0x70, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

			case 7:
				sequence = 8
				callID = 0x10
				contextID = 4
				opNum = 6
				rqUUID = ipid2
				stubData = []byte{0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
				stubData = append(stubData, e.causality...)
				stubData = append(stubData, 0x00, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x0d, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x77, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5f, 0x00, 0x70, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

			default:
				if sequence < 8 {
					return fmt.Errorf("Undefined behaviour in Exec Request. Expected sequence < 8, got %d", sequence)
				}

				sequence = 9
				contextID = 4
				callID = 0x0b
				opNum = 0x18
				rqUUID = ipid2

				commandBytes := []byte(command)
				commandBytes = append(commandBytes, make([]byte, 4-(len(commandBytes)%4))...)

				stubLen := uint16(len(command) + 1769)
				stubLen2 := uint16(len(command) + 1727)
				stubLen3 := uint16(len(command) + 1713)
				commLen := uint16(len(command) + 93)
				commLen2 := uint16(len(command) + 16)

				stubLenB := make([]byte, 2)
				binary.LittleEndian.PutUint16(stubLenB, stubLen)
				stubLen2B := make([]byte, 2)
				binary.LittleEndian.PutUint16(stubLen2B, stubLen2)

				stubLen3B := make([]byte, 2)
				binary.LittleEndian.PutUint16(stubLen3B, stubLen3)
				commLenB := make([]byte, 2)
				binary.LittleEndian.PutUint16(commLenB, commLen)
				commLen2B := make([]byte, 2)
				binary.LittleEndian.PutUint16(commLen2B, commLen2)

				stubData = []byte{0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
				stubData = append(stubData, e.causality...)
				stubData = append(stubData, 0x00, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x0d, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5f, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x06, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x63, 0x00, 0x72, 0x00, 0x65, 0x00, 0x61, 0x00, 0x74, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00)
				stubData = append(stubData, stubLenB...)
				stubData = append(stubData, 0, 0)
				stubData = append(stubData, stubLenB...)
				stubData = append(stubData, 0x00, 0x00, 0x4d, 0x45, 0x4f, 0x57, 0x04, 0x00, 0x00, 0x00, 0x81, 0xa6, 0x12, 0xdc, 0x7f, 0x73, 0xcf, 0x11, 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24, 0x12, 0xf8, 0x90, 0x45, 0x3a, 0x1d, 0xd0, 0x11, 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24, 0x00, 0x00, 0x00, 0x00)
				stubData = append(stubData, stubLen2B...)
				stubData = append(stubData, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12)
				stubData = append(stubData, stubLen3B...)
				stubData = append(stubData, 0x00, 0x00, 0x02, 0x53, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x03, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x15, 0x01, 0x00, 0x00, 0x73, 0x01, 0x00, 0x00, 0x76, 0x02, 0x00, 0x00, 0xd4, 0x02, 0x00, 0x00, 0xb1, 0x03, 0x00, 0x00, 0x15, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x12, 0x04, 0x00, 0x80, 0x00, 0x5f, 0x5f, 0x50, 0x41, 0x52, 0x41, 0x4d, 0x45, 0x54, 0x45, 0x52, 0x53, 0x00, 0x00, 0x61, 0x62, 0x73, 0x74, 0x72, 0x61, 0x63, 0x74, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x4c, 0x69, 0x6e, 0x65, 0x00, 0x00, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, 0x49, 0x6e, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0x00, 0x57, 0x69, 0x6e, 0x33, 0x32, 0x41, 0x50, 0x49, 0x7c, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x20, 0x46, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x7c, 0x6c, 0x70, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x00, 0x00, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0x00, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0x8c, 0x00, 0x00, 0x00, 0x00, 0x49, 0x44, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x59, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0x00, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0x8c, 0x00, 0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x11, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x00, 0x00, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x85, 0x01, 0x00, 0x00, 0x00, 0x49, 0x6e, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x85, 0x01, 0x00, 0x00, 0xac, 0x01, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x57, 0x69, 0x6e, 0x33, 0x32, 0x41, 0x50, 0x49, 0x7c, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x20, 0x46, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x7c, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x7c, 0x6c, 0x70, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x20, 0x00, 0x00, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x85, 0x01, 0x00, 0x00, 0xac, 0x01, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x2b, 0x02, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0xda, 0x01, 0x00, 0x00, 0x00, 0x49, 0x44, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xba, 0x02, 0x00, 0x00, 0xac, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x2b, 0x02, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0xda, 0x01, 0x00, 0x00, 0x72, 0x02, 0x00, 0x00, 0x11, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x53, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xef, 0x02, 0x00, 0x00, 0x00, 0x49, 0x6e, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xef, 0x02, 0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x4c, 0x03, 0x00, 0x00, 0x00, 0x57, 0x4d, 0x49, 0x7c, 0x57, 0x69, 0x6e, 0x33, 0x32, 0x5f, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x53, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x00, 0x00, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xef, 0x02, 0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x66, 0x03, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0x44, 0x03, 0x00, 0x00, 0x00, 0x49, 0x44, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xf5, 0x03, 0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x66, 0x03, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0x44, 0x03, 0x00, 0x00, 0xad, 0x03, 0x00, 0x00, 0x11, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3a, 0x57, 0x69, 0x6e, 0x33, 0x32, 0x5f, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x53, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70)
				stubData = append(stubData, make([]byte, 501)...)
				stubData = append(stubData, commLenB...)
				stubData = append(stubData, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01)
				stubData = append(stubData, commLen2B...)
				stubData = append(stubData, 0x00, 0x80, 0x00, 0x5f, 0x5f, 0x50, 0x41, 0x52, 0x41, 0x4d, 0x45, 0x54, 0x45, 0x52, 0x53, 0x00, 0x00)
				stubData = append(stubData, commandBytes...)
				stubData = append(stubData, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
				if len(stubData) > 5500 {
					return fmt.Errorf("Long request packet not yet implemented. Needed below 5500, got %d", len(stubData))
				}
				nextStage = "Result"
			}

			authv := rpce.NewAuthVerifier(0x0a, 4, 0, make([]byte, 16))
			packetRPC := rpce.NewRequestReq(callID, contextID, opNum, append(rqUUID, stubData...), &authv)
			packetRPC.CommonHead.PFCFlags = 0x83

			messagesig := ntlmssp.NewMessageSignature(packetRPC.AuthBytes(), e.clientSigningKey, sequence)
			authv.AuthValue = messagesig.Bytes()

			wmiSend := packetRPC.Bytes()
			// e.log.Infof("writing stub data (call id %d): %x", callID, packetRPC.StubData[16:])
			// e.log.Infof("Parsed stub data: %+v", parseStub(packetRPC.StubData[16:]))
			// e.log.Infof("unknown portion: (%d) %x", len(parseStub(packetRPC.StubData[16:]).Unknown), parseStub(packetRPC.StubData[16:]).Unknown)
			e.tcpClient.Write(wmiSend)

			//reads 16 bytes
			hdr := rpce.Response{}
			for hdr.CommonHead.PFCFlags&rpce.PFCLastFrag == 0 {
				hbuff := make([]byte, 16)
				n, err := e.tcpClient.Read(hbuff)
				hdr = rpce.ParseResponse(hbuff)
				buff := make([]byte, hdr.CommonHead.FragLength-16)
				n, err = e.tcpClient.Read(buff)
				n = n + 16
				resp = append(hbuff, buff...)
				if err != nil && err == io.EOF {
					e.log.Error("Conn closed BRUH")
					return err
				}

				if uint16(n) < hdr.CommonHead.FragLength {
					buff := make([]byte, hdr.CommonHead.FragLength-uint16(n))
					e.tcpClient.Read(buff)
					resp = append(resp, buff...)
				}
			}
			if nextStage == "Result" {
				if len(resp) > 1145 {
					e.log.Info("PID? ", binary.LittleEndian.Uint16(resp[1141:1145]))
					return nil
				} else {
					e.log.Info("Response shorter than expected... possible error in command? Expected > 1145, got ", len(resp))
					return nil
				}

			}
			e.stage = nextStage

		}
	}

	return nil
}

func WMIExec(target, username, password, hash, domain, command, clientHostname, binding string, cfgIn *WmiExecConfig) error {
	if cfgIn == nil {
		cfg, err := NewExecConfig(username, password, hash, domain, target, clientHostname, true, nil, nil)
		if err != nil {
			return err
		}
		cfgIn = &cfg
	}
	execer := NewExecer(cfgIn)
	err := execer.SetTargetBinding(binding)
	if err != nil {
		return err
	}

	err = execer.Auth()
	if err != nil {
		return err
	}

	if command != "" {
		command = "C:\\Windows\\system32\\cmd.exe /c " + command
		if execer.TargetRPCPort == 0 {
			execer.log.Error("RPC Port is 0, cannot connect")
			return errors.New("RPC Port is 0, cannot connect")
		}

		err = execer.RPCConnect()
		if err != nil {
			return err
		}
		err = execer.Exec(command)
		if err != nil {
			return err
		}
	}

	return nil

}

func toUnicodeS(s string) (string, error) {
	s, e := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder().String(s)
	if e != nil {
		return "", e
	}
	return s, nil
}
