package wmiexec

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"errors"
	"io"

	"github.com/C-Sto/goWMIExec/pkg/wmiexec/rpce"

	"github.com/C-Sto/goWMIExec/pkg/wmiexec/uuid"

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
	"golang.org/x/crypto/md4"
	"golang.org/x/text/encoding/unicode"
)

var logger, logerr = zap.NewProduction()
var sugar = logger.Sugar()

type WmiExecConfig struct {
	username, password, hash, domain string
	targetAddress, clientHostname    string

	verbose bool
	logger  *zap.Logger
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
	targetRPCPort    int
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

func (e *wmiExecer) Connect() error {
	var err error

	e.tcpClient, err = net.Dial("tcp", e.config.targetAddress)
	if err != nil {
		e.log.Error(err.Error())
		return err
	}

	defer e.tcpClient.Close()

	//Hello, please are you ok to connect?
	packetRPC := NewPacketRPCBind(2, 0xd016, 2, 0, uuid.IID_IObjectExporter, 0)
	packetRPC.RPCHead.FragLength = 0x0074
	prepBytes := packetRPC.Bytes()
	recv := make([]byte, 2048)
	e.tcpClient.Write(prepBytes)
	e.tcpClient.Read(recv)
	recvHdr := RPCHead{}

	binary.Read(bytes.NewReader(recv), binary.LittleEndian, &recvHdr)

	if recvHdr.PacketType != 12 {
		e.log.Info("No, can't connect soz lol")
		return errors.New("Got an unexpected response. Wanted 12 (0x0c) got ")
	}
	e.log.Info("Successfully connected to host and sent a bind request")

	//cool, can we auth?
	packetRPCReq := NewPacketRPCRequest(3, 0, 0, 0, 02, 0, 0x05, nil)
	copy(prepBytes, make([]byte, len(prepBytes))) //zero the buffer, just in case something dumb is giong on
	prepBytes = packetRPCReq.Bytes()
	e.tcpClient.Write(prepBytes)
	n, err := e.tcpClient.Read(recv)
	if err != nil {
		e.log.Error("Error reading tcp thing")
		return err
	}
	e.log.Info("Successfully connected to host and sent an RPC request packet")
	rsp := NewDCOMResponse(recv[:n])
	resolved := NewDCOMOXIDResolver(rsp.Stub)

	e.log.Infof("Resolved names, all network string bindings for host:")
	for _, x := range resolved.StringBindings {
		//decode for output to user (this should probably be in main... whatever)
		dcoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		b, er := dcoder.Bytes(x.NetworkAddr)
		if er != nil {
			e.log.Error(er.Error())
			continue
		}
		e.log.Infof("\t%v", string(b)) //strs = append(strs, unicode.UTF16( // string(x.NetworkAddr))
	}

	b, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(resolved.StringBindings[0].NetworkAddr)
	if err != nil {
		e.log.Error("Couldn't decode hostname from response")
		return err
	}
	e.log.Info("Using first value as target hostname: ", string(b))
	e.targetHostname = string(b)
	return nil
}

func (e *wmiExecer) Auth() error {
	var err error
	e.tcpClient, err = net.Dial("tcp", e.config.targetAddress)
	if err != nil {
		return err
	}
	defer e.tcpClient.Close()

	//ey, can I please talk to SCM? I will use NTLM SSP to auth..
	packetRPC := NewPacketRPCBind(3, 0xd016, 1, 0x0001, uuid.IID_IRemoteSCMActivator, 0)
	packetRPC.RPCHead.FragLength = 0x0078
	packetRPC.RPCHead.AuthLength = 0x0028
	packetRPC.RPCBindTail.NegotiateFlags = 0xa2088207

	prepBytes := packetRPC.Bytes()
	recv := make([]byte, 2048)
	e.tcpClient.Write(prepBytes)

	lenRead, _ := e.tcpClient.Read(recv)

	index := bytes.Index(recv, []byte("NTLMSSP"))
	nameLen := binary.LittleEndian.Uint16(recv[index+12 : index+14])
	tgtLen := binary.LittleEndian.Uint16(recv[index+40 : index+42])

	ntlmChal := recv[index+24 : index+32]
	deets := recv[index+56+int(nameLen) : index+56+int(nameLen)+int(tgtLen)]
	timebytes := recv[lenRead-12 : lenRead-4]

	//hostname := toUnicodeS("DESKTOP-65V3K18")
	hostname := e.config.clientHostname
	//domain here!
	//username here!
	domain := []byte(e.config.domain)
	uniuser, err := toUnicodeS(e.config.username)
	if err != nil {
		return err
	}
	username := []byte(uniuser)

	key1, err := NTLMV2Hash(e.config.password, string(e.config.hash), e.config.username, string(e.config.domain), e.logProper)
	if err != nil {
		return err
	}

	ntlmResp := NTLMV2Response(key1, ntlmChal, timebytes, deets)
	userOffset := uint32ToBytes(uint32(len(domain) + 64))
	hostOffset := uint32ToBytes(uint32(len(domain) + len(username) + 64))
	lmOffset := uint32ToBytes(uint32(len(domain) + len(username) + len(hostname) + 64))
	ntlmOffset := uint32ToBytes(uint32(len(domain) + len(username) + len(hostname) + 88))
	sessionKeyOffset := uint32ToBytes(uint32(len(domain) + len(username) + len(hostname) + len(ntlmResp) + 88))

	sspResp := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00}
	sspResp = append(sspResp, lmOffset...)
	//these double up as 'maxlen'
	sspResp = append(sspResp, uint16ToBytes(uint16(len(ntlmResp)))...)
	sspResp = append(sspResp, uint16ToBytes(uint16(len(ntlmResp)))...)
	sspResp = append(sspResp, ntlmOffset...)

	sspResp = append(sspResp, uint16ToBytes(uint16(len(domain)))...)
	sspResp = append(sspResp, uint16ToBytes(uint16(len(domain)))...)
	sspResp = append(sspResp, 0x40, 0, 0, 0)

	sspResp = append(sspResp, uint16ToBytes(uint16(len(username)))...)
	sspResp = append(sspResp, uint16ToBytes(uint16(len(username)))...)
	sspResp = append(sspResp, userOffset...)

	sspResp = append(sspResp, uint16ToBytes(uint16(len(hostname)))...)
	sspResp = append(sspResp, uint16ToBytes(uint16(len(hostname)))...)
	sspResp = append(sspResp, hostOffset...)

	//session key length
	sspResp = append(sspResp, 0, 0, 0, 0)
	sspResp = append(sspResp, sessionKeyOffset...)

	//negotiate flags
	sspResp = append(sspResp, 0x15, 0x82, 0x88, 0xa2)

	sspResp = append(sspResp, domain...)
	sspResp = append(sspResp, username...)
	sspResp = append(sspResp, hostname...)
	sspResp = append(sspResp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	sspResp = append(sspResp, ntlmResp...)

	packetAuth := NewPacketRPCAuth3(3, rpce.RPC_C_AUTHN_LEVEL_CONNECT, sspResp)
	prepBytes2 := packetAuth.Bytes()
	e.tcpClient.Write(prepBytes2)

	//lenRead, _ = tcpClient.Read(recv2)

	cause_id_bytes := [16]byte{}
	rand.Seed(time.Now().UnixNano())
	rand.Read(cause_id_bytes[:])

	dcomThing := NewDCOMRemoteInstance(cause_id_bytes, e.config.targetAddress)
	p := NewPacketRPCRequest(0x03, uint16(len(dcomThing.Bytes())), 0, 0, 3, 1, 4, nil)
	prepBytes3 := p.Bytes()
	recv3 := make([]byte, 2048)
	e.tcpClient.Write(append(prepBytes3, dcomThing.Bytes()...))
	lenRead, _ = e.tcpClient.Read(recv3)

	if recv3[2] == 3 {
		pf := PacketFault{}
		binary.Read(bytes.NewReader(recv3), binary.LittleEndian, &pf)
		e.log.Error("Error: ", pf.StatusString(), " ", pf.Status)
		return errors.New(pf.StatusString())
	}

	if recv3[2] == 2 {
		e.log.Info("WMI Access possible!")
	}

	unihn, err := toUnicodeS(e.targetHostname + "[")
	if err != nil {
		return err
	}
	targ := "\x07\x00" + unihn
	tgtIndex := bytes.Index(recv3, []byte(targ))
	portString := recv3[tgtIndex+len(unihn)+2 : tgtIndex+len(unihn)+12]
	s, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().String(string(portString))
	if err != nil {
		return err
	}
	portNum, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	if portNum == 0 {
		e.log.Error("Got portNum 0.")
		return fmt.Errorf("did not expect port number to be 0")
	}

	//meow... MS must have been smoking crack when this was developed
	meowSig, _ := hex.DecodeString("4D454F570100000018AD09F36AD8D011A07500C04FB68820")
	meowIndex := bytes.Index(recv3, meowSig)
	ipid := recv3[meowIndex+48 : meowIndex+64]
	e.oxid = recv3[meowIndex+32 : meowIndex+40]
	oxid2Index := bytes.Index(recv3[meowIndex+100:], e.oxid)
	objUUID := recv3[meowIndex+100+oxid2Index+12 : meowIndex+100+oxid2Index+28]
	e.targetRPCPort = portNum
	e.causality = cause_id_bytes[:]
	e.ipid = ipid
	e.objectUUID = objUUID

	return nil
}

func (e *wmiExecer) RPCConnect() error {
	var err error
	e.log.Infof("Connecting to %s:%d", e.config.targetAddress[:strings.Index(e.config.targetAddress, ":")], e.targetRPCPort)
	e.tcpClient, err = net.Dial("tcp", fmt.Sprintf("%s:%d", e.config.targetAddress[:strings.Index(e.config.targetAddress, ":")], e.targetRPCPort))
	if err != nil {
		e.log.Error("Error: ", err.Error())
		return err
	}
	//lol always open tcp

	bindPacket := NewPacketRPCBind(2, 0x160d, 3, 0, uuid.IID_IRemUnknown2, 0)
	bindPacket.RPCHead.FragLength = 0xd0
	bindPacket.RPCHead.AuthLength = 0x28
	bindPacket.RPCBindTail.NegotiateFlags = 0xa2088297
	prepBytes := bindPacket.Bytes()
	recv := make([]byte, 2048)
	e.tcpClient.Write(prepBytes)
	lenRead, _ := e.tcpClient.Read(recv)

	e.assGroup = binary.LittleEndian.Uint32(recv[20:24])
	index := bytes.Index(recv, []byte("NTLMSSP"))
	nameLen := binary.LittleEndian.Uint16(recv[index+12 : index+14])
	tgtLen := binary.LittleEndian.Uint16(recv[index+40 : index+42])

	ntlmChal := recv[index+24 : index+32]
	deets := recv[index+56+int(nameLen) : index+56+int(nameLen)+int(tgtLen)]
	timebytes := recv[lenRead-12 : lenRead-4]
	hostname := e.config.clientHostname
	domain := []byte(e.config.domain)
	uniuser, err := toUnicodeS(e.config.username)
	if err != nil {
		return err
	}
	username := []byte(uniuser)

	key1, err := NTLMV2Hash(e.config.password, string(e.config.hash), e.config.username, string(e.config.domain), e.logProper)
	if err != nil {
		return err
	}

	ntlmResp := NTLMV2Response(key1, ntlmChal, timebytes, deets)

	userOffset := uint32ToBytes(uint32(len(domain) + 64))
	hostOffset := uint32ToBytes(uint32(len(domain) + len(username) + 64))
	lmOffset := uint32ToBytes(uint32(len(domain) + len(username) + len(hostname) + 64))
	ntlmOffset := uint32ToBytes(uint32(len(domain) + len(username) + len(hostname) + 88))
	sessionKeyOffset := uint32ToBytes(uint32(len(domain) + len(username) + len(hostname) + len(ntlmResp) + 88))

	sspResp := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00}
	sspResp = append(sspResp, lmOffset...)
	//these double up as 'maxlen'
	sspResp = append(sspResp, uint16ToBytes(uint16(len(ntlmResp)))...)
	sspResp = append(sspResp, uint16ToBytes(uint16(len(ntlmResp)))...)
	sspResp = append(sspResp, ntlmOffset...)

	sspResp = append(sspResp, uint16ToBytes(uint16(len(domain)))...)
	sspResp = append(sspResp, uint16ToBytes(uint16(len(domain)))...)
	sspResp = append(sspResp, 0x40, 0, 0, 0)

	sspResp = append(sspResp, uint16ToBytes(uint16(len(username)))...)
	sspResp = append(sspResp, uint16ToBytes(uint16(len(username)))...)
	sspResp = append(sspResp, userOffset...)

	sspResp = append(sspResp, uint16ToBytes(uint16(len(hostname)))...)
	sspResp = append(sspResp, uint16ToBytes(uint16(len(hostname)))...)
	sspResp = append(sspResp, hostOffset...)

	//session key length
	sspResp = append(sspResp, 0, 0, 0, 0)
	sspResp = append(sspResp, sessionKeyOffset...)

	//negotiate flags
	sspResp = append(sspResp, 0x15, 0x82, 0x88, 0xa2)

	sspResp = append(sspResp, domain...)
	sspResp = append(sspResp, username...)
	sspResp = append(sspResp, hostname...)
	sspResp = append(sspResp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	sspResp = append(sspResp, ntlmResp...)

	packetAuth := NewPacketRPCAuth3(2, rpce.RPC_C_AUTHN_LEVEL_PKT, sspResp)

	prepBytes2 := packetAuth.Bytes()
	e.tcpClient.Write(prepBytes2)
	packetRPC := NewPacketRPCRequest(0x83, 76, 16, 4, 2, 0, 3, e.objectUUID)

	packetRemQ := NewPacketDCOMRemQueryInterface(e.causality, e.ipid, uuid.IID_IWbemLoginClientID[:])
	ntlmVer := NewPacketNTLMSSPVerifier(4, 4, 0)
	rpcSign := append([]byte{0, 0, 0, 0}, packetRPC.Bytes()...)
	rpcSign = append(rpcSign, packetRemQ.Bytes()...)
	rpcSign = append(rpcSign, ntlmVer.Bytes()[:12]...)

	mac := hmac.New(md5.New, key1)
	mac.Write(ntlmResp[:mac.Size()])
	sessionBase := mac.Sum(nil)
	//signingConst := "session key to client-to-server signing key magic constant.\x00" //what on earth was MS smoking
	signingConst := []byte{0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x74, 0x6f, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x6f, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x6d, 0x61, 0x67, 0x69, 0x63, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x00}
	md5er := md5.New()
	md5er.Write(append(sessionBase, signingConst...))
	e.clientSigningKey = md5er.Sum(nil)
	md5er.Reset()

	hmacer := hmac.New(md5.New, e.clientSigningKey)
	hmacer.Write(rpcSign)
	sig := hmacer.Sum(nil)[:8]
	copy(ntlmVer.SSPVerifierBody.NTLMSSPVerifierChecksum[:], sig)

	wmiClientSend := append(packetRPC.Bytes(), packetRemQ.Bytes()...)
	wmiClientSend = append(wmiClientSend, ntlmVer.Bytes()...)
	e.tcpClient.Write(wmiClientSend)
	recv3 := make([]byte, 2048)
	lenRead, _ = e.tcpClient.Read(recv3)

	hdr := RPCHead{}
	binary.Read(bytes.NewReader(recv3), binary.LittleEndian, &hdr)
	if recv3[2] == 3 {
		pf := PacketFault{}
		binary.Read(bytes.NewReader(recv3), binary.LittleEndian, &pf)
		//log maybe
		e.log.Error("Error: ", pf.StatusString(), pf.Status)
		return errors.New(pf.StatusString())
	}

	e.objUUID2 = make([]byte, 16)
	if recv3[2] == 2 {
		oxidInd := bytes.Index(recv3, e.oxid)
		e.objUUID2 = recv3[oxidInd+16 : oxidInd+32]
		e.stage = "AlterContext"
	} else {
		return fmt.Errorf("Did not receive expected value. Wanted 2, got %d", recv3[2])
	}

	return nil

}

func (e *wmiExecer) Exec(command string) error {

	sequence := uint32(0)

	var rqFlags byte
	var stubData, ipid2 []byte
	var callID, reqLen uint32
	var contextID, opNum, authPadding uint16
	var rqUUID []byte
	var reqSplit bool
	resp := make([]byte, 2048)
	for e.stage != "exit" {
		if resp[2] == 3 {
			pf := PacketFault{}
			binary.Read(bytes.NewReader(resp), binary.LittleEndian, &pf)
			e.log.Error("Error: ", pf.StatusString(), pf.Status)
			return errors.New(pf.StatusString())
		}
		switch e.stage {
		case "AlterContext":
			acID := uint32(0)
			acConID := uint16(0)
			acUUID := [16]byte{}

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

			packetRPC := NewPacketRPCAlterContext(acID, e.assGroup, acConID, acUUID[:])
			e.tcpClient.Write(packetRPC.Bytes())
			resp = make([]byte, 2048)
			e.tcpClient.Read(resp)
			e.stage = "Request"

		case "Request":
			nextStage := "Request"
			rqFlags = 0x83
			switch sequence {
			case 0:
				sequence = 1
				rqFlags = 0x83
				authPadding = 12
				callID = 3
				contextID = 2
				opNum = 3
				rqUUID = e.objUUID2
				s, ee := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().String(e.config.clientHostname)
				if ee != nil {
					panic(e)
				}

				//this is an extremely gross hack, due to the fact I don't understand how dcom/dcerpc packets need to be formatted for this specific call.
				//there is a weird bug to do with lengths here. awgh and myself spent a long time trying to work out wtf is going on, alas, dcom has beaten us for now
				if len(s) != 15 {
					newName := RandStringBytesMaskImprSrcSB(15)
					ns, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder().String(newName)
					if err != nil {
						panic("why me")
					}
					e.log.Infof("name length not 15, got %d. Converting to %s (was %s)", len(e.config.clientHostname), newName, s)
					e.config.clientHostname = ns
					s = newName
				}

				hnLen := uint32(len(s) + 1)
				hnBytes := append([]byte(e.config.clientHostname), 0, 0)
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
				stubData = append(stubData, hnLenByte...) //32bit length (assume this is maxlen)
				stubData = append(stubData, 0, 0, 0, 0)   //32 bit nulls (pointer to first value)
				stubData = append(stubData, hnLenByte...) //32bit length (assume this is actuallen)
				stubData = append(stubData, hnBytes...)   //actual name
				//processID
				pid := []byte{0, 0}
				rand.Read(pid)
				stubData = append(stubData, pid...)           //pid (ofc)
				stubData = append(stubData, 0, 0, 0, 0, 0, 0) //6 bytes of null?
				e.log.Info("Stub Len: ", len(stubData))
				nextStage = "AlterContext"
				//expected = 64

			case 1:
				sequence = 2
				rqFlags = 0x83
				authPadding = 8
				callID = 4
				contextID = 3
				rqUUID = e.ipid
				stubData = []byte{0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
				stubData = append(stubData, e.causality...)
				stubData = append(stubData, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
				//expected = 64

			case 2:
				sequence = 3
				authPadding = 0
				callID = 5
				contextID = 3
				opNum = 6
				rqUUID = e.ipid
				wminameLen := uint32(len(e.targetHostname) + 14)
				hnLenByte := make([]byte, 4)
				binary.LittleEndian.PutUint32(hnLenByte, wminameLen)
				wmiNameStr, err := toUnicodeS("\\\\" + e.targetHostname + "\\root\\cimv2")
				if err != nil {
					return err
				}
				wmiNameUni := []byte(wmiNameStr)
				wmiNameUni = append(wmiNameUni, 0, 0)

				stubData = []byte{0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
				stubData = append(stubData, e.causality...)
				stubData = append(stubData, 0, 0, 0, 0, 0, 0, 2, 0)
				stubData = append(stubData, hnLenByte...)
				stubData = append(stubData, 0, 0, 0, 0)
				stubData = append(stubData, hnLenByte...)
				stubData = append(stubData, wmiNameUni...)
				stubData = append(stubData, 0x04, 0x00, 0x02, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x2d, 0x00, 0x55, 0x00, 0x53, 0x00, 0x2c, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
				//expected = 256

			case 3:
				sequence = 4
				authPadding = 8
				contextID = 0
				callID = 6
				opNum = 5
				rqUUID = e.objectUUID
				oxidID := bytes.Index(resp, e.oxid)
				ipid2 = resp[oxidID+16 : oxidID+32]
				pktMemRelease := NewPacketDCOMMemRelease(e.causality, e.objUUID2, e.ipid)
				stubData = pktMemRelease.Bytes()
				//expected = 64

			case 4:
				sequence = 5
				authPadding = 4
				contextID = 0
				callID = 7
				opNum = 3
				rqUUID = e.objectUUID
				remqry := NewPacketDCOMRemQueryInterface(e.causality, ipid2, []byte{0x9e, 0xc1, 0xfc, 0xc3, 0x70, 0xa9, 0xd2, 0x11, 0x8b, 0x5a, 0x00, 0xa0, 0xc9, 0xb7, 0xc9, 0xc4})
				stubData = remqry.Bytes()
				//expected = 128

			case 5:
				sequence = 6
				authPadding = 4
				callID = 8
				contextID = 0
				opNum = 3
				rqUUID = e.objectUUID
				nextStage = "AlterContext"
				remqry := NewPacketDCOMRemQueryInterface(e.causality, ipid2, []byte{0x83, 0xb2, 0x96, 0xb1, 0xb4, 0xba, 0x1a, 0x10, 0xb6, 0x9c, 0x00, 0xaa, 0x00, 0x34, 0x1d, 0x07})
				stubData = remqry.Bytes()
				//expected = 128

			case 6:
				sequence = 7
				authPadding = 0
				callID = 9
				contextID = 4
				opNum = 6
				rqUUID = ipid2
				stubData = []byte{0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
				stubData = append(stubData, e.causality...)
				stubData = append(stubData, 0x00, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x0d, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x77, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5f, 0x00, 0x70, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
				//expected = 22064

			case 7:
				sequence = 8
				authPadding = 0
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
				authPadding = 0
				contextID = 4
				callID = 0x0b
				opNum = 0x18
				rqUUID = ipid2

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

				commandBytes := []byte(command)
				if len(command)%4 == 0 {
					commandBytes = append(commandBytes, 0, 0, 0, 0)
				} else {
					commandBytes = append(commandBytes, make([]byte, len(command)%4)...)
				}

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
				rqFlags = 0x83
				nextStage = "Result"
			}

			packetRPC := NewPacketRPCRequest(rqFlags, uint16(len(stubData)), 16, authPadding, callID, contextID, opNum, rqUUID)
			if reqSplit {
				packetRPC.ReqHead.AllocHint = reqLen
			}

			pktNTLMSSP := NewPacketNTLMSSPVerifier(byte(authPadding), 4, sequence)
			rpc := packetRPC.Bytes()
			ntlmsspVer := pktNTLMSSP.Bytes()
			rpcSign := make([]byte, 4)
			binary.LittleEndian.PutUint32(rpcSign, sequence)
			rpcSign = append(rpcSign, rpc...)
			rpcSign = append(rpcSign, stubData...)
			rpcSign = append(rpcSign, ntlmsspVer[:authPadding+8]...)
			hmacer := hmac.New(md5.New, e.clientSigningKey)
			hmacer.Write(rpcSign)
			rpcSig := hmacer.Sum(nil)
			copy(pktNTLMSSP.SSPVerifierBody.NTLMSSPVerifierChecksum[:], rpcSig)
			ntlmsspVer = pktNTLMSSP.Bytes()

			wmiSend := append(rpc, stubData...)
			wmiSend = append(wmiSend, ntlmsspVer...)
			e.tcpClient.Write(wmiSend)

			if reqSplit {
				return fmt.Errorf("Long request packet not yet implemented. Should have errored earlier due to split requirement, stub data len is %d", len(stubData))
			}

			//reads 16 bytes
			hdr := RPCHead{}
			for hdr.PacketFlags&byte(PacketFlagLastFrag) == 0 {
				hbuff := make([]byte, 16)
				n, err := e.tcpClient.Read(hbuff)
				binary.Read(bytes.NewReader(hbuff), binary.LittleEndian, &hdr)
				buff := make([]byte, hdr.FragLength-16)
				n, err = e.tcpClient.Read(buff)
				n = n + 16
				resp = append(hbuff, buff...)
				if err != nil && err == io.EOF {
					e.log.Error("Conn closed BRUH")
					return err
				}

				if uint16(n) < hdr.FragLength {
					buff := make([]byte, hdr.FragLength-uint16(n))
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

func WMIExec(target, username, password, hash, domain, command, clientHostname string, cfgIn *WmiExecConfig) error {
	if cfgIn == nil {
		cfg, err := NewExecConfig(username, password, hash, domain, target, clientHostname, true, nil, nil)
		if err != nil {
			return err
		}
		cfgIn = &cfg
	}
	execer := NewExecer(cfgIn)
	err := execer.Connect()
	if err != nil {
		return err
	}

	err = execer.Auth()
	if err != nil {
		return err
	}

	if command != "" {
		if execer.targetRPCPort == 0 {
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

func uint16ToBytes(v uint16) []byte {
	b := []byte{0, 0}
	binary.LittleEndian.PutUint16(b, v)
	return b
}

func uint32ToBytes(v uint32) []byte {
	b := []byte{0, 0, 0, 0}
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func NTLMV2Response(hash, servChal, timestamp, targetInfo []byte) []byte {

	v := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	v = append(v, timestamp...)
	chal := make([]byte, 8)
	rand.Seed(time.Now().UnixNano())
	rand.Read(chal)
	v = append(v, chal...)
	v = append(v, 0, 0, 0, 0)
	v = append(v, targetInfo...)
	v = append(v, 0, 0, 0, 0, 0, 0, 0, 0)

	mac := hmac.New(md5.New, hash)
	mac.Write(servChal)
	mac.Write(v)
	hmacVal := mac.Sum(nil)
	return append(hmacVal, v...)
}

//NTLMV2Hash returns the NTLMV2 hash provided a password or hash (if both are provided, the hash takes precidence), username and target info
func NTLMV2Hash(password, hash, username, target string, log *zap.Logger) ([]byte, error) {
	if hash == "" {
		h := md4.New()
		unipw, err := toUnicodeS(password)
		if err != nil {
			return nil, err
		}
		h.Write([]byte(unipw))
		hash = hex.EncodeToString(h.Sum(nil))
	}
	log.Sugar().Info("Authenticating with the hash value: ", hash)
	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(md5.New, hashBytes)
	idkman, err := toUnicodeS(strings.ToUpper(username) + target)
	if err != nil {
		return nil, err
	}
	mac.Write([]byte(idkman))
	return mac.Sum(nil), nil
}

func toUnicodeS(s string) (string, error) {
	s, e := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder().String(s)
	if e != nil {
		return "", e
	}
	return s, nil
}

//https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func RandStringBytesMaskImprSrcSB(n int) string {
	rand.NewSource(time.Now().UnixNano())
	sb := strings.Builder{}
	sb.Grow(n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, rand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			sb.WriteByte(letterBytes[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return sb.String()
}
