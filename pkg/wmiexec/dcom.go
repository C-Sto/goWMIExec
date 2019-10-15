package wmiexec

import (
	"bytes"
	"encoding/binary"
	"math"
)

type PacketDCOMRemoteInstance struct {
	DCOMVersionMajor                                                                                                             uint16
	DCOMVersionMinor                                                                                                             uint16
	DCOMFlags                                                                                                                    uint32
	DCOMReserved                                                                                                                 uint32
	DCOMCausalityID                                                                                                              [16]byte
	Unknown                                                                                                                      uint32
	Unknown2                                                                                                                     uint32
	Unknown3                                                                                                                     uint32
	Unknown4                                                                                                                     uint32
	IActPropertiesCntData                                                                                                        uint32
	IActPropertiesOBJREFSignature                                                                                                uint32
	IActPropertiesOBJREFFlags                                                                                                    uint32
	IActPropertiesOBJREFIID                                                                                                      [16]byte
	IActPropertiesCUSTOMOBJREFCLSID                                                                                              [16]byte
	IActPropertiesCUSTOMOBJREFCBExtension                                                                                        uint32
	IActPropertiesCUSTOMOBJREFSize                                                                                               uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesTotalSize                                                                            uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesReserved                                                                             uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCommonHeader                                                             uint64
	IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderPrivateHeader                                                            uint64
	IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderTotalSize                                                                uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCustomHeaderSize                                                         uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderReserved                                                                 uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesDestinationContext                                                                   uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesNumActivationPropertyStructs                                                         uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesClsInfoClsid                                                                         [16]byte
	IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrReferentID                                                                   uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrReferentID                                                                uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesNULLPointer                                                                          uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrMaxCount                                                                     uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid                                                           [16]byte
	IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid2                                                          [16]byte
	IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid3                                                          [16]byte
	IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid4                                                          [16]byte
	IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid5                                                          [16]byte
	IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid6                                                          [16]byte
	IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrMaxCount                                                                  uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize                                                          uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize2                                                         uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize3                                                         uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize4                                                         uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize5                                                         uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize6                                                         uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesCommonHeader                                        uint64
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPrivateHeader                                       uint64
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesSessionID                                           uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesRemoteThisSessionID                                 uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesClientImpersonating                                 uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionIDPresent                                  uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesDefaultAuthnLevel                                   uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionGuid                                       [16]byte
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesProcessRequestFlags                                 uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesOriginalClassContext                                uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesFlags                                               uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesReserved                                            [32]byte // = 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesUnusedBuffer                                        uint64
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoCommonHeader                                              uint64
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoPrivateHeader                                             uint64
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiatedObjectClsId                                   [16]byte
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoClassContext                                              uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoActivationFlags                                           uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoFlagsSurrogate                                            uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInterfaceIdCount                                          uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiationFlag                                         uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtr                                               uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationEntirePropertySize                                            uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMajor                                                  uint16
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMinor                                                  uint16
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtrMaxCount                                       uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIds                                                  [16]byte
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsUnusedBuffer                                      uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoCommonHeader                                          uint64
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoPrivateHeader                                         uint64
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientOk                                              uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved                                              uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved2                                             uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved3                                             uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrReferentID                                   uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoNULLPtr                                               uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextUnknown                         uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextCntData                         uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFSignature                 uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFFlags                     uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFIID                       [16]byte
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCLSID         [16]byte
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCBExtension   uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFSize          uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoUnusedBuffer                                          [48]byte // = 0x01, 0x00, 0x01, 0x00, 0x63, 0x2c, 0x80, 0x2a, 0xa5, 0xd2, 0xaf, 0xdd, 0x4d, 0xc4, 0xbb, 0x37, 0x4d, 0x37, 0x76, 0xd7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoCommonHeader                                                   uint64
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoPrivateHeader                                                  uint64 //", packet_private_header);
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoAuthenticationFlags                                            uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoPtrReferentID                                        uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoNULLPtr                                                        uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved                                   uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameReferentID                             uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNULLPtr                                    uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved2                                  uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameMaxCount                               uint32 //", packet_target_length);
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameOffset                                 uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameActualCount                            uint32   //", packet_target_length);
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameString                                 [32]byte // uint32//uint", packet_target_unicode);
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoCommonHeader                                                   uint64
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoPrivateHeader                                                  uint64
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoNULLPtr                                                        uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoProcessID                                                      uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoApartmentID                                                    uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoContextID                                                      uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoCommonHeader                                                 uint64
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoPrivateHeader                                                uint64
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoNULLPtr                                                      uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrReferentID                                   uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestClientImpersonationLevel        uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestNumProtocolSequences            uint16
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestUnknown                         uint16
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrReferentID  uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrMaxCount    uint32
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrProtocolSeq uint16
	IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoUnusedBuffer                                                 [6]byte // = 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

}

func NewDCOMRemoteInstance(causality [16]byte, target string) PacketDCOMRemoteInstance {
	r := PacketDCOMRemoteInstance{}

	targetB := []byte(target)
	targetL := uint32(len(targetB)/2) + 1

	b := uint32(math.Trunc(float64(len(targetB))/8+1)*8 - float64(len(targetB)))
	nulls := make([]byte, b)
	targetB = append(targetB, nulls...)

	targetCnt := uint32(len(targetB)) + 720
	pktSize := uint32(len(targetB)) + 680
	pktTotal := uint32(len(targetB)) + 664
	privHeader := uint64(len(targetB) + 40)
	propDataSize := uint32(len(targetB) + 56)

	r.DCOMVersionMajor = 0x05
	r.DCOMVersionMinor = 0x07
	r.DCOMFlags = 0x01
	r.DCOMReserved = 0x00
	r.DCOMCausalityID = causality // packet_causality_ID);
	r.Unknown = 0x00
	r.Unknown2 = 0x00
	r.Unknown3 = 0x020000
	r.Unknown4 = targetCnt                       //", packet_cntdata);
	r.IActPropertiesCntData = targetCnt          //", packet_cntdata);
	r.IActPropertiesOBJREFSignature = 0x574f454d // 0x4d, 0x45, 0x4f, 0x57
	r.IActPropertiesOBJREFFlags = 0x04
	r.IActPropertiesOBJREFIID = [16]byte{0xa2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	r.IActPropertiesCUSTOMOBJREFCLSID = [16]byte{0x38, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	r.IActPropertiesCUSTOMOBJREFCBExtension = 0x00
	r.IActPropertiesCUSTOMOBJREFSize = pktSize                     //", packet_size);
	r.IActPropertiesCUSTOMOBJREFIActPropertiesTotalSize = pktTotal //", packet_total_size);
	r.IActPropertiesCUSTOMOBJREFIActPropertiesReserved = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCommonHeader = 0xcccccccc00081001 // 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc
	r.IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderPrivateHeader = 0xb0              // 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderTotalSize = pktTotal              //", packet_total_size);
	r.IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCustomHeaderSize = 0xc0
	r.IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderReserved = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesDestinationContext = 0x02
	r.IActPropertiesCUSTOMOBJREFIActPropertiesNumActivationPropertyStructs = 0x06
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsInfoClsid = [16]byte{} // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrReferentID = 0x0200
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrReferentID = 0x00020004 //0x04, 0x00, 0x02, 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesNULLPointer = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrMaxCount = 0x06
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid = [16]byte{0xb9, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid2 = [16]byte{0xab, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid3 = [16]byte{0xa5, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid4 = [16]byte{0xa6, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid5 = [16]byte{0xa4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid6 = [16]byte{0xaa, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrMaxCount = 0x06
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize = 0x68
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize2 = 0x58
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize3 = 0x90
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize4 = propDataSize //", packet_property_data_size);
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize5 = 0x20
	r.IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize6 = 0x30
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesCommonHeader = 0xcccccccc00081001 // 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPrivateHeader = 0x58
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesSessionID = 0xffffffff
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesRemoteThisSessionID = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesClientImpersonating = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionIDPresent = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesDefaultAuthnLevel = 0x02
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionGuid = [16]byte{} // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesProcessRequestFlags = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesOriginalClassContext = 0x14
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesFlags = 0x02
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesReserved = [32]byte{} // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesUnusedBuffer = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoCommonHeader = 0xcccccccc00081001 //0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoPrivateHeader = 0x48
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiatedObjectClsId = [16]byte{0x5e, 0xf0, 0xc3, 0x8b, 0x6b, 0xd8, 0xd0, 0x11, 0xa0, 0x75, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20}
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoClassContext = 0x14
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoActivationFlags = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoFlagsSurrogate = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInterfaceIdCount = 0x01
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiationFlag = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtr = 0x0200
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationEntirePropertySize = 0x58
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMajor = 0x05
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMinor = 0x07
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtrMaxCount = 0x01
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIds = [16]byte{0x18, 0xad, 0x09, 0xf3, 0x6a, 0xd8, 0xd0, 0x11, 0xa0, 0x75, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20}
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsUnusedBuffer = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoCommonHeader = 0xcccccccc00081001 // 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoPrivateHeader = 0x80
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientOk = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved2 = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved3 = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrReferentID = 0x0200
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoNULLPtr = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextUnknown = 0x60
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextCntData = 0x60
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFSignature = 0x574f454d // 0x4d, 0x45, 0x4f, 0x57
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFFlags = 0x04
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFIID = [16]byte{0xc0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCLSID = [16]byte{0x3b, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCBExtension = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFSize = 0x30
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoUnusedBuffer = [48]byte{0x01, 0x00, 0x01, 0x00, 0x63, 0x2c, 0x80, 0x2a, 0xa5, 0xd2, 0xaf, 0xdd, 0x4d, 0xc4, 0xbb, 0x37, 0x4d, 0x37, 0x76, 0xd7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoCommonHeader = 0xcccccccc00081001 // 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoPrivateHeader = privHeader        //", packet_private_header);
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoAuthenticationFlags = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoPtrReferentID = 0x0200
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoNULLPtr = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameReferentID = 0x00020004 // 0x04, 0x00, 0x02, 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNULLPtr = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved2 = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameMaxCount = targetL // ", packet_target_length);
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameOffset = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameActualCount = targetL //", packet_target_length);
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameString = [32]byte{}   //", packet_target_unicode);
	copy(r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameString[:], targetB)
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoCommonHeader = 0xcccccccc00081001  //0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoPrivateHeader = 0xcccccccc00081001 //0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoNULLPtr = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoProcessID = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoApartmentID = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoContextID = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoCommonHeader = 0xcccccccc00081001 // 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoPrivateHeader = 0x20
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoNULLPtr = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrReferentID = 0x0200
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestClientImpersonationLevel = 0x02
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestNumProtocolSequences = 0x01
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestUnknown = 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrReferentID = 0x00020004 // 0x04, 0x00, 0x02, 0x00
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrMaxCount = 0x01
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrProtocolSeq = 0x07
	r.IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoUnusedBuffer = [6]byte{}

	return r
}

func (p PacketDCOMRemoteInstance) Bytes() []byte {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.LittleEndian, p)
	return buff.Bytes()
}

type PacketDCOMRemQueryInterface struct {
	VersionMajor uint16
	VersionMinor uint16
	Flags        uint32
	Reserved     uint32
	CausalityID  [16]byte
	Reserved2    uint32
	IPID         [16]byte
	Refs         uint32
	IIDs         uint16
	Unknown      [6]byte
	IID          [16]byte
}

func NewPacketDCOMRemQueryInterface(causalityID, IPID, IID []byte) PacketDCOMRemQueryInterface {
	r := PacketDCOMRemQueryInterface{
		VersionMajor: 5,
		VersionMinor: 7,
		Flags:        0,
		Reserved:     0,
		//CausalityID:
		Reserved2: 0,
		//IPID:
		Refs:    5,
		IIDs:    1,
		Unknown: [6]byte{0, 0, 1, 0, 0, 0},
	}
	copy(r.CausalityID[:], causalityID)
	copy(r.IPID[:], IPID)
	copy(r.IID[:], IID)
	return r
}

func (p PacketDCOMRemQueryInterface) Bytes() []byte {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.LittleEndian, p)
	return buff.Bytes()
}

type PacketDCOMMemRelease struct {
	VersionMajor  uint16
	VersionMinor  uint16
	Flags         uint32
	Reserved      uint32
	CausalityID   [16]byte
	Reserved2     uint32
	Unknown       uint32
	InterfaceRefs uint32
	IPID          [16]byte
	PublicRefs    uint32
	PrivateRefs   uint32
	packetIPID2   [16]byte
	PublicRefs2   uint32
	PrivateRefs2  uint32
}

func NewPacketDCOMMemRelease(causality, ipid, ipid2 []byte) PacketDCOMMemRelease {
	r := PacketDCOMMemRelease{
		VersionMajor: 0x05,
		VersionMinor: 0x07,
		Flags:        0x00,
		Reserved:     0x00,
		//CausalityID:  packet_causality_ID);
		Reserved2:     0x00,
		Unknown:       0x02,
		InterfaceRefs: 0x02,
		//IPID:  packet_IPID);
		PublicRefs:  0x05,
		PrivateRefs: 0x00,
		//packet_IPID2:  packet_IPID2);
		PublicRefs2:  0x05,
		PrivateRefs2: 0x00,
	}

	copy(r.CausalityID[:], causality)
	copy(r.IPID[:], ipid)
	copy(r.packetIPID2[:], ipid2)

	return r
}

func (p PacketDCOMMemRelease) Bytes() []byte {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.LittleEndian, p)
	return buff.Bytes()
}

type DCOMResponse struct {
	RPCHead  RPCHead
	DCOMMeta DCOMMeta
	Stub     []byte
}

type DCOMMeta struct {
	AllocHint   uint32
	ContextID   uint16
	CancelCount uint8
	Empty       byte
}

func NewDCOMResponse(b []byte) DCOMResponse {
	r := DCOMResponse{}
	br := bytes.NewReader(b)
	binary.Read(br, binary.LittleEndian, &r.RPCHead)
	binary.Read(br, binary.LittleEndian, &r.DCOMMeta)
	r.Stub = make([]byte, br.Len())
	br.Read(r.Stub)

	return r
}

type DCOMOXIDResolver struct {
	VersionMajor     uint16
	VersionMinor     uint16
	Unknown          [8]byte
	NumEntries       uint16
	SecurityOffset   uint16
	StringBindings   []DCOMStringBinding
	SecurityBindings []DCOMSecurityBinding
	Unknown2         [8]byte
}

type DCOMSecurityBinding struct {
	AuthnSvc  uint16
	AuthzSvc  uint16
	PrincName []byte
}

type DCOMStringBinding struct {
	TowerId     uint16
	NetworkAddr []byte
}

func NewDCOMOXIDResolver(b []byte) DCOMOXIDResolver {
	r := DCOMOXIDResolver{}
	cursor := 0
	r.VersionMajor = binary.LittleEndian.Uint16(b[cursor : cursor+2])
	cursor += 2
	r.VersionMajor = binary.LittleEndian.Uint16(b[cursor : cursor+2])
	cursor += 2
	copy(r.Unknown[:], b[cursor:cursor+8])
	cursor += 8

	r.NumEntries = binary.LittleEndian.Uint16(b[cursor : cursor+2])
	cursor += 2
	r.SecurityOffset = binary.LittleEndian.Uint16(b[cursor : cursor+2])
	cursor += 2

	for !bytes.HasPrefix(b[cursor:], []byte{0, 0}) {
		newBind := DCOMStringBinding{}
		newBind.TowerId = binary.LittleEndian.Uint16(b[cursor : cursor+2])
		cursor += 2
		//yep, scan to double null top kek
		if bytes.HasPrefix(b[cursor:], []byte{0, 0}) {
			newBind.NetworkAddr = []byte{0, 0}
			cursor += 2
		} else {
			end := bytes.Index(b[cursor:], []byte{0, 0, 0})
			newBind.NetworkAddr = b[cursor : end+cursor+1]
			cursor += end + 3
		}
		r.StringBindings = append(r.StringBindings, newBind)
	}
	cursor += 2

	for !bytes.HasPrefix(b[cursor:], []byte{0, 0}) {
		newBind := DCOMSecurityBinding{}
		newBind.AuthnSvc = binary.LittleEndian.Uint16(b[cursor : cursor+2])
		cursor += 2
		newBind.AuthzSvc = binary.LittleEndian.Uint16(b[cursor : cursor+2])
		cursor += 2
		//yep, scan to double null top kek
		if bytes.HasPrefix(b[cursor:], []byte{0, 0}) {
			newBind.PrincName = []byte{0, 0}
			cursor += 2
		} else {
			end := bytes.Index(b[cursor:], []byte{0, 0, 0})
			newBind.PrincName = b[cursor : end+cursor]
			cursor += end + 1
		}
		r.SecurityBindings = append(r.SecurityBindings, newBind)
	}
	cursor += 2

	return r
}
