package smb

import (
	"bufio"
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/stacktitan/smb/gss"
	"github.com/stacktitan/smb/ntlmssp"
	"github.com/stacktitan/smb/smb/encoder"
)

type Session struct {
	IsSigningRequired bool
	IsAuthenticated   bool
	securityMode      uint16
	messageID         uint64
	sessionID         uint64
	conn              net.Conn
	dialect           uint16
	options           Options
}

type Options struct {
	Host        string
	Port        int
	Workstation string
	Domain      string
	User        string
	Password    string
	Hash        string
}

func validateOptions(opt Options) error {
	if opt.Host == "" {
		return errors.New("Missing required option: Host")
	}
	if opt.Port < 1 || opt.Port > 65535 {
		return errors.New("Invalid or missing value: Port")
	}
	return nil
}

func NewSession(opt Options) (s *Session, err error) {

	if err := validateOptions(opt); err != nil {
		return nil, err
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", opt.Host, opt.Port))
	if err != nil {
		return
	}

	s = &Session{
		IsSigningRequired: false,
		IsAuthenticated:   false,
		securityMode:      0,
		messageID:         0,
		sessionID:         0,
		dialect:           0,
		conn:              conn,
		options:           opt,
	}

	err = s.NegotiateProtocol()
	if err != nil {
		return
	}

	return s, nil
}

func (s *Session) NegotiateProtocol() error {
	negReq := s.NewNegotiateReq()
	buf, err := s.send(negReq)
	if err != nil {
		return err
	}

	negRes := NewNegotiateRes()
	if err := encoder.Unmarshal(buf, &negRes); err != nil {
		return err
	}

	if negRes.Header.Status != StatusOk {
		return errors.New(fmt.Sprintf("NT Status Error: %d\n", negRes.Header.Status))
	}

	// Check SPNEGO security blob
	spnegoOID, err := gss.ObjectIDStrToInt(gss.SpnegoOid)
	if err != nil {
		return err
	}
	oid := negRes.SecurityBlob.OID
	if !oid.Equal(asn1.ObjectIdentifier(spnegoOID)) {
		return errors.New(fmt.Sprintf(
			"Unknown security type OID [expecting %s]: %s\n",
			gss.SpnegoOid,
			negRes.SecurityBlob.OID))
	}

	// Check for NTLMSSP support
	ntlmsspOID, err := gss.ObjectIDStrToInt(gss.NtLmSSPMechTypeOid)
	if err != nil {
		return err
	}

	hasNTLMSSP := false
	for _, mechType := range negRes.SecurityBlob.Data.MechTypes {
		if mechType.Equal(asn1.ObjectIdentifier(ntlmsspOID)) {
			hasNTLMSSP = true
			break
		}
	}
	if !hasNTLMSSP {
		return errors.New("Server does not support NTLMSSP")
	}

	s.securityMode = negRes.SecurityMode
	s.dialect = negRes.DialectRevision

	// Determine whether signing is required
	mode := uint16(s.securityMode)
	if mode&SecurityModeSigningEnabled > 0 {
		if mode&SecurityModeSigningRequired > 0 {
			s.IsSigningRequired = true
		} else {
			s.IsSigningRequired = false
		}
	} else {
		s.IsSigningRequired = false
	}

	ssreq, err := s.NewSessionSetup1Req()
	if err != nil {
		return err
	}
	ssres, err := NewSessionSetup1Res()
	if err != nil {
		return err
	}
	buf, err = encoder.Marshal(ssreq)
	if err != nil {
		return err
	}

	buf, err = s.send(ssreq)
	if err != nil {
		return err
	}
	encoder.Unmarshal(buf, &ssres)

	challenge := ntlmssp.NewChallenge()
	resp := ssres.SecurityBlob
	encoder.Unmarshal(resp.ResponseToken, &challenge)

	if ssres.Header.Status != StatusMoreProcessingRequired {
		status, _ := StatusMap[negRes.Header.Status]
		return errors.New(fmt.Sprintf("NT Status Error: %s\n", status))
	}
	s.sessionID = ssres.Header.SessionID

	ss2req, err := s.NewSessionSetup2Req()
	if err != nil {
		return err
	}

	auth := ntlmssp.NewAuthenticate(s.options.Domain, s.options.User, s.options.Workstation, s.options.Password, challenge)

	responseToken, err := encoder.Marshal(auth)
	if err != nil {
		return err
	}
	resp2 := ss2req.SecurityBlob
	resp2.ResponseToken = responseToken
	ss2req.SecurityBlob = resp2
	ss2req.Header.Credits = 127
	buf, err = encoder.Marshal(ss2req)
	if err != nil {
		return err
	}

	buf, err = s.send(ss2req)
	if err != nil {
		return err
	}
	var authResp Header
	encoder.Unmarshal(buf, &authResp)
	if authResp.Status != StatusOk {
		status, _ := StatusMap[authResp.Status]
		return errors.New(fmt.Sprintf("NT Status Error: %s\n", status))
	}
	s.IsAuthenticated = true

	return nil
}

func (s *Session) Close() {
	s.conn.Close()
}

func (s *Session) send(req interface{}) (res []byte, err error) {
	buf, err := encoder.Marshal(req)
	if err != nil {
		return nil, err
	}

	b := new(bytes.Buffer)
	if err = binary.Write(b, binary.BigEndian, uint32(len(buf))); err != nil {
		return
	}

	rw := bufio.NewReadWriter(bufio.NewReader(s.conn), bufio.NewWriter(s.conn))
	if _, err = rw.Write(append(b.Bytes(), buf...)); err != nil {
		return
	}
	rw.Flush()

	var size uint32
	if err = binary.Read(rw, binary.BigEndian, &size); err != nil {
		return
	}
	if size > 0x00FFFFFF {
		return nil, errors.New("Invalid NetBIOS Session message")
	}

	data := make([]byte, size)
	l, err := io.ReadFull(rw, data)
	if err != nil {
		return nil, err
	}
	if uint32(l) != size {
		return nil, errors.New("Message size invalid")
	}

	protID := data[0:4]
	switch string(protID) {
	default:
		return nil, errors.New("Protocol Not Implemented")
	case ProtocolSmb2:
	}

	s.messageID++
	return data, nil
}
