//go:build windows

package smb

import (
	"encoding/asn1"
	"errors"
	"syscall"
	"unsafe"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/kerberos"
)

const secPkgAttrSessionKey = 9

type secPkgContextSessionKey struct {
	SessionKeyLength uint32
	SessionKey       *byte
}

type sspiKrb5Initiator struct {
	targetSPN string
	creds     *sspi.Credentials
	ctx       *sspi.Context
	nameBuf   []uint16
	namePtr   *uint16
	seqNum    uint32
	sessKey   []byte
}

func newSSPIKrb5Initiator(targetSPN string) (*sspiKrb5Initiator, error) {
	creds, err := kerberos.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, err
	}
	nameBuf, err := syscall.UTF16FromString(targetSPN)
	if err != nil {
		creds.Release()
		return nil, err
	}
	return &sspiKrb5Initiator{
		targetSPN: targetSPN,
		creds:     creds,
		nameBuf:   nameBuf,
		namePtr:   &nameBuf[0],
	}, nil
}

func (i *sspiKrb5Initiator) OID() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
}

func (i *sspiKrb5Initiator) InitSecContext() ([]byte, error) {
	output := make([]byte, kerberos.PackageInfo.MaxToken)
	i.ctx = sspi.NewClientContext(i.creds, sspi.ISC_REQ_MUTUAL_AUTH|sspi.ISC_REQ_INTEGRITY|sspi.ISC_REQ_CONFIDENTIALITY|sspi.ISC_REQ_USE_SESSION_KEY)
	authDone, n, err := i.updateContext(output, nil)
	if err != nil {
		return nil, err
	}
	if n == 0 && !authDone {
		return nil, errors.New("kerberos token should not be empty")
	}
	return output[:n], nil
}

func (i *sspiKrb5Initiator) AcceptSecContext(token []byte) ([]byte, error) {
	output := make([]byte, kerberos.PackageInfo.MaxToken)
	authDone, n, err := i.updateContext(output, token)
	if err != nil {
		return nil, err
	}
	if authDone {
		if err := i.ctx.VerifySelectiveFlags(sspi.ISC_REQ_INTEGRITY | sspi.ISC_REQ_USE_SESSION_KEY); err != nil {
			return nil, err
		}
		if err := i.querySessionKey(); err != nil {
			return nil, err
		}
	}
	return output[:n], nil
}

func (i *sspiKrb5Initiator) Sum(data []byte) []byte {
	if i.ctx == nil {
		return nil
	}
	_, maxSignature, _, _, err := i.ctx.Sizes()
	if err != nil || maxSignature == 0 {
		return nil
	}

	var buffers [2]sspi.SecBuffer
	buffers[0].Set(sspi.SECBUFFER_DATA, data)
	buffers[1].Set(sspi.SECBUFFER_TOKEN, make([]byte, maxSignature))
	ret := sspi.MakeSignature(i.ctx.Handle, 0, sspi.NewSecBufferDesc(buffers[:]), i.seqNum)
	if ret != sspi.SEC_E_OK {
		return nil
	}
	return buffers[1].Bytes()
}

func (i *sspiKrb5Initiator) SessionKey() []byte {
	if i.ctx != nil {
		i.ctx.Release()
		i.ctx = nil
	}
	if i.creds != nil {
		i.creds.Release()
		i.creds = nil
	}
	return i.sessKey
}

func (i *sspiKrb5Initiator) updateContext(dst, src []byte) (bool, int, error) {
	var inBuf [1]sspi.SecBuffer
	inBuf[0].Set(sspi.SECBUFFER_TOKEN, src)
	inBufs := &sspi.SecBufferDesc{Version: sspi.SECBUFFER_VERSION, BuffersCount: 1, Buffers: &inBuf[0]}

	var outBuf [1]sspi.SecBuffer
	outBuf[0].Set(sspi.SECBUFFER_TOKEN, dst)
	outBufs := &sspi.SecBufferDesc{Version: sspi.SECBUFFER_VERSION, BuffersCount: 1, Buffers: &outBuf[0]}

	ret := i.ctx.Update(i.namePtr, outBufs, inBufs)
	switch ret {
	case sspi.SEC_E_OK:
		return true, int(outBuf[0].BufferSize), nil
	case sspi.SEC_I_COMPLETE_NEEDED, sspi.SEC_I_COMPLETE_AND_CONTINUE:
		ret = sspi.CompleteAuthToken(i.ctx.Handle, outBufs)
		if ret != sspi.SEC_E_OK {
			return false, 0, ret
		}
	case sspi.SEC_I_CONTINUE_NEEDED:
	default:
		return false, 0, ret
	}
	return false, int(outBuf[0].BufferSize), nil
}

func (i *sspiKrb5Initiator) querySessionKey() error {
	var key secPkgContextSessionKey
	ret := sspi.QueryContextAttributes(i.ctx.Handle, secPkgAttrSessionKey, (*byte)(unsafe.Pointer(&key)))
	if ret != sspi.SEC_E_OK {
		return ret
	}
	defer sspi.FreeContextBuffer(key.SessionKey)
	if key.SessionKeyLength == 0 || key.SessionKey == nil {
		return errors.New("SSPI returned an empty Kerberos session key")
	}
	i.sessKey = append([]byte(nil), unsafe.Slice(key.SessionKey, int(key.SessionKeyLength))...)
	return nil
}
