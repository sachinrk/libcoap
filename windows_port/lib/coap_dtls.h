#ifndef _COAP_DTLS_H_
#define _COAP_DTLS_H_

//
// A very basic dtls implementation for coap.
//

#include "coap_config.h"
#include "net.h"
#include "address.h"


#pragma once

//
// Buffer sizes related to UDP. These values are on basis of assumption/approximation and might change in future.
// Currently, this size is chosen to handle the RDPPayload + DTLS hedaers + Largest ACK Vector theoretically possible
//
#define MAX_UDP_BUFFER_SIZE (1024 * 4)

#define MAX_DTLS_HDR_TRLR_SIZE 96

#define DTLS_HDR_SIZE 29

#define MAX_FEC_HEADER_SIZE 20

#define MAX_RDG_UDP_TRANSPORT_HDR_SIZE 4

#define MAX_UDP_AND_IP_HDR_SIZE 28

#define MAX_ENCRYPTED_UDP_BUFFER_SIZE (MAX_UDP_BUFFER_SIZE + MAX_DTLS_HDR_TRLR_SIZE)

#define MAX_UDP_EXTRA_SIZE 200

#define DTLS_SALT_SIZE 32

#define DTLS_TIMEOUT 500

#define DTLS_MAX_RETRYCOUNT 40

#define NumInputOutputBuffers 4

#define DTLS_SSP_NAME        UNISP_NAME

//
// Encryption level set on a TS server.
//

#define TS_ENCRYPTION_LEVEL_FIRST              0

#define TS_ENCRYPTION_LEVEL_NONE               0
#define TS_ENCRYPTION_LEVEL_LOW                1
#define TS_ENCRYPTION_LEVEL_CLIENT_COMPATIBLE  2
#define TS_ENCRYPTION_LEVEL_HIGH               3
#define TS_ENCRYPTION_LEVEL_FIPS               4

#define TS_ENCRYPTION_LEVEL_LAST               4

#define TS_ENCRYPTION_LEVEL_DEFAULT            TS_ENCRYPTION_LEVEL_LOW

// Maximum supported algorithms by webserver
// Currently 4: RC4, RC2, DES, 3DES, AES-128, AES-256

//
// States through which the DTLS component transitions.
//
typedef enum __DTLSState
{
    DTLSUninitialized = 1,
    DTLSActivated,
    DTLSSendBufferOutAndCallSSPAgain,
    DTLSSendBufferOutAndReceiveAndThenCallSSPAgain,
    DTLSReceiveAndThenCallSSPAgain,
    DTLSDataTransfer,
    DTLSGoBackToHandShakeAndCallSSPAgainWithSameData,
    DTLSProcessSignature,
    DTLSError
} DTLSState;


typedef enum __DTLSSecFilterState
{
    DTLSSFStateDisconnected,
    DTLSSFStateInitialized,
    DTLSSFStateInHandshake,
    DTLSSFStateProcessingData,
    DTLSSFStateDataAvailable
} DTLSSecFilterState;


typedef struct _DTLSStruct
{

    //
    // Credentials handle used during SSPI handshake
    //
    CredHandle m_hCredentials;

    //
    // Name of the Security Support Provider we are using.
    //
    SEC_CHAR* m_SSPName;

    //
    // Is this server?
    //
    BOOL m_Server;

    //
    // The m_Server name.
    //
    SEC_CHAR* m_ServerName;

    //
    // Context handle.
    //
    CtxtHandle m_hContext;

    //
    // SSL stream sizes for use during the encryption and decryption
    // phase: header, maximum message and trailer lengths.
    //
    ULONG m_cbMaxMsgSize;
    ULONG m_cbHeader;
    ULONG m_cbTrailer;

    //
    // The maximum size of a token used during the handshaking phase. Obtained
    // by querying the SChannel package.
    //
    ULONG m_cbMaxHandshakeToken;

    //
    // Buffer which holds raw data received from the network.
    //
    __field_bcount(m_cbInput)
    PBYTE m_pbInput;
    ULONG m_cbInput; // size of the m_pbInput buffer
    __field_range(<=, m_cbInput)
    ULONG m_cbInputData; //amount of the raw data currently in the m_pbInput buffer

    //
    // Buffer which holds processed data.
    //
    __field_bcount(m_cbProcessed)
    BYTE* m_pbProcessed;
    ULONG m_cbProcessed; // size of m_pbProcessed buffer
    __field_range(<=, m_cbProcessed)
    ULONG m_cbProcessedData; // total size of the data in the m_pbProcessed buffer
    __field_range(<=, m_cbProcessedData)
    ULONG m_cbNonConsumedProcessedData; // size of the data in the m_pbProcessed buffer not yet consumed by the caller.

    //
    // Something.
    //
    ULONG m_ulContextFeatures;

    ULONG m_cbMaxBufferSize;

    //
    // m_cbDtlsRecordSize = m_cbMaxMsgSize + m_cbHeader + m_cbTrailer
    //
    ULONG m_cbDtlsRecordSize;

    DTLSState m_dtlsState;
    DTLSSecFilterState m_State;

    //
    // DTLS RFC deals with timeout values. Since SSP does not handle this, it is
    // handled here.
    //
    ULONG     m_uTimeOut;
    ULONG     m_uRetryCount;

    //
    // This is used to indiciate whether the handshake is called for the first time
    // or subsequently
    //
    ULONG     m_uIterationCount;

    //
    // This is used to store the MTU passed as part of Activate call.
    //
    ULONG     m_uInitialMTU;

    //
    // Signature handling - applicable for the client only
    //
    PBYTE m_pbSignature;
    ULONG m_cbSignatureSize;

    //
    // Salt
    //
    //    PBYTE m_pbSalt;
    BYTE m_pbSalt[ DTLS_SALT_SIZE ];
    ULONG m_cbSaltSize;

    //
    // Server cert parameters.
    //

    UINT32 uiSelectedProtocol;
    BYTE  bUserAuthentication;
    BYTE  bEncryptionLevel;

    PCSTR CertSubject;
    PCSTR CertStore;

    PBYTE pHandshakeBLOB;
    ULONG cbHandshakeBLOB;

    BYTE m_dtlsHandshakeRecvPkt[MAX_ENCRYPTED_UDP_BUFFER_SIZE];
    BYTE m_dtlsHandshakeSendPkt[MAX_ENCRYPTED_UDP_BUFFER_SIZE];
} DTLSStruct, *PDTLSStruct;

VOID
InitializeDtlsObject(
    __inout PDTLSStruct DtlsObject
    );

VOID
CleanupDtlsObject(
    PDTLSStruct DtlsObject
    );

HRESULT
InitializeClient(
//    __in PXSECURITY_FILTER_CLIENT_SETTINGS pConfig,
    __in PCSTR wszServerName,
    __in PDTLSStruct DtlsObject,
    BOOL fMutualAuth
    );


HRESULT
InitializeServer(
    __inout PDTLSStruct DtlsObject,
    __in PCSTR CertSubject,
    __in PCSTR CertStoreName
    );

HRESULT
DoDTLSHandshake(
    __in                        BOOL bTimeoutFired,
    __in_bcount_opt(cbIn)       PBYTE  pbIn,
    __in                        ULONG  cbIn,
    __deref_out_ecount(*pcbOut) PBYTE* ppbOut,
    __out                       PULONG pcbOut,
    __out                       PULONG puTimeoutValue,
    __out                       PBOOLEAN pbDone,
    __inout                     PDTLSStruct DtlsObject
    );

HRESULT
AllocateSSPIBuffer(
    __in DWORD dwSize,
    __deref_out_bcount(dwSize) PVOID* ppBuffer
    );

VOID
FreeSSPIBuffer(
    __in PVOID pBuffer
    );

HRESULT
InitializeInputBuffer(
    __inout PDTLSStruct DtlsObject
    );


HRESULT
InitializeProcessedBuffer(
    __inout PDTLSStruct DtlsObject
    );

HRESULT
OnHandshakeCompleted(
    __inout PDTLSStruct DtlsObject
    );

HRESULT
QueryStreamSizes(
    __inout PDTLSStruct DtlsObject
    );

HRESULT
DecryptData(
    __in_bcount(cbIn) PBYTE pbIn,
    ULONG cbIn,
    __inout PDTLSStruct DtlsObject
    );

//
// Encrypts the data in pbDataBuffer in place.
//
HRESULT
EncryptData(
    __inout_bcount_part(*pcbDataBuffer, *pcbDataBuffer) PBYTE pbDataBuffer,
    __inout PULONG pcbDataBuffer,
    ULONG fQOP,
    __inout PDTLSStruct DtlsObject
    );


HRESULT
SetMTU(
    ULONG uMTU,
    __inout PDTLSStruct DtlsObject
    );


HRESULT
ResizeBufferForDataTransfer(
    __inout PDTLSStruct DtlsObject
    );

HRESULT
SendToPeer(
    __in coap_context_t* ctx,
    __inout PBYTE BufferToSend,
    __inout ULONG BytesToSend,
    __in coap_address_t* dst
    );

HRESULT
ReceiveFromPeer(
    __in coap_context_t *ctx,
    __inout PBYTE *Buffer,
    __inout PULONG BufferSize,
    __inout coap_address_t** dst
    );

HRESULT
DTLSFilterInComingData(
    __in_ecount(*pcbInOut) PBYTE pbIn,
    __inout PULONG pcbInOut,
    __deref_out_ecount(*pcbInOut) PBYTE* ppbOut,
    __inout PDTLSStruct DtlsObject
    );


HRESULT
DTLSFilterOutgoingData(
    __in_ecount(*pcbInOut) BYTE* pbIn,
    __inout ULONG* pcbInOut,
    __deref_out_ecount(*pcbInOut) PBYTE* ppbOut,
    __inout PDTLSStruct DtlsObject
    );

coap_tid_t
DTLS_coap_send(
    coap_context_t* context,
    const coap_endpoint_t *local_interface,
    const coap_address_t *dst,
    coap_pdu_t *pdu,
    PDTLSStruct DtlsObject
    );

int
DTLS_coap_read(
    coap_context_t *Context,
    PDTLSStruct DtlsObject
    );


int
DTLS_coap_handle_message(
    coap_context_t *Context,
    unsigned char *coap_message,
    size_t message_length,
    coap_packet_t *packet);

#endif

