
#include "coap_dtls.h"
#include "mem.h"
#include "debug.h"


HRESULT
AllocateSSPIBuffer(
    __in DWORD dwSize,
    __deref_out_bcount(dwSize) PVOID* ppBuffer
    )
{
    HRESULT  hr = E_NOTIMPL;

    *ppBuffer = NULL;

    *ppBuffer = coap_malloc(dwSize);

    if (*ppBuffer == NULL)
    {
        hr = E_OUTOFMEMORY;
    }
    else
    {
        hr = S_OK;
    }

    return hr;
}

VOID
FreeSSPIBuffer(
    __in PVOID pBuffer
    )
{
    coap_free(pBuffer);
}


HRESULT
GetSchannelCred(
    __in PCSTR CertSubject,
    __in PCSTR CertStoreName,
    __in DWORD dwStoreLocation,
    __out PDWORD pdwCredFormat,
    __deref_out PVOID* ppaCred
    )
{
    HRESULT hr = E_NOTIMPL;
    PCCERT_CONTEXT* ppCertContext = NULL;
    HCERTSTORE hCertStore = NULL;
    PCWSTR CertSubjectW = L"www.sslbullet.com";

    *ppaCred = NULL;

    hr = AllocateSSPIBuffer(sizeof(PCCERT_CONTEXT), (PVOID*)&ppCertContext);

    if (FAILED(hr))
    {
        debug("AllocateSSPIBuffer");
        goto exit;
    }

    ppCertContext[0] = NULL;


    //
    // Attempt to open the certificate store to search for the certificate.
    //
    hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A,
                               0,
                               0,
                               CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | dwStoreLocation,
                               CertStoreName);

    if (hCertStore == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto exit;
    }

    //
    // We have opened a store, so perform the search.
    //

    ppCertContext[0] = CertFindCertificateInStore(hCertStore,
                                                  X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                  0,
                                                  CERT_FIND_SUBJECT_STR_A,
                                                  CertSubject,
                                                  NULL);

    if (ppCertContext[0] == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto exit;
    }

    *ppaCred = (PVOID)ppCertContext;
    *pdwCredFormat = SCH_CRED_FORMAT_CERT_CONTEXT;

exit:

    if (FAILED(hr))
    {
        if (ppCertContext != NULL)
        {
            FreeSSPIBuffer((PVOID)ppCertContext);
        }

    }

    if (hCertStore)
    {
        CertCloseStore(hCertStore, 0);
    }

    return hr;
}


HRESULT
FreeSchannelCred(
        __in PVOID paCred
        )
{
    PCCERT_CONTEXT* ppCertContext = (PCCERT_CONTEXT*)paCred;

    //This function does not return errors.
    CertFreeCertificateContext( ppCertContext[0] );

    FreeSSPIBuffer( paCred );

    return S_OK;

}


HRESULT
AllocateAndCopySSPIString(
    __in PCSTR szSource,
    __deref_out SEC_CHAR** ppTarget
    )
{
    HRESULT  hr = E_NOTIMPL;
    PSTR  pTarget = NULL;
    size_t cbTargetSize = 0;

    *ppTarget = (SEC_CHAR*)NULL;

    hr = StringCbLength(szSource, MAX_PATH * sizeof(WCHAR), &cbTargetSize);

    if (FAILED(hr))
    {
        debug("StringCchLength");
        goto exit;
    }

    cbTargetSize += sizeof(WCHAR);

    hr = AllocateSSPIBuffer((DWORD)cbTargetSize, (PVOID*)&pTarget);

    if (FAILED(hr))
    {
        debug("AllocateSSPIBuffer");
        goto exit;
    }

    hr = StringCbCopy(pTarget, cbTargetSize, szSource);

    if (FAILED(hr))
    {
        debug("StringCbCopy");
        goto exit;
    }

    *ppTarget = pTarget;

exit:

    if (FAILED(hr) && pTarget != NULL)
    {
        FreeSSPIBuffer(pTarget);
    }

    return hr;
}


HRESULT
InitializeInputBuffer(
    __inout PDTLSStruct DtlsObject
    )
{
    HRESULT hr = E_NOTIMPL;
    PSecPkgInfo pSecPkgInfo;

    if(DtlsObject->m_pbInput)
    {
        free(DtlsObject->m_pbInput);
        DtlsObject->m_pbInput = NULL;
    }

    DtlsObject->m_cbInputData = 0;

    //
    // Determine the maximum size needed to hold a token used during the
    // DTLS handshake.
    //
    hr = QuerySecurityPackageInfo(DTLS_SSP_NAME, &pSecPkgInfo);

    if (FAILED(hr))
    {
        debug("QuerySecurityPackageInfo");
        goto exit;
    }

    DtlsObject->m_cbMaxHandshakeToken = pSecPkgInfo->cbMaxToken;

    //TODO: For now CredSSP cannot tell exactly how much space does in need for
    //a handshake token (it depends on encryption algorithms used).
    //So we add a 2K padding to be on the safe side.
    //We need to remove this when CredSSP is fixed.
    DtlsObject->m_cbMaxHandshakeToken += 2048;

    //
    // Use the maximum handshake token size for now. When the handshake is
    // complete we will reallocate based on the largest message size we
    // will receive.
    //
    DtlsObject->m_cbInput = DtlsObject->m_cbMaxHandshakeToken;
    DtlsObject->m_pbInput = malloc(DtlsObject->m_cbInput);

    if (DtlsObject->m_pbInput == NULL)
    {
        hr = E_OUTOFMEMORY;

        if (FAILED(hr))
        {
            debug("memory allocation");
            goto exit;
        }
    }

    hr = S_OK;

exit:

    if (pSecPkgInfo)
    {
          FreeContextBuffer(pSecPkgInfo);
    }

    return hr;

}


HRESULT
InitializeProcessedBuffer(
    __inout PDTLSStruct DtlsObject
    )
{
    HRESULT hr = E_NOTIMPL;

    //We need to add this padding because WD expects the buffer
    // to have some extra space.
    //TODO: 1. Fix WD so it won't require bigger buffer
    const ULONG cbPadding = 512;

    if(DtlsObject->m_pbProcessed)
    {
        free(DtlsObject->m_pbProcessed);
        DtlsObject->m_pbProcessed = NULL;
    }

    DtlsObject->m_cbProcessedData = 0;
    DtlsObject->m_cbNonConsumedProcessedData = 0;

    //
    // We need buffer twice as large as the maximum message size for the current protocol.
    // Thus, we will be able to accept up to maximum message size of data in one call to
    // FilterIncomingData().
    //
    //
    // Adding the max size of the trailer (m_cbTrailer) to the buffer size to make sure,
    // that we can process all the data a caller puts into our internal input buffer (m_pbInput).
    // The size of m_pbInput buffer is (m_cbMaxMsgSize + m_cbHeader + m_cbTrailer) * 2.
    // The header and the trailer are removed from the processed data.
    // The header size is fixed, but the actual trailer size is usually less than m_cbTrailer.
    // Thus, to be on the safe side we have to assume that the size of processed data can be up to
    // (m_cbMaxMsgSize + m_cbTrailer) * 2.
    //
    DtlsObject->m_cbProcessed = (DtlsObject->m_cbMaxMsgSize + DtlsObject->m_cbTrailer) * 2;
    DtlsObject->m_pbProcessed = malloc(DtlsObject->m_cbProcessed + cbPadding);

    if (DtlsObject->m_pbProcessed == NULL)
    {
        hr = E_OUTOFMEMORY;
        debug("memory allocation");
        goto exit;
    }

    hr = S_OK;

exit:

    return hr;
}


HRESULT
QueryStreamSizes(
    __inout PDTLSStruct DtlsObject
    )
{
    HRESULT hr = S_OK;
    SECURITY_STATUS secStatus = SEC_E_OK;
    SecPkgContext_StreamSizes secPkgSizes = { 0 };

    DtlsObject->m_cbMaxMsgSize = 0;
    DtlsObject->m_cbHeader = 0;
    DtlsObject->m_cbTrailer = 0;

    secStatus = QueryContextAttributes(&DtlsObject->m_hContext,
                                       SECPKG_ATTR_DATAGRAM_SIZES,
                                       (VOID*) &secPkgSizes);

    if (SEC_E_OK != secStatus)
    {
        hr = HRESULT_FROM_WIN32(secStatus);
        goto exit;
    }
    else
    {
        hr = S_OK;
    }

    DtlsObject->m_cbMaxMsgSize = secPkgSizes.cbMaximumMessage;
    DtlsObject->m_cbHeader = secPkgSizes.cbHeader;
    DtlsObject->m_cbTrailer = secPkgSizes.cbTrailer;

exit:

    return hr;

}


HRESULT
InitializeClientDTLSCredentials(
    __deref_out PVOID* ppCreds
    )
{
    HRESULT         hr = S_OK;
    PSCHANNEL_CRED  pDTLSCreds = NULL;

    PVOID pCert = NULL;
    //DWORD dwCredFormat;

    hr = AllocateSSPIBuffer(sizeof(SCHANNEL_CRED), (PVOID*)&pDTLSCreds);

    if (FAILED(hr))
    {
        debug("m_pHelper->AllocateSSPIBuffer");
        goto exit;
    }

    RtlZeroMemory(pDTLSCreds, sizeof(SCHANNEL_CRED));

    pDTLSCreds->dwVersion = SCHANNEL_CRED_VERSION;
    pDTLSCreds->grbitEnabledProtocols = SP_PROT_DTLS1_0;

    pDTLSCreds->dwFlags = SCH_CRED_NO_DEFAULT_CREDS |
                          SCH_CRED_NO_SERVERNAME_CHECK |
                          SCH_CRED_MANUAL_CRED_VALIDATION;

    *ppCreds = pDTLSCreds;

exit:

    if (FAILED(hr))
    {
        if (pDTLSCreds)
        {
            FreeSSPIBuffer(pDTLSCreds);
        }
    }

    return hr;
}


HRESULT
InitializeServerDTLSCredentials(
    __in PDTLSStruct DtlsObject,
    __deref_out PVOID* ppDTLSCreds
    )
{
    HRESULT hr = E_NOTIMPL;
    PSCHANNEL_CRED pDTLSCreds = NULL;

    CONST ALG_ID rgAlgsFips[] = {//CALG_RC4,
                                 //CALG_RC2,
                                 CALG_DES,
                                 CALG_3DES,
                                 CALG_AES_128,
                                 CALG_AES_256};

    CONST DWORD cAlgsFips = sizeof(rgAlgsFips) / sizeof(ALG_ID);
    ALG_ID* pAlgs = NULL;
    DWORD cAlgs = 0;
    PVOID pCert = NULL;
    DWORD dwCredFormat;

    *ppDTLSCreds = NULL;

    //
    // Now get the server DTLS certificate by using the certificate
    // subject name.
    //
    hr = GetSchannelCred(DtlsObject->CertSubject,
                         DtlsObject->CertStore,
                         CERT_SYSTEM_STORE_LOCAL_MACHINE,
                         &dwCredFormat,
                         &pCert);

    if (FAILED(hr))
    {
        debug("GetSchannelCred");
        goto exit;
    }

    //
    // If the encryption level is set to FIPS, use FIPS-compliant algorithms.
    // This is done automatically by Schannel if the system-wide FIPS registry
    // key in LSA is set, however if FIPS is just set for TS, we must do it
    // manually. BTW 4 is the encryption level for FIPS.
    //

    hr = AllocateSSPIBuffer(sizeof(rgAlgsFips), (PVOID*)&pAlgs);

    if (FAILED(hr))
    {
        debug("AllocateSSPIBuffer");
        goto exit;
    }

    RtlCopyMemory( pAlgs, rgAlgsFips, sizeof(rgAlgsFips) );

    cAlgs = cAlgsFips;

    //
    // Initialize the DTLS credentials.
    //

    hr = AllocateSSPIBuffer(sizeof(SCHANNEL_CRED), (PVOID*)&pDTLSCreds);

    if (FAILED(hr))
    {
        debug("AllocateSSPIBuffer");
        goto exit;
    }

    RtlZeroMemory(pDTLSCreds, sizeof(SCHANNEL_CRED));

    pDTLSCreds->dwVersion = SCHANNEL_CRED_VERSION;
    pDTLSCreds->dwCredFormat = dwCredFormat;

    //
    // Allow SChannel to select the DTLS protocol version.
    //
    pDTLSCreds->grbitEnabledProtocols = SP_PROT_DTLS1_0;

    pDTLSCreds->cCreds = 1;
    pDTLSCreds->paCred = (PCCERT_CONTEXT *)pCert;

    pDTLSCreds->palgSupportedAlgs = pAlgs;
    pDTLSCreds->cSupportedAlgs = cAlgsFips;

    //
    // If we are using the high encryption level, we enforce that the
    // key length must be at least 128 bits.
    //
    if (DtlsObject->bEncryptionLevel == TS_ENCRYPTION_LEVEL_HIGH )
    {
        pDTLSCreds->dwMinimumCipherStrength = 128;
    }

    *ppDTLSCreds = (PVOID)pDTLSCreds;

exit:

    if (FAILED(hr))
    {
        if (pAlgs)
        {
            FreeSSPIBuffer(pAlgs);
        }
        if (pCert)
        {
            FreeSchannelCred(pCert);
        }
        if (pDTLSCreds)
        {
            FreeSSPIBuffer(pDTLSCreds);
        }
    }

    return hr;
}


HRESULT
InitializeClient(
    __in PCSTR wszServerName,
    __in PDTLSStruct DtlsObject,
    BOOL fMutualAuth
    )
{
    HRESULT hr = E_NOTIMPL;
    PVOID pCreds = NULL;
    SECURITY_STATUS secStatus = SEC_E_OK;

    UNREFERENCED_PARAMETER(fMutualAuth);

    if( wszServerName != NULL )
    {
        hr = AllocateAndCopySSPIString(wszServerName, &DtlsObject->m_ServerName);

        if (FAILED(hr))
        {
            debug("AllocateAndCopySSPIString");
            goto exit;
        }
    }
    else
    {
        hr = E_FAIL;
        goto exit;
    }

    DtlsObject->m_Server = FALSE;

    hr = InitializeClientDTLSCredentials(&pCreds);

    if (FAILED(hr))
    {
        debug("InitializeClientDTLSCredentials");
        goto exit;
    }

    secStatus = AcquireCredentialsHandle(NULL,                   // Not used with Schannel.
                                         DTLS_SSP_NAME,
                                         SECPKG_CRED_OUTBOUND,   // client
                                         NULL,                   // Not used with Schannel.
                                         pCreds,              // Protocol to use and customizable features.
                                         NULL,                // Not used with Schannel.
                                         NULL,                // Not used with Schannel.
                                         &DtlsObject->m_hCredentials,     // Receives the requested credential handle
                                         NULL);                 // XP gets certificate expiration, downlevel gets zero.

    if (SEC_E_OK != secStatus)
    {
        debug("DtlsAcquireCredentialsHandle");
        hr = HRESULT_FROM_WIN32(secStatus);
        goto exit;;
    }

    //
    // Set up the features that we desire from the security context.
    //
    DtlsObject->m_ulContextFeatures = ISC_REQ_REPLAY_DETECT   |
                                      ISC_REQ_SEQUENCE_DETECT |
                                      ISC_REQ_CONFIDENTIALITY |
                                      ISC_REQ_DATAGRAM        | // Datagram is used for DTLS
                                      ISC_REQ_ALLOCATE_MEMORY |
                                      ISC_REQ_EXTENDED_ERROR;

    //
    // Determine how much space is needed for the input buffer and then
    // allocate it.
    //
    hr = InitializeInputBuffer(DtlsObject);

    if (FAILED(hr))
    {
        debug("InitializeInputBuffer");
        goto exit;
    }

    DtlsObject->m_dtlsState = DTLSActivated;
    DtlsObject->m_uInitialMTU = MAX_UDP_BUFFER_SIZE;

exit:

    if (pCreds != NULL)
    {
        FreeSSPIBuffer(pCreds);
    }

    return hr;
} // Initialize


HRESULT
InitializeServer(
    __inout PDTLSStruct DtlsObject,
    __in PCSTR CertSubject,
    __in PCSTR CertStoreName
    )
{
    HRESULT hr = E_NOTIMPL;
    SECURITY_STATUS secStatus = SEC_E_OK;
    PVOID pDTLSCreds = NULL;

    //
    // Set up the features that we desire from the security context.
    //
    DtlsObject->m_ulContextFeatures = ASC_REQ_REPLAY_DETECT |
                                      ASC_REQ_SEQUENCE_DETECT |
                                      ASC_REQ_CONFIDENTIALITY |
                                      ASC_REQ_DATAGRAM        | // Datagram is used for DTLS
                                      ASC_REQ_ALLOCATE_MEMORY |
                                      ASC_REQ_EXTENDED_ERROR;

    DtlsObject->CertSubject = CertSubject;
    DtlsObject->CertStore = CertStoreName;

    hr = InitializeServerDTLSCredentials(DtlsObject, &pDTLSCreds);

    if (FAILED(hr))
    {
        debug("InitializeCredentials");
        goto exit;
    }

    //
    // Acquire a credentials handle.
    //
    secStatus = AcquireCredentialsHandle(NULL,                // Not used with Schannel.
                                         DTLS_SSP_NAME,
                                         SECPKG_CRED_INBOUND, // server
                                         NULL,                // Not used with Schannel.
                                         pDTLSCreds,           // Protocol to use and customizable features.
                                         NULL,                // Not used with Schannel.
                                         NULL,                // Not used with Schannel.
                                         &DtlsObject->m_hCredentials,     // Receives the requested credential handle
                                         NULL);                // XP gets certificate expiration, downlevel gets zero.

    if (SEC_E_OK != secStatus)
    {
        hr = HRESULT_FROM_WIN32(secStatus);

        if (FAILED(hr))
        {
            debug("DtlsAcquireCredentialsHandle");
            goto exit;
        }
    }

    hr = InitializeInputBuffer(DtlsObject);

    if (FAILED(hr))
    {
        debug("InitializeInputBuffer");
        goto exit;
    }

    DtlsObject->m_dtlsState = DTLSActivated;
    DtlsObject->m_uInitialMTU = MAX_UDP_BUFFER_SIZE;

exit:

    if (pDTLSCreds != NULL)
    {
        PSCHANNEL_CRED pCreds = (PSCHANNEL_CRED)pDTLSCreds;

        if(pCreds->paCred != NULL)
        {
            FreeSchannelCred((PVOID)pCreds->paCred);
        }

        if (pCreds->palgSupportedAlgs != NULL )
        {
            FreeSSPIBuffer(pCreds->palgSupportedAlgs);
        }

        FreeSSPIBuffer(pDTLSCreds);
    }

    return hr;

}



VOID
InitializeDtlsObject(
    __inout PDTLSStruct DtlsObject
    )
{
    DtlsObject->m_Server = TRUE;

    DtlsObject->m_ServerName = NULL;

    SecInvalidateHandle(&DtlsObject->m_hCredentials);
    SecInvalidateHandle(&DtlsObject->m_hContext);

    DtlsObject->m_pbInput = NULL;
    DtlsObject->m_cbInput = 0;
    DtlsObject->m_cbInputData = 0;

    DtlsObject->m_pbProcessed = NULL;
    DtlsObject->m_cbProcessed = 0;
    DtlsObject->m_cbProcessedData = 0;
    DtlsObject->m_cbNonConsumedProcessedData = 0;

    DtlsObject->m_State = DTLSSFStateDisconnected;

    DtlsObject->m_ulContextFeatures = 0;

    DtlsObject->m_cbMaxMsgSize = 0;
    DtlsObject->m_cbHeader = 0;
    DtlsObject->m_cbTrailer = 0;
    DtlsObject->m_cbMaxHandshakeToken = 0;

    DtlsObject->m_cbDtlsRecordSize = 0;

    DtlsObject->m_cbMaxBufferSize = 0;

    // don't ZeroMemory on m_pbSalt, keep it random.
    // TODO initialize m_pbSalt to unique
    DtlsObject->m_cbSaltSize = DTLS_SALT_SIZE;

    DtlsObject->m_uTimeOut = DTLS_TIMEOUT;
    DtlsObject->m_uRetryCount = 0;

    // DtlsObject->bEncryptionLevel = TS_ENCRYPTION_LEVEL_FIPS;
}


VOID
CleanupDtlsObject(
    PDTLSStruct DtlsObject
    )
{

    if (SecIsValidHandle(&DtlsObject->m_hCredentials))
    {
        FreeCredentialsHandle(&DtlsObject->m_hCredentials);
    }

    if (SecIsValidHandle(&DtlsObject->m_hContext))
    {
        DeleteSecurityContext(&DtlsObject->m_hContext);
    }

    if (DtlsObject->m_pbInput != NULL)
    {
        free(DtlsObject->m_pbInput);
        DtlsObject->m_pbInput = NULL;
    }

    if (DtlsObject->m_pbProcessed != NULL)
    {
        free(DtlsObject->m_pbProcessed);
        DtlsObject->m_pbProcessed = NULL;
    }

    if (DtlsObject->m_ServerName != NULL)
    {
        FreeSSPIBuffer(DtlsObject->m_ServerName);
        DtlsObject->m_ServerName = NULL;
    }
}


// note: the caller should free *ppbout using FreeSSPIBuffer
HRESULT
DoDTLSHandshake(
    __in BOOL  bTimeoutFired,
    __in_bcount_opt(cbIn)       PBYTE  pbIn,
    __in                        ULONG  cbIn,
    __deref_out_ecount(*pcbOut) PBYTE* ppbOut,
    __out                       PULONG pcbOut,
    __out                       PULONG puTimeoutValue,
    __out                       PBOOLEAN pbDone,
    __inout                     PDTLSStruct DtlsObject
    )
{
    HRESULT hr = S_OK;
    SECURITY_STATUS secStatus = SEC_E_OK;

    *pbDone = FALSE;

    SecBufferDesc secBufDescriptorIn = { 0 };
    SecBufferDesc secBufDescriptorOut = { 0 };
    SecBufferDesc* psecBufDescriptorIn = NULL;

    ULONG uInputBuffers = 0;
    ULONG uOutputBuffers = 0;

    ULONG ulOutContextFeatures = 0;
    TimeStamp timeStamp = {0};

    SecBuffer rgSecBuffersOut[NumInputOutputBuffers] = { 0 };
    SecBuffer rgSecBuffersIn[NumInputOutputBuffers] = { 0 };

    //
    // Parameter validation
    //

    DtlsObject->m_State = DTLSSFStateInHandshake;

    if (!ppbOut || !pcbOut)
    {
        hr = E_INVALIDARG;
        goto exit;
    }

    *pcbOut = 0;
    *ppbOut = NULL;

    //
    // Timeout calculation
    //
    if (bTimeoutFired)
    {
        // TODO: Make this logic more sophisticated

        DtlsObject->m_uRetryCount++;
        if (DtlsObject->m_uRetryCount > DTLS_MAX_RETRYCOUNT)
        {
            hr = E_FAIL;
            goto exit;
        }
    }

    //
    // Buffer Handling:
    // ----------------
    //
    // Client - Initial - NULL input buffer
    //                  - 1 output buffer of type token
    //
    //        - Next iterations - 2 input buffer of type token and empty
    //                          - 2 output buffer of type token and alert
    //
    // Server - 3 input buffers of type token, empty and extra - client address
    //        - 2 output buffers of type token and alert
    //

    //
    // Setup the input buffers. For the client initial case, the input buffer is zero.
    //
    if (pbIn != NULL)
    {
        rgSecBuffersIn[0].BufferType = SECBUFFER_TOKEN;
        rgSecBuffersIn[0].cbBuffer   = cbIn;
        rgSecBuffersIn[0].pvBuffer   = (PVOID*)pbIn;

        rgSecBuffersIn[1].BufferType = SECBUFFER_EMPTY;
        rgSecBuffersIn[1].cbBuffer   = 0;
        rgSecBuffersIn[1].pvBuffer   = NULL;

        uInputBuffers = 2;

        if (DtlsObject->m_Server)
        {
            rgSecBuffersIn[2].BufferType = SECBUFFER_EXTRA;
            rgSecBuffersIn[2].cbBuffer   = DtlsObject->m_cbSaltSize;
            rgSecBuffersIn[2].pvBuffer   = DtlsObject->m_pbSalt;
            uInputBuffers = 3;
        }
    }

    secBufDescriptorIn.ulVersion = SECBUFFER_VERSION;
    secBufDescriptorIn.cBuffers  = uInputBuffers;
    secBufDescriptorIn.pBuffers  = rgSecBuffersIn;

    psecBufDescriptorIn = &secBufDescriptorIn;

    rgSecBuffersOut[0].BufferType = SECBUFFER_TOKEN;
    rgSecBuffersOut[0].cbBuffer   = 0;
    rgSecBuffersOut[0].pvBuffer   = NULL;
    uOutputBuffers = 1;

    if (pbIn != NULL)
    {
        rgSecBuffersOut[1].BufferType = SECBUFFER_ALERT;
        rgSecBuffersOut[1].cbBuffer   = 0;
        rgSecBuffersOut[1].pvBuffer   = NULL;
        uOutputBuffers++;
    }

    secBufDescriptorOut.ulVersion = SECBUFFER_VERSION;
    secBufDescriptorOut.cBuffers  = uOutputBuffers;
    secBufDescriptorOut.pBuffers  = rgSecBuffersOut;

    // TODO: Refer to MSDN to handle alerts

    //
    // Now call InitializeSecurityContext or AcceptSecurityContext for the first
    // time and get back the blob to send to the server or client respectively.
    //
    if(DtlsObject->m_Server)
    {
        secStatus = AcceptSecurityContext(&DtlsObject->m_hCredentials,
                                          SecIsValidHandle( &DtlsObject->m_hContext ) ? &DtlsObject->m_hContext : NULL,
                                          psecBufDescriptorIn,
                                          DtlsObject->m_ulContextFeatures,
                                          SECURITY_NATIVE_DREP,
                                          &DtlsObject->m_hContext,
                                          &secBufDescriptorOut,
                                          &ulOutContextFeatures,
                                          &timeStamp);
    }
    else
    {
        secStatus = InitializeSecurityContext(&DtlsObject->m_hCredentials,
                                              SecIsValidHandle( &DtlsObject->m_hContext ) ? &DtlsObject->m_hContext : NULL,
                                              (SEC_CHAR*)DtlsObject->m_ServerName,
                                              DtlsObject->m_ulContextFeatures,
                                              0,
                                              SECURITY_NATIVE_DREP,
                                              psecBufDescriptorIn,
                                              0,
                                              SecIsValidHandle( &DtlsObject->m_hContext ) ? NULL : &DtlsObject->m_hContext,
                                              &secBufDescriptorOut,
                                              &ulOutContextFeatures,
                                              NULL);
    }

    if  (uOutputBuffers > 1 && rgSecBuffersOut[1].cbBuffer != 0 && rgSecBuffersOut[1].pvBuffer != NULL )
    {
        //
        // We have an alert. The assumption is that alert is generated usually
        // when there is no data. In the case where both data and alert is generated
        // we ignore the alert.
        //
        if (FAILED(secStatus) && rgSecBuffersOut[0].cbBuffer == 0)
        {
            //
            // Handle as an extended error
            //
            ulOutContextFeatures |= ISC_RET_EXTENDED_ERROR;
            rgSecBuffersOut[0].cbBuffer = rgSecBuffersOut[1].cbBuffer;
            rgSecBuffersOut[0].pvBuffer = rgSecBuffersOut[1].pvBuffer;
        }
        else
        {
            FreeContextBuffer(rgSecBuffersOut[1].pvBuffer);
        }

        rgSecBuffersOut[1].pvBuffer = NULL;
        rgSecBuffersOut[1].cbBuffer = 0;
    }

    switch (secStatus)
    {
        //
        // This is the case where one fragment inside a message flight is
        // produced by the SSP. Application should call send with this fragment
        // and then call DoHandShake again
        //
        case SEC_I_MESSAGE_FRAGMENT:
        {
            DtlsObject->m_dtlsState = DTLSSendBufferOutAndCallSSPAgain;
            hr = S_OK;
            break;
        }

        //
        // This is the case when the entire flight is produced by the SSP.
        // Application should send the final fragment and then wait for recv.
        //
        case SEC_I_CONTINUE_NEEDED:
        {
            DtlsObject->m_dtlsState = DTLSSendBufferOutAndReceiveAndThenCallSSPAgain;
            *puTimeoutValue = DtlsObject->m_uTimeOut;
            hr = S_OK;
            break;
        }

        //
        // This is the case where the server receives few fragments for a message
        // flight but the whole flight is still not completed. Application
        // should wait for recv.
        //
        case SEC_E_INCOMPLETE_MESSAGE:
        {
            DtlsObject->m_dtlsState = DTLSReceiveAndThenCallSSPAgain;
            *puTimeoutValue = DtlsObject->m_uTimeOut;
            hr = S_OK;
            break;
        }

        //
        // In this case, the PMTU is smaller than HelloClient message. DTLS cannot
        // proceed
        //
        case SEC_E_CANNOT_PACK:
        {
            assert(!DtlsObject->m_bServer); // Validate that this should occur only on client
            break;
        }

        //
        // The handshake is completed. Switch to data transfer.
        //
        case SEC_E_OK:
        {
            DtlsObject->m_dtlsState = DTLSDataTransfer;

            hr = ResizeBufferForDataTransfer(DtlsObject);

            if (FAILED(hr))
            {
                debug("ResizeBufferForDataTransfer failed");
                goto exit;
            }

            //
            // Do processing needed for when the handshake completes.
            //
            hr = OnHandshakeCompleted(DtlsObject);

            if (FAILED(hr))
            {
                debug("OnHandshakeCompleted");
                goto exit;
            }

            *pbDone = TRUE;

            if( DtlsObject->m_cbInputData )
            {
                //If we got some extra data in the buffer
                //try to decrypt it
                /* cbData = 0;
                hr = FilterIncomingData( NULL, 0, &cbData, pcbExtra );
                CHECK_QUIT_HRCODE(hr, "FilterIncomingData");*/
            }

            hr = S_OK;

            break;
        }

        case SEC_I_INCOMPLETE_CREDENTIALS:
        case SEC_I_SIGNATURE_NEEDED:
        default:
        {
            hr = HRESULT_FROM_WIN32(secStatus);

            if (FAILED(hr))
            {
                goto exit;
            }
        }
    }

    if (rgSecBuffersOut[0].pvBuffer != NULL && rgSecBuffersOut[0].cbBuffer > 0)
    {
        hr = AllocateSSPIBuffer(rgSecBuffersOut[0].cbBuffer, (PVOID*)ppbOut);

        if (FAILED(hr))
        {
            debug("AllocateSSPIBuffer");
            goto exit;
        }

        RtlZeroMemory(*ppbOut, rgSecBuffersOut[0].cbBuffer);

        *pcbOut = rgSecBuffersOut[0].cbBuffer;
        memcpy_s(*ppbOut, *pcbOut, rgSecBuffersOut[0].pvBuffer, rgSecBuffersOut[0].cbBuffer);

        FreeContextBuffer(rgSecBuffersOut[0].pvBuffer);
        rgSecBuffersOut[0].pvBuffer = NULL;
        rgSecBuffersOut[0].cbBuffer = 0;
    }

exit:

    if (FAILED(hr))
    {
        DtlsObject->m_dtlsState = DTLSError;
    }

    return hr;

}//DoDTLSHandshake


//-----------------------------------------------------------------------------
// Encrypts the data in pbDataBuffer in place.
HRESULT
EncryptData(
    __inout_bcount_part(*pcbDataBuffer, *pcbDataBuffer) PBYTE pbDataBuffer,
    __inout PULONG pcbDataBuffer,
    ULONG fQOP,
    __inout PDTLSStruct DtlsObject
    )
{
    HRESULT hr = E_NOTIMPL;

    SecBuffer rgSecBuffersIn[4] = {0};
    SecBufferDesc secBufDescriptorIn;
    ULONG cbRealDataSize = 0;

    //Validate context handle. SSPs don't validate it for kernel mode callers
    //and may end up in AV
    if (!SecIsValidHandle(&DtlsObject->m_hContext))
    {
        hr = HRESULT_FROM_NT(STATUS_INVALID_HANDLE);
        goto exit;
    }

    //
    // Check that the minimum message size has not been exceeded.
    //
    if (*pcbDataBuffer <= DtlsObject->m_cbTrailer + DtlsObject->m_cbHeader)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        debug("EncryptData: plaintext data buffer is too small!");
        goto exit;
    }

    //
    // Check that the maximum message size has not been exceeded.
    //
    if (*pcbDataBuffer > DtlsObject->m_cbMaxMsgSize + DtlsObject->m_cbHeader + DtlsObject->m_cbTrailer)
    {
        hr = E_INVALIDARG;
        debug("EncryptData: plaintext data is too large!");
        goto exit;
    }

    //
    // Set up the buffers for encryption
    //
    cbRealDataSize = *pcbDataBuffer - DtlsObject->m_cbHeader - DtlsObject->m_cbTrailer;

    rgSecBuffersIn[0].BufferType = SECBUFFER_STREAM_HEADER;
    rgSecBuffersIn[0].pvBuffer = pbDataBuffer;
    rgSecBuffersIn[0].cbBuffer = DtlsObject->m_cbHeader;

    rgSecBuffersIn[1].BufferType = SECBUFFER_DATA;
    rgSecBuffersIn[1].pvBuffer = pbDataBuffer + DtlsObject->m_cbHeader;
    rgSecBuffersIn[1].cbBuffer = cbRealDataSize;

    rgSecBuffersIn[2].BufferType = SECBUFFER_STREAM_TRAILER;
    rgSecBuffersIn[2].pvBuffer = pbDataBuffer + DtlsObject->m_cbHeader + cbRealDataSize;
    rgSecBuffersIn[2].cbBuffer = DtlsObject->m_cbTrailer;

    rgSecBuffersIn[3].BufferType = SECBUFFER_EMPTY;

    secBufDescriptorIn.ulVersion = SECBUFFER_VERSION;
    secBufDescriptorIn.cBuffers = 4;
    secBufDescriptorIn.pBuffers = rgSecBuffersIn;

    //
    // Encrypt the data.
    //

    hr = EncryptMessage(&DtlsObject->m_hContext,
                        fQOP,
                        &secBufDescriptorIn,
                        0);

    if (FAILED(hr))
    {
        goto exit;
    }

    // Encryption should not exceed the size of the input buffer.
    // We also depend on header, message and trailer to be in place.
    assert(rgSecBuffersIn[0].cbBuffer == DtlsObject->m_cbHeader);
    assert(rgSecBuffersIn[1].cbBuffer == cbRealDataSize);
    assert(rgSecBuffersIn[2].cbBuffer <= DtlsObject->m_cbTrailer);

    if (rgSecBuffersIn[0].cbBuffer +
        rgSecBuffersIn[1].cbBuffer +
        rgSecBuffersIn[2].cbBuffer > *pcbDataBuffer)
    {
        debug("EncryptMessage has returned an illegal buffer size!");
        hr = E_FAIL;
        goto exit;
    }

    *pcbDataBuffer = rgSecBuffersIn[0].cbBuffer +
                     rgSecBuffersIn[1].cbBuffer +
                     rgSecBuffersIn[2].cbBuffer;

    //
    // We have finished successfully.
    //
    hr = S_OK;

exit:

    return hr;
} // EncryptData


//-----------------------------------------------------------------------------
// Reallocates the receive buffer to hold DTLS application data.
//
HRESULT
ResizeInputBufferToDtlsRecordSize(
    __inout PDTLSStruct DtlsObject
)
{
    HRESULT hr = E_NOTIMPL;
    BYTE* pbNewInputBuffer = NULL;
    ULONG cbDTLSRecord = 0;

    //
    // We need buffer twice as large as the maximum message size for the current protocol.
    // Thus, we will be able to accept up to maximum message size of data in one call to
    // FilterIncomingData().
    // Consider the following:
    // Suppose client sends us 2 messages of size cbMaxMsgSize,
    // and we receive them in 3 packets of sizes (cbMaxMsgSize-1), cbMaxMsgSize and 1
    // In this case the first call to FilterIncomingData() will put (cbMaxMsgSize-1)
    // bytes of encripted data into the receive buffer, because the message is incomplete.
    // When the next call to FilterIncomingData() receives cbMaxMsgSize of data, it will need
    // (cbMaxMsgSize-1) + cbMaxMsgSize buffer size to acommodate all the data.
    //
    //
    cbDTLSRecord = (DtlsObject->m_cbMaxMsgSize + DtlsObject->m_cbHeader + DtlsObject->m_cbTrailer) * 2;

    //
    // Make sure that we still have enough space for all the extra data accumulated in the input buffer.
    //
    if (cbDTLSRecord < DtlsObject->m_cbInputData)
    {
        cbDTLSRecord = DtlsObject->m_cbInputData;
    }

    pbNewInputBuffer = malloc(cbDTLSRecord);

    if (!pbNewInputBuffer)
    {
        hr = E_OUTOFMEMORY;
        if (FAILED(hr))
        {
           debug("memory allocation");
           goto exit;
        }
    }

    //
    // We need to copy any extra data that may be remaining
    // into the receive buffer.

    RtlCopyMemory(pbNewInputBuffer,
                  DtlsObject->m_pbInput,
                  DtlsObject->m_cbInputData );

    free(DtlsObject->m_pbInput);

    DtlsObject->m_pbInput = pbNewInputBuffer;
    DtlsObject->m_cbInput = cbDTLSRecord;

    //
    // We have finished successfully.
    //
    hr = S_OK;

exit:

    return hr;

} // ResizeInputBufferToDtlsRecordSize


HRESULT
OnHandshakeCompleted(
    __inout PDTLSStruct DtlsObject
    )
{
    HRESULT hr = E_NOTIMPL;

    //
    // Determine the size of the DTLS header and trailer and the
    // maximum message size.
    //
    hr = QueryStreamSizes(DtlsObject);

    if (FAILED(hr))
    {
        debug("QueryStreamSizes");
        goto exit;
    }

    //
    // Reallocate the input buffer.
    //
    hr = ResizeInputBufferToDtlsRecordSize(DtlsObject);

    if (FAILED(hr))
    {
        debug("ResizeInputBufferToDtlsRecordSize");
        goto exit;
    }

    //
    // Initialize processed data buffer.
    //
    hr = InitializeProcessedBuffer(DtlsObject);

    if (FAILED(hr))
    {
        debug("InitializeProcessedBuffer");
        goto exit;
    }

exit:

    return hr;
}


HRESULT
SetMTU(
    ULONG uMTU,
    __inout PDTLSStruct DtlsObject
    )
{
    HRESULT hr = S_OK;
    SECURITY_STATUS secStatus = SEC_E_OK;

    //
    // Validate context handle.
    //
    if(!SecIsValidHandle(&DtlsObject->m_hContext))
    {
        hr = HRESULT_FROM_NT(STATUS_INVALID_HANDLE);

        if (FAILED(hr))
        {
            debug("SecIsValidHandle failed");
            goto exit;
        }
    }

    secStatus = SetContextAttributes(&DtlsObject->m_hContext,
                                     SECPKG_ATTR_DTLS_MTU,
                                     &uMTU,
                                     sizeof(uMTU));
    if (SEC_E_OK != secStatus)
    {
        hr = HRESULT_FROM_WIN32(secStatus);
        goto exit;
    }

    hr = ResizeBufferForDataTransfer(DtlsObject);

    if (FAILED(hr))
    {
        debug("ResizeBufferForDataTransfer failed");
        goto exit;
    }

exit:

    return hr;
}



HRESULT
ResizeBufferForDataTransfer(
    __inout PDTLSStruct DtlsObject
    )
{
    HRESULT hr = S_OK;
    SECURITY_STATUS secStatus = SEC_E_OK;
    SecPkgContext_DatagramSizes secPkgSizes = { 0 };

    //
    // We must have completed the DTLS handshake and have the message
    // component sizes by this stage.
    //
    assert(DtlsObject->m_dtlsState == DTLSDataTransfer);

    //
    // Determine the size of the DTLS header and trailer and the maximum message size.
    // Make buffer
    //

    //
    // Validate context handle.
    //
    if(!SecIsValidHandle(&DtlsObject->m_hContext))
    {
        hr = HRESULT_FROM_NT(STATUS_INVALID_HANDLE);

        if (FAILED(hr))
        {
            debug("SecIsValidHandle failed");
            goto exit;
        }
    }

    secStatus = QueryContextAttributes(&DtlsObject->m_hContext,
                                       SECPKG_ATTR_DATAGRAM_SIZES,
                                       (PVOID) &secPkgSizes);

    if (SEC_E_OK != secStatus)
    {
        hr = HRESULT_FROM_WIN32(secStatus);
        goto exit;
    }

    DtlsObject->m_cbMaxMsgSize = secPkgSizes.cbMaximumMessage;
    DtlsObject->m_cbHeader = secPkgSizes.cbHeader;
    DtlsObject->m_cbTrailer = secPkgSizes.cbTrailer;

    DtlsObject->m_cbDtlsRecordSize = DtlsObject->m_cbMaxMsgSize +
                                     DtlsObject->m_cbHeader +
                                     DtlsObject->m_cbTrailer;

    if (DtlsObject->m_cbMaxBufferSize < DtlsObject->m_cbDtlsRecordSize)
    {
        DtlsObject->m_cbMaxBufferSize = DtlsObject->m_cbDtlsRecordSize;
    }

exit:

    return hr;
}


// note, the caller should free *ppbOut
HRESULT
DTLSFilterInComingData(
    __in_ecount(*pcbInOut) PBYTE pbIn,
    __inout PULONG pcbInOut,
    __deref_out_ecount(*pcbInOut) PBYTE* ppbOut,
    __inout PDTLSStruct DtlsObject
    )
{
    HRESULT hr = S_OK;
    SECURITY_STATUS secStatus = SEC_E_OK;
    SecBufferDesc secBufDescriptorOut;
    SecBuffer rgSecBuffersOut[NumInputOutputBuffers] = { 0 };

    if (pbIn == NULL || pcbInOut == NULL)
    {
        debug ("check params");
        goto exit;
    }

    assert(*pcbInOut < DtlsObject->m_cbMaxBufferSize);

    //
    // Validate context handle.
    //
    if( !SecIsValidHandle( &DtlsObject->m_hContext ) )
    {
        hr = HRESULT_FROM_NT(STATUS_INVALID_HANDLE);
        debug("SecIsValidHandle failed");
        goto exit;
    }

    //
    // Set up the decryption buffers.
    //
    rgSecBuffersOut[0].BufferType = SECBUFFER_DATA;
    rgSecBuffersOut[0].pvBuffer = pbIn;
    rgSecBuffersOut[0].cbBuffer = *pcbInOut;

    rgSecBuffersOut[1].BufferType = SECBUFFER_EMPTY;
    rgSecBuffersOut[2].BufferType = SECBUFFER_EMPTY;
    rgSecBuffersOut[3].BufferType = SECBUFFER_EMPTY;

    secBufDescriptorOut.ulVersion = SECBUFFER_VERSION;
    secBufDescriptorOut.cBuffers = NumInputOutputBuffers;
    secBufDescriptorOut.pBuffers = rgSecBuffersOut;

    //
    // Now decrypt the data.
    //
    secStatus = DecryptMessage(&DtlsObject->m_hContext,
                               &secBufDescriptorOut,
                               0,
                               NULL);

    if (SEC_E_OK != secStatus)
    {
        switch (secStatus)
        {
            //
            // In this case, the last flight from the server to the client is lost,
            // and the client regenerates its last flight. This will cause the server
            // to go back and call AcceptSecurityContext
            //
            case SEC_E_UNFINISHED_CONTEXT_DELETED:
                assert(DtlsObject->m_bServer); // Validation this should happen only for server
                DtlsObject->m_dtlsState = DTLSGoBackToHandShakeAndCallSSPAgainWithSameData;
                hr = S_OK;
                goto exit;

            // SEC_E_INCOMPLETE_MESSAGE means DTLS needs more data to proceed. it's
            // non-fatal because it will be called again with more data
            case SEC_E_INCOMPLETE_MESSAGE:
            // SEC_E_INVALID_TOKEN is also non-fatal based on discussion with DTLS team
            case SEC_E_INVALID_TOKEN:
            //
            // This error can occur is a packet arrives which is left of the
            // sliding window implemented for protected against replay attacks
            // See section 4.1.2.5 of RFC 4347. Application should consider
            // this as non fatal error
            //
            case SEC_E_OUT_OF_SEQUENCE:
                hr = S_FALSE; // non fatal error
                goto exit;

            default:
                hr = HRESULT_FROM_WIN32(secStatus);
                goto exit;
        }
    }

    //
    // Locate the decrypted data and any (optional) extra buffers.
    //
    for (int i = 1; i < NumInputOutputBuffers; i++)
    {
        if (rgSecBuffersOut[i].BufferType == SECBUFFER_DATA)
        {
            *pcbInOut = rgSecBuffersOut[i].cbBuffer;
            *ppbOut = (BYTE*) rgSecBuffersOut[i].pvBuffer;
        }

        if (rgSecBuffersOut[i].BufferType == SECBUFFER_EXTRA)
        {
            //
            // Nothing to do
            //
        }
    }

exit:

    // DTLS always consumes all data
    DtlsObject->m_cbInputData = 0;

    if (FAILED(hr))
    {
        DtlsObject->m_dtlsState = DTLSError;
    }

    return hr;
}

HRESULT
DTLSFilterOutgoingData(
    __in_ecount(*pcbInOut) BYTE* pbIn,
    __inout ULONG* pcbInOut,
    __deref_out_ecount(*pcbInOut) PBYTE* ppbOut,
    __inout PDTLSStruct DtlsObject
    )
{
    HRESULT hr = S_OK;
    SECURITY_STATUS secStatus = SEC_E_OK;
    SecBufferDesc secBufDescriptorIn;
    SecBuffer rgSecBuffersIn[NumInputOutputBuffers] = { 0 };
    ULONG cbRealDataSize = 0;

    if (pbIn == NULL || pcbInOut == NULL)
    {
        debug("Check params");
        goto exit;
    }

    assert(*pcbInOut < DtlsObject->m_cbMaxBufferSize);

    //
    // Validate context handle.
    //
    if(!SecIsValidHandle(&DtlsObject->m_hContext))
    {
        hr = HRESULT_FROM_NT(STATUS_INVALID_HANDLE);
        debug("SecIsValidHandle failed");
        goto exit;
    }

    //
    // Check that the maximum message size has not been exceeded.
    //
    if ( *pcbInOut > DtlsObject->m_cbMaxMsgSize )
    {
        hr = E_INVALIDARG;
        goto exit;
    }

    cbRealDataSize = *pcbInOut - DtlsObject->m_cbHeader - DtlsObject->m_cbTrailer;
    //
    // Set up the buffers for encryption
    //
    rgSecBuffersIn[0].BufferType = SECBUFFER_STREAM_HEADER;
    rgSecBuffersIn[0].pvBuffer = pbIn;
    rgSecBuffersIn[0].cbBuffer = DtlsObject->m_cbHeader;

    rgSecBuffersIn[1].BufferType = SECBUFFER_DATA;
    rgSecBuffersIn[1].pvBuffer = pbIn + DtlsObject->m_cbHeader;
    rgSecBuffersIn[1].cbBuffer = cbRealDataSize;

    rgSecBuffersIn[2].BufferType = SECBUFFER_STREAM_TRAILER;
    rgSecBuffersIn[2].pvBuffer = pbIn + DtlsObject->m_cbHeader + cbRealDataSize;
    rgSecBuffersIn[2].cbBuffer = DtlsObject->m_cbTrailer;

    secBufDescriptorIn.ulVersion = SECBUFFER_VERSION;
    secBufDescriptorIn.cBuffers = NumInputOutputBuffers;
    secBufDescriptorIn.pBuffers = rgSecBuffersIn;

    //
    // Encrypt the data.
    //
    secStatus = EncryptMessage(&DtlsObject->m_hContext,
                               0,
                               &secBufDescriptorIn,
                               0);

    if (SEC_E_OK != secStatus)
    {
        hr = HRESULT_FROM_WIN32(secStatus);
        goto exit;
    }

    *pcbInOut = rgSecBuffersIn[0].cbBuffer +
                rgSecBuffersIn[1].cbBuffer +
                rgSecBuffersIn[2].cbBuffer;
    *ppbOut = (PBYTE)pbIn;

exit:

    if (FAILED(hr))
    {
       DtlsObject->m_dtlsState = DTLSError;
    }

    return hr;
}


HRESULT SendToPeer(
    __in coap_context_t* ctx,
    __inout PBYTE BufferToSend,
    __inout ULONG BytesToSend,
    __in coap_address_t* dst
    )
{
    HRESULT hr = S_OK;

    int BytesSent = 0;

    BytesSent = coap_network_send(ctx,
                                  ctx->endpoint,
                                  dst,
                                  (unsigned char*) BufferToSend,
                                  BytesToSend);

    if (BytesSent < 0)
    {
        debug ("SendToPeer: Send failed");
        hr = E_FAIL;
    }

    return hr;
}


HRESULT ReceiveFromPeer(
    __in coap_context_t *ctx,
    __inout PBYTE *Buffer,
    __inout PULONG BufferSize,
    __inout coap_address_t** dst
    )
{

    HRESULT hr = S_OK;
    coap_packet_t *packet = NULL;

    if (Buffer == NULL || BufferSize == NULL || dst == NULL)
    {
        hr = E_INVALIDARG;
        goto exit;
    }

    if (coap_network_read(ctx->endpoint, &packet) < 0)
    {
        hr = E_FAIL;
        goto exit;
    }

    *Buffer = packet->payload;
    *BufferSize = packet->length;
    *dst = &packet->src;

exit:

    if (FAILED(hr))
    {
        if (packet != NULL)
        {
            coap_free_packet(packet);
        }
    }

    return hr;
}

coap_tid_t
DTLS_coap_send(
    coap_context_t* context,
    const coap_endpoint_t *local_interface,
    const coap_address_t *dst,
    coap_pdu_t *pdu,
    PDTLSStruct DtlsObject
    )
{
    HRESULT hr = S_OK;
    ULONG BytesWritten;
    coap_tid_t id = COAP_INVALID_TID;
    PBYTE BufferToSend = NULL;
    ULONG BufferLength = 0;

    if ( !context || !dst || !pdu )
      return id;

    /* Do not send error responses for requests that were received via
     * IP multicast. */
    if (coap_is_mcast(&local_interface->addr) &&
        COAP_RESPONSE_CLASS(pdu->hdr->code) > 2) {
      return COAP_DROPPED_RESPONSE;
    }

    //
    // Copy the message into the m_pbInput accounting for the dtls record header
    // and trailer.
    //

    if (DtlsObject->m_cbProcessed < DtlsObject->m_cbHeader + pdu->length + DtlsObject->m_cbTrailer)
    {
        return COAP_INVALID_TID;
    }


    memcpy_s(DtlsObject->m_pbProcessed + DtlsObject->m_cbHeader,
             DtlsObject->m_cbProcessed - DtlsObject->m_cbHeader,
             pdu->hdr,
             pdu->length);

    DtlsObject->m_cbProcessedData = DtlsObject->m_cbHeader + pdu->length + DtlsObject->m_cbTrailer;

    debug("Bytes to encrypt (Dtls Header + COAP Pdu + Dtls Trailer) = %d\n", DtlsObject->m_cbProcessedData);

    hr = DTLSFilterOutgoingData(DtlsObject->m_pbProcessed,
                                &DtlsObject->m_cbProcessedData,
                                &DtlsObject->m_pbProcessed,
                                DtlsObject);

    debug("After encryption, bytes = %d\n", DtlsObject->m_cbProcessedData);

    BytesWritten = context->network_send(context,
                                         local_interface,
                                         dst,
                                         DtlsObject->m_pbProcessed,
                                         DtlsObject->m_cbProcessedData);

    if (BytesWritten >= 0) {
      coap_transaction_id(dst, pdu, &id);
    } else {
      coap_log(LOG_CRIT, "coap_send_impl: %s\n", strerror(errno));
    }

    return id;
}


int
DTLS_coap_read(
    coap_context_t *Context,
    PDTLSStruct DtlsObject
    )
{
    LONG BytesRead = -1;
    coap_packet_t *Packet;
    HRESULT hr = S_OK;      /* the value to be returned */
    PBYTE DecryptedData = NULL;

    BytesRead = Context->network_read(Context->endpoint, &Packet);

    if (BytesRead < 0)
    {
        hr = E_FAIL;
        goto exit;
    }

    hr = DTLSFilterInComingData(Packet->payload,
                                (PULONG)&Packet->length,
                                &DecryptedData,
                                DtlsObject);

    if (FAILED(hr))
    {
        debug("DTLSFilterInComingData failed with hr=0x%x\n", hr);
        goto exit;
    }

    debug("DTLS_coap_read: After decryption, COAP Pdu bytes %d\n", Packet->length);

    DTLS_coap_handle_message(Context, DecryptedData, Packet->length, Packet);

    coap_free_packet(Packet);

exit:

    if (FAILED(hr))
    {
        if (Packet != NULL)
        {
            coap_free_packet(Packet);
            Packet = NULL;
        }
    }

    return hr;
}


int
DTLS_coap_handle_message(
    coap_context_t *Context,
    unsigned char *coap_message,
    size_t message_length,
    coap_packet_t *packet)
{
    enum result_t {RESULT_OK, RESULT_ERR_EARLY, RESULT_ERR};
    int result = RESULT_ERR_EARLY;
    coap_queue_t *node;

    if (message_length < COAP_HDR_SIZE)
    {
        debug("coap_handle_message: discarded invalid frame\n" );
        goto error_early;
    }

    /* check version identifier */
    if (((*coap_message >> 6) & 0x03) != COAP_DEFAULT_VERSION)
    {
        debug("coap_handle_message: unknown protocol version %d\n", (*coap_message >> 6) & 0x03);
        goto error_early;
    }

    node = coap_new_node();

    if (!node)
    {
        goto error_early;
    }

    /* from this point, the result code indicates that */
    result = RESULT_ERR;

    node->pdu = coap_pdu_init(0, 0, 0, message_length);

    if (!node->pdu)
    {
        goto error;
    }

    if (!coap_pdu_parse(coap_message, message_length, node->pdu))
    {
        debug("discard malformed PDU\n");
        goto error;
    }

    coap_ticks(&node->t);

    coap_packet_populate_endpoint(packet, &node->local_if);
    coap_packet_copy_source(packet, &node->remote);

    /* and add new node to receive queue */
    coap_transaction_id(&node->remote, node->pdu, &node->id);

#ifndef NDEBUG
    if (LOG_DEBUG <= coap_get_log_level())
    {
        #ifndef INET6_ADDRSTRLEN
        #define INET6_ADDRSTRLEN 40
        #endif

        /** @FIXME get debug to work again **
        unsigned char addr[INET6_ADDRSTRLEN+8], localaddr[INET6_ADDRSTRLEN+8];
        if (coap_print_addr(remote, addr, INET6_ADDRSTRLEN+8) &&
        coap_print_addr(&packet->dst, localaddr, INET6_ADDRSTRLEN+8) )
        debug("** received %d bytes from %s on interface %s:\n",
        (int)msg_len, addr, localaddr);
        */

        coap_show_pdu(node->pdu);
    }
#endif

  coap_dispatch(Context, node);
  return -RESULT_OK;

 error:
  /* FIXME: send back RST? */
  coap_delete_node(node);
  return -result;

 error_early:
  return -result;
}


