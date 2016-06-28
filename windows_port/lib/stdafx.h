//
//    Copyright (C) Microsoft.  All rights reserved.
//
// stdafx.h : include file for standard system include files,
//      or project specific include files that are used frequently,
//      but are changed infrequently

#pragma once


#include <nt.h>
#include <ntrtl.h>
#include <nturtl.h>
#include <windows.h>
#include <strsafe.h>

#define SECURITY_PACKAGE
#define SECURITY_WIN32

#include <security.h>
#include <schannel.h>
#include <credssp.h>
#include <wincrypt.h>

//#include "tsunknown.h"

#define SSPIString SEC_WCHAR*

//
// XPlat headers.
//
//#include "RdpXPlat.h"
//#include "RdpXObjectImpl.h"
//#include "RdpXPlatObjectFactory.h"
//#include "LegacyXPlatInline.h"
//#include "trace.h"
