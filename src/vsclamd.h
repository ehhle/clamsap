/* Copyright (c) 2001 - 2022, Markus Strehle, SAP SE
 *
 * MIT License, http://www.opensource.org/licenses/mit-license.php
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * 
 */

#ifndef VSCLAM_H
#define VSCLAM_H

#ifdef __cplusplus
extern "C"
{
#endif

/*--------------------------------------------------------------------*/
/* VSA example defines                                                */
/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/
/* CLAMDSAP VERSION CONTROL                                           */
/*--------------------------------------------------------------------*/
/*
 *  Adapter defines:
 *  A VSA must return a VSA_CONFIG struture with the provided 
 *  features and settings.
 *  These defines are for this VSA_CONFIG structure.
 */
#ifdef VSI2_COMPATIBLE
    /* supports VSI version 2      */
#define VSI_VERSION            2
#else
#define VSI_VERSION            1
#endif
/* adapter stuff               */
#ifdef CLAMSAP_VERSION
#define VSA_ADAPTER_VERSION    CLAMSAP_VERSION
#else
#define VSA_ADAPTER_VERSION    "0.104.1"
#endif
#define VSA_ADAPTER_MAJVER     0
#define VSA_ADAPTER_MINVER     1041
#define VSA_VENDORINFO         "OpenSource Project CLAMSAP (http://sourceforge.net/projects/clamsap/) "
#define VSA_VENDORINFO_LN      (sizeof(VSA_VENDORINFO)-1)
#define VSA_ADAPTERNAME        "CLAMDSAP: ClamAV daemon to SAP NW-VSI Adapter Version: "VSA_ADAPTER_VERSION" "
#define VSA_ADAPTERNAME_LN     (sizeof(VSA_ADAPTERNAME)-1)
#define VSA_VERSION_STRING     "ClamSAP VSA for clamd daemon "VSA_ADAPTER_VERSION" and higher"

/* we can not access to the engine, so we know 1 driver/definition */
#define CLEANUP(x)          { rc = x; goto cleanup; }
/* default for VSA_CONFIG: the current directory*/
#ifdef _WIN32
#define DIR_SEP             "\\"
#define DRIVER_DIRECTORY    "."
# define DIRSLASH           '\\'
# define DIRSLASH_STR       "\\"
#else
#define DIR_SEP             "/"
#define DRIVER_DIRECTORY    "."
# define DIRSLASH           '/'
# define DIRSLASH_STR       "/"
#endif
#define DRIVER_DIRECTORY_LN (sizeof(DRIVER_DIRECTORY)-1)

#define CLAMAV_DRIVERS      "CLAMD"
#define MAX_DRIVERS         1

#define CLAMAV_DRIVERS_LN   (sizeof(CLAMAV_DRIVERS)-1)

#define ENGINE_DATA(x,y,z) \
    _utc_date.tm_mon = y-1;  \
    _utc_date.tm_mday= x;    \
    _utc_date.tm_year= z-1900;

/* define exported sysmbols for zOS */
#ifdef SAPonOS390
#pragma export(VsaStartup)
#pragma export(VsaGetConfig)
#pragma export(VsaInit)
#pragma export(VsaScan)
#pragma export(VsaReleaseScan)
#pragma export(VsaEnd)
#pragma export(VsaCleanup)
#endif
/* structs for VsaGetConfig returning own configuration */
typedef struct {
    VS_INITPARAM_T     tCode;
    VS_PARAMTYPE_T     tType;
    size_t             lLength;
    VSA_PARAMVALUE     pvValue;
} MY_INITPARAMS;

typedef struct  {
    VS_OPTPARAM_T      tCode;
    VS_PARAMTYPE_T     tType;
    size_t             lLength;
    VSA_PARAMVALUE     pvValue;
} MY_OPTPARAMS;


/* structure for transporting our usrdata + our 
 * function pointer + virus_info 
 */
struct usrdata {
    VSA_RC          vsa_rc;
    UInt            uiJobID;
    UInt            uiMsgFlags;
    size_t          lObjectSize;
    VSA_EVENTCBFP   pvFncptr;
    void           *pvUsrdata;
    Bool            bScanFileLocal;
    Bool            bScanBestEffort;
    Bool            bScanAllFiles;
    Bool            bScanCompressed;
    UInt            iComress2Level;
    Bool            bMimeCheck;
    Bool            bActiveContent;
    Bool            bPdfAllowOpenAction;
    Bool            bScanMimeTypesWildCard;
    Bool            bBlockMimeTypesWildCard;
    PChar           pszScanMimeTypes;
    PChar           pszBlockMimeTypes;
    PChar           pszScanExtensions;
    PChar           pszBlockExtensions;
    VS_OBJECTTYPE_T tFileType;
    VS_OBJECTTYPE_T tObjectType;
    PVSA_SCANINFO   pScanInfo;
    VS_MESSAGE_T    tMsg_rc;
};
typedef struct usrdata USRDATA, *PUSRDATA, **PPUSRDATA;

/* structure for server connection */
struct clamdconnect {
    Bool            bLocal;
    UInt            iTimeout;
    PChar           pProtocol;
    PChar           pServer;
    PChar           pPort;
};
typedef struct clamdconnect CLAMDCON, *PCLAMDCON, **PPCLAMDCON;

struct initdata {
   PVSA_INITPARAM   initdirectory;
   PVSA_INITPARAM   drivers;
   PVSA_INITPARAM   tmpdir;
   PVSA_INITPARAM   server;
};
typedef struct initdata INITDATA, *PINITDATA;

/* helper macros */
#define VSAddINITParameter(pl, i, c, a, b, s) \
{       pl[i].struct_size    = sizeof(VSA_INITPARAM); \
        pl[i].tCode          = c; \
        pl[i].tType          = a; \
        pl[i].lLength        = b; \
        pl[i].pvValue        = s; \
        i++; \
}
#define VSAddOPTParameter(pl, i, c, a, b, s) \
{       pl[i].struct_size    = sizeof(VSA_OPTPARAM); \
        pl[i].tCode          = c; \
        pl[i].tType          = a; \
        pl[i].lLength        = b; \
        pl[i].pvValue        = s; \
        i++; \
}

#define CB_FUNC(msg, udata)                         \
    ((cfunc != NULL) && (uiMsgFlag & msg)) ?        \
       cfunc ( heng, msg, (VSA_PARAM)udata, pvUsrdata ) : VS_CB_OK;

#define SET_VSA_RC(_vsa_rc_) \
{   if (usrdata.vsa_rc == VSA_OK || usrdata.vsa_rc > _vsa_rc_) \
    usrdata.vsa_rc = _vsa_rc_; }

#define SETSTRING( buf, txt )                                           \
{   if (txt != NULL && (len=strlen((const char*)txt)) > (size_t)0)      \
    {   buf = (PChar)malloc(len+1);                                     \
    if (buf == NULL)                                                    \
        CLEANUP(VSA_E_NO_SPACE);                                        \
    /* CCQ_OFF */ memcpy(buf,txt,len); /*CCQ_ON */                      \
    buf[len] = 0; } /* ensure zero termination */                       \
    else                                                                \
        buf = NULL;                                                     \
}
#define SETSTRINGLN( buf, txt, len)                                     \
{   buf = (PChar)malloc(len+1);                                         \
    if (buf == NULL)                                                    \
        CLEANUP(VSA_E_NO_SPACE);                                        \
    /* CCQ_OFF */ memcpy(buf,txt,len); /*CCQ_ON */                      \
    buf[len] = 0;   /* ensure zero termination */                       \
}

#define SETERRORTEXT    SETSTRING

#ifdef __cplusplus
}
#endif

#endif /* VSCLAM_H */
