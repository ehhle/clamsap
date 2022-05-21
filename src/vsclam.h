/* Copyright (c) 2012 - 2022, Markus Strehle, SAP SE
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
/* CLAMSAP VERSION CONTROL                                            */
/*--------------------------------------------------------------------*/
/*
 *  Adapter defines:
 *  A VSA must return a VSA_CONFIG structure with the provided
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
#define VSA_ADAPTER_VERSION    "0.104.2"
#endif
#define VSA_ADAPTER_MAJVER     0
#define VSA_ADAPTER_MINVER     1042
#define VSA_VENDORINFO         "OpenSource Project CLAMSAP (http://sourceforge.net/projects/clamsap/) "
#define VSA_VENDORINFO_LN      (sizeof(VSA_VENDORINFO)-1)
#define VSA_ADAPTERNAME        "CLAMSAP: ClamAV to SAP NW-VSI Adapter Version: "VSA_ADAPTER_VERSION" "
#define VSA_ADAPTERNAME_LN     (sizeof(VSA_ADAPTERNAME)-1)
#define VSA_VERSION_STRING     "ClamSAP VSA for libclamav "VSA_ADAPTER_VERSION" and higher"

/* we can not access to the engine, so we know 1 driver/definition */
#define CLEANUP(x)          { rc = x; goto cleanup; }
/* default for VSA_CONFIG: the current directory*/
#ifdef _WIN32
#define DIR_SEP             "\\"
#define DRIVER_DIRECTORY    "."
#else
#define DIR_SEP             "/"
#define DRIVER_DIRECTORY    "/var/lib/clamav"
#endif
#define DRIVER_DIRECTORY_LN (sizeof(DRIVER_DIRECTORY)-1)

#define CLAMAV_DRIVERS      "main.cvd,daily.cvd,bytecode.cvd,safebrowsing.cvd"
#define MIN_DRIVERS         1
#define MAX_DRIVERS         4

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

#ifdef CL_SCAN_STDOPT
struct cl_scan_options {
    unsigned int general;
    unsigned int parse;
    unsigned int heuristic;
    unsigned int mail;
    unsigned int dev;
};
#endif
typedef struct cl_scan_options CLAM_SCAN_OPT;

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
    CLAM_SCAN_OPT   cl_scan_options;
};
typedef struct usrdata USRDATA, *PUSRDATA, **PPUSRDATA;

struct initdata {
   PVSA_INITPARAM   enginedirectory;
   PVSA_INITPARAM   initdirectory;
   PVSA_INITPARAM   drivers;
   PVSA_INITPARAM   tmpdir;
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

#define SETSTRINGLN( buf, txt, len )                                    \
{   if (txt != NULL)                                                    \
    {   buf = (PChar)malloc(len+1);                                     \
    if (buf == NULL)                                                    \
        CLEANUP(VSA_E_NO_SPACE);                                        \
    /* CCQ_OFF */ memcpy(buf,txt,len); /*CCQ_ON */                      \
    buf[len] = 0; } /* ensure zero termination */                       \
    else                                                                \
        buf = NULL;                                                     \
}

#define SETERRORTEXT    SETSTRING

typedef int (FN_CL_INIT)(unsigned int);
typedef struct cl_engine * (FN_CL_ENGINE_NEW)(void);
typedef int (FN_CL_ENGINE_FREE)(struct cl_engine *);
typedef const char * (FN_CL_RETDBDIR)(void);
typedef const char * (FN_CL_STRERROR)(int);
typedef void (FN_CL_CVDFREE)(struct cl_cvd *);
typedef struct cl_cvd *(FN_CL_CVDHEAD)(const char *);
typedef int (FN_CL_ENGINE_SET_STR)(struct cl_engine *, enum cl_engine_field, const char *);
typedef long long (FN_CL_ENGINE_GET_NUM)(const struct cl_engine *, enum cl_engine_field f, int *);
typedef int (FN_CL_ENGINE_SET_NUM)(struct cl_engine *, enum cl_engine_field f, long long);
typedef int (FN_CL_ENGINE_COMPILE)(struct cl_engine *);
typedef int (FN_CL_LOAD)(const char *, struct cl_engine *, unsigned int *, unsigned int);
typedef unsigned int (FN_CL_RETFLEVEL)(void);
#ifdef CL_SCAN_STDOPT
typedef int (FN_CL_SCANFILE)(const char *, const char **, unsigned long int *, const struct cl_engine *, unsigned int);
#else
typedef int (FN_CL_SCANFILE)(const char *, const char **, unsigned long int *, const struct cl_engine *, struct cl_scan_options *);
#endif
typedef void     *DLL_HDL;
typedef struct {
    /* function pointers for clamav functions in libclamav library */
    FN_CL_INIT              *fp_cl_init;
    FN_CL_ENGINE_NEW        *fp_cl_engine_new;
    FN_CL_ENGINE_FREE       *fp_cl_engine_free;
    FN_CL_RETDBDIR          *fp_cl_retdbdir;
    FN_CL_STRERROR          *fp_cl_strerror;
    FN_CL_CVDFREE           *fp_cl_cvdfree;
    FN_CL_CVDHEAD           *fp_cl_cvdhead;
    FN_CL_ENGINE_SET_STR    *fp_cl_engine_set_str;
    FN_CL_ENGINE_GET_NUM    *fp_cl_engine_get_num;
    FN_CL_ENGINE_COMPILE    *fp_cl_engine_compile;
    FN_CL_LOAD              *fp_cl_load;
    FN_CL_ENGINE_SET_NUM    *fp_cl_engine_set_num;
    FN_CL_RETFLEVEL         *fp_cl_retflevel;
    FN_CL_SCANFILE          *fp_cl_scanfile;
    /* handle */
    char                     bLoaded;
    DLL_HDL                  dll_hdl;
} clamav_function_pointers;

struct clamav_function_s {
    const char *  function_name;
    int           function_index;
};

typedef int (APIENTRY DLL_CALL)(void);
typedef DLL_CALL *DLL_ADR;
typedef size_t    size_tR;

#define DLL_DEFINE(x)       {  # x, DLL_FPTR_OFFSET(x) }
#define CLAMAV_FIRST_FUNC    fp_cl_init
#define DLL_FPTR_OFFSET(x)  ((offsetof(clamav_function_pointers,fp_ ## x) - offsetof(clamav_function_pointers,CLAMAV_FIRST_FUNC)) / sizeof(DLL_ADR *))

#ifdef __cplusplus
}
#endif

#endif /* VSCLAM_H */
