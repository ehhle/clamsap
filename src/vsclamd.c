/* Copyright (c) 2012 - 2021, Markus Strehle, SAP SE
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

/*source--------------------------------------------------------------*/
/*                                                                    */
/* Description:                                                       */
/* ============                                                       */
/*                                                                    */
/*                                                                    */
/*                                                                    */
/*  Author:    Markus Strehle, SAP AG (mailto:markus.strehle@sap.com) */
/*  Reviewer:                                                         */
/*  Version:       1.103.x                                            */
/*                                                                    */
/*  Created:                                                          */
/*    20 June 2005  Markus Strehle                                    */
/*                                                                    */
/*  Modified:                                                         */
/*    25 Apr  2012  Markus Strehle                                    */
/*                  Connect remote ClamD(aemon)                       */
/*    25 Mar  2011  Markus Strehle                                    */
/*                  Adaption for ClamAV 0.97                          */
/*    01 Nov  2010  Markus Strehle                                    */
/*                  Adaption for ClamAV 0.96                          */
/*    05 Aug  2009  Markus Strehle                                    */
/*                  Adaption for ClamAV 0.95                          */
/*    15 Aug  2008  Markus Strehle                                    */
/*                  (many changes)                                    */
/*    09 Apr  2015  Markus Strehle                                    */
/*                  Adaption for ClamAV 0.98                          */
/*                  Return VSA_CONTENTINFO for NW-VSI 2.00            */
/*                                                                    */
/*  Remarks:                                                          */
/*      Supports NW-VSI Version 2.00 http://scn.sap.com/docs/DOC-7838 */
/*                                                                    */
/*                                                                    */
/**********************************************************************/
/*                                                                    */
/*                                                                    */
/* --- public functions ----------------------------------------------*/
/*                                                                    */
/*      VsaStartup                                                    */
/*      VsaInit                                                       */
/*      VsaGetConfig                                                  */
/*      VsaScan                                                       */
/*      VsaReleaseScan                                                */
/*      VsaEnd                                                        */
/*      VsaCleanup                                                    */
/*                                                                    */
/* --- private functions ---------------------------------------------*/
/*      setScanError                                                  */
/*      registerCallback                                              */
/*      freevirusinfo                                                 */
/*      freevirusinfo2                                                */
/*      freescanerror                                                 */
/*      freescanerror2                                                */
/*      freeVSA_INIT                                                  */
/*      freeVSA_CONFIG                                                */
/*      getFileSize                                                   */
/*                                                                    */
/**********************************************************************/
/*--------------------------------------------------------------------*/
/* Adapter defines                                                    */
/*--------------------------------------------------------------------*/
#ifdef SAPwithUNICODE
#undef SAPwithUNICODE
#undef UNICODE 
#undef _UNICODE
#endif

/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/
/* system includes (OS-dependent)                                     */
/*--------------------------------------------------------------------*/
#ifdef _WIN32
#ifndef WIN32_MEAN_AND_LEAN
#define WIN32_MEAN_AND_LEAN
#endif
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#if !(defined (SAPonNT) && _MSC_VER >= 1900)
#define snprintf _snprintf
#endif

#else
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h> 

/*--------------------------------------------------------------------*/
/* Own includes                                                       */
/*--------------------------------------------------------------------*/
#include "vsaxxtyp.h"
#include "vsclamd.h"
#ifdef VSI2_COMPATIBLE
#include "csdecompr.h"
#include "vsmime.h"
#endif

/*--------------------------------------------------------------------*/
/* static globals                                                     */
/*--------------------------------------------------------------------*/
static Bool              bgInit             =   FALSE;
static size_t            lgRefCounter       =   0;
static const char        builddate[]        =   "[DATE]CLAMSAP: " __DATE__ ", " __TIME__ ;
#ifdef __cplusplus
static const char        version[]          =   "@[CPP]CLAMSAP: " VSA_ADAPTER_VERSION;
#else
static const char        version[]          =   "@[ C ]CLAMSAP: " VSA_ADAPTER_VERSION;
#endif
static PChar             pClamdaemon        = NULL;
#ifdef VSI2_COMPATIBLE
static PChar             pLoadError         = NULL;
#endif

#define INT_2_BYTES(cres, num)                 \
{                                              \
   (cres)[0] = (char)(((num) >>24) & 0xff);    \
   (cres)[1] = (char)(((num) >>16) & 0xff);    \
   (cres)[2] = (char)(((num) >>8)  & 0xff);    \
   (cres)[3] = (char)( (num)       & 0xff);    \
}

#ifdef _WIN32
#  define _sendmysocket( s , p, len) send(s, p, len,0)
#else
#  define _sendmysocket( s , p, len) write(s, p, len)
#endif

#ifdef _WIN32
#  define _readmysocket( s , p, len) recv(s, p, len,0)
#else
#  define _readmysocket( s , p, len) read(s, p, len)
#endif

#ifdef _WIN32
# define _closemysocket(s) closesocket(s)
#else
# define _closemysocket(s) close(s)
#endif

/* all known messages, provided also in VSA_CONFIG */
static const UInt     uigVS_SAP_ALL = VS_M_ERROR              |
                                      VS_M_ABORTSCAN          |
                                      VS_M_VIRUS              |
                                      VS_M_CLEAN              |
                                      VS_M_NOTSCANNED         |
                                      VS_M_OBJECTFOUND;

/*--------------------------------------------------------------------*/
/* helper functions                                                   */
/*--------------------------------------------------------------------*/
#ifdef VSI2_COMPATIBLE
static VSA_RC scanFile(
    void           *pEngine,
    UInt            uiJobID,
    PChar           pszObjectName,
    USRDATA        *pUsrData,
    PChar           errorReason);

static VSA_RC scanBuffer(
    void           *pEngine,
    UInt            uiJobID,
    PChar           pszObjectName,
    PByte           pObject,
    size_t          lObjectSize,
    USRDATA        *pUsrData,
    PChar           errorReason);

static VSA_RC scanCompressed(
    void           *pEngine,
    UInt            uiJobID,
    PChar           pszObjectName,
    USRDATA        *pUsrData,
    PChar           errorReason);

static VSA_RC scanCompressedBuffer(
    void           *pEngine,
    UInt            uiJobID,
    PChar           pszObjectName,
    PByte           pObject,
    size_t          lObjectSize,
    USRDATA        *pUsrData,
    PChar           errorReason);

static VSA_RC vsaSetContentTypeParametes(VSA_OPTPARAM *,
    USRDATA *
    );
#endif

static VSA_RC setScanError(UInt            uiJobID,
                           PChar           pszObjectName,
                           size_t          lObjectSize,
                           Int             iErrorRC,
                           PChar           pszErrorText,
                           PPVSA_SCANERROR pp_scanerror);
/*
 * socket conntect method
 */
static VSA_RC vsaConnectd( PChar server, PChar port, PChar zCommand, PPChar zAnswer);
/*
 * send byte stream to clamd
 */
static VSA_RC vsaSendBytes2Clamd( PChar server, PChar port, FILE *pFP, PByte pByte, size_t lByte, PPChar zAnswer);

/*
 * parse URI
 */
static VSA_RC vsaparseURI( PChar uri, PChar bLocal, PPChar prot, PPChar server, PPChar port);

/*
 *  Assign the VSA_INIT and OPTPARAM values to
 *  internal configuration.
 */
static VSA_RC vsaSetInitConfig(VSA_INITPARAMS *,
                               INITDATA *
                               );

static VSA_RC vsaSetOptConfig(VSA_OPTPARAMS *,
                               USRDATA *
                               );

static VSA_RC registerCallback( VSA_CALLBACK *, 
                                USRDATA *
                              );

static void freevirusinfo(VSA_VIRUSINFO **);
static void freevirusinfo2(VSA_VIRUSINFO *);
static void freescanerror(VSA_SCANERROR **);
static void freescanerror2(VSA_SCANERROR *);
static void freecontentinfo2(VSA_CONTENTINFO *);

static void freeVSA_INIT(  VSA_INIT **);
static void freeVSA_CONFIG(VSA_CONFIG **);

static VSA_RC getFileSize(Char *, size_t *);

#ifndef DEFAULT_PROTOCOL
#define DEFAULT_PROTOCOL   "tcp"
#endif

#ifndef DEFAULT_SERVER 
#define DEFAULT_SERVER     "127.0.0.1"
#endif

#ifndef LOCAL_SOCKET_PATH
#define LOCAL_SOCKET_PATH  "/var/lib/clamav/clamd-socket"
#endif

#ifndef DEFAULT_PORT
#define DEFAULT_PORT       "3310"
#endif
/*--------------------------------------------------------------------*/
/* VSA public functions                                               */
/*--------------------------------------------------------------------*/
/**********************************************************************
 *  VsaStartup()
 *
 *  Description:
 *     Global initialization of the adapter. This function will be called
 *     once after loading the VSA.
 *
 *  Returncodes: 
 *  VSA_OK                   |      Success
 *  VSA_E_NOT_INITIALISED    |      Global initialization not successful
 *  VSA_E_NO_SPACE           |      Any resource allocation failed 
 *
 **********************************************************************/
VSA_RC
DLL_EXPORT VsaStartup( void )
{
    /* 
     * Comment: 
     * This dummy adapter does not need any further interfaces,
     * so return here VSA_OK.
     */
    /*--------------------------------------------------------------------*/
    /* The startup will be called process global                          */
    /* With this we say, we are ready to work                             */
    /*--------------------------------------------------------------------*/      
    if(bgInit == FALSE)
    {   
#ifdef _WIN32
        WORD wVersionRequested;
        WSADATA wsaData;
        int error;

        wVersionRequested = MAKEWORD(2,2);
        error = WSAStartup(wVersionRequested, &wsaData);     /* start Winsock*/
        if(error!=0)
        {
            return VSA_E_LOAD_FAILED;
        }

        if(HIBYTE(wsaData.wVersion) < 2)  /* check Version 2 of Winsock*/
        {
            WSACleanup();
            return VSA_E_LOAD_FAILED;
        }
#endif
#ifdef VSI2_COMPATIBLE
        InitializeTable();
        if(pLoadError) free(pLoadError);
        /* load libmagic library */
        vsaLoadMagicLibrary(&pLoadError);
        /*if(rc) return VSA_E_LOAD_FAILED;*/
        if(pClamdaemon == NULL) {
           pClamdaemon = (PChar)getenv("CLAMD");
           if(pClamdaemon == NULL) {
              pClamdaemon = (PChar)getenv("INITSERVERS");
           }
           if(pClamdaemon == NULL) {
              pClamdaemon = (PChar)getenv("INITSERVER");
           }
        }
#endif
        bgInit = TRUE;
    }
    return VSA_OK;
}


/**********************************************************************
 *  VsaGetConfig() 
 *
 *  Description:
 *     This call allows the SAP system to know which type of VSA was loaded and
 *     which parameters and other features it has. An AV vendor of a VSA
 *     can also define a default profile of initial and optional 
 *     parameters here. <nl>
 *     "REQ" (required) parameters are mandatory. <nl>
 *     "OPT" (optional) parameters are not mandatory.
 *
 *  Returncodes:
 *  VSA_OK                |         Success
 *  VSA_E_NOT_INITIALISED |         Global initialization not successful
 *  VSA_E_NO_SPACE        |         Any resource allocation failed 
 *  VSA_E_NULL_PARAMETER  |         NULL pointer provided
 *
 **********************************************************************/
VSA_RC 
DLL_EXPORT VsaGetConfig(PPVSA_CONFIG pp_config)
{
    size_t len = 0;
    /*
     * Comment:
     * This structure helps to define a list of parameters. This adapter
     * supports following of the VSA parameters.
     * The length is set to 0 because there are only BOOL parameters. In
     * case of Char parameters you have to set the length of the string.
     */
    static MY_INITPARAMS _initparams[] = {
        { VS_IP_INITDRIVERS            ,   VS_TYPE_CHAR   ,      0,     0}, 
        /*{ VS_IP_INITDRIVERDIRECTORY    ,   VS_TYPE_CHAR   ,      0,     0},*/
        { VS_IP_INITTEMP_PATH          ,   VS_TYPE_CHAR   ,      0,     0},
        { VS_IP_INITSERVERS            ,   VS_TYPE_CHAR   ,      0,     0}

    };

    static MY_OPTPARAMS _optparams[] = {
        { VS_OP_SCANBESTEFFORT         ,   VS_TYPE_BOOL   ,      0,     (void*)1},
        { VS_OP_SCANALLFILES           ,   VS_TYPE_BOOL   ,      0,     (void*)1},
        { VS_OP_SCANACCESSFILELOCAL    ,   VS_TYPE_BOOL   ,      0,     (void*)1},
        { VS_OP_SCANEXCLUDEMIMETYPES   ,   VS_TYPE_CHAR   ,      0,     (void*)""}
#ifdef VSI2_COMPATIBLE
        ,
        { VS_OP_SCANEXTRACT            ,   VS_TYPE_BOOL   ,      0,     (void*)1},
        { VS_OP_SCANMIMETYPES          ,   VS_TYPE_CHAR   ,      0,     (void*)""},
        { VS_OP_SCANEXTENSIONS         ,   VS_TYPE_CHAR   ,      0,     (void*)""},
        { VS_OP_BLOCKMIMETYPES         ,   VS_TYPE_CHAR   ,      0,     (void*)""},
        { VS_OP_BLOCKEXTENSIONS        ,   VS_TYPE_CHAR   ,      0,     (void*)""}
#endif
    };

    VSA_RC      rc      =   VSA_OK;
    int         x       =   0,
                ipar    =   sizeof(_initparams)/sizeof(_initparams[0]),
                opar    =   sizeof(_optparams)/sizeof(_optparams[0]);
 
    if(bgInit == FALSE)
        return VSA_E_NOT_INITIALISED; /* no successful VsaStartup */

    /*--------------------------------------------------------------------*/
    /* VSA_CONFIG allocation. Return a filled structure in the function   */
    /*--------------------------------------------------------------------*/
    if(pp_config == NULL)
        return VSA_E_NULL_PARAM; /* no handle */
    (*pp_config)                           = (PVSA_CONFIG)calloc(1, sizeof(VSA_CONFIG));
    if ((*pp_config) == NULL)
        CLEANUP(VSA_E_NO_SPACE);

    /* init params */
    (*pp_config)->pInitParams              = (PVSA_INITPARAMS)calloc(1, sizeof(VSA_INITPARAMS));
    if ((*pp_config)->pInitParams == NULL)
        CLEANUP(VSA_E_NO_SPACE);
    (*pp_config)->pInitParams->pInitParam  = (PVSA_INITPARAM)calloc(ipar, sizeof(VSA_INITPARAM));
    if ((*pp_config)->pInitParams->pInitParam == NULL)
        CLEANUP(VSA_E_NO_SPACE);
    
    /* option params */
    (*pp_config)->pOptParams               = (PVSA_OPTPARAMS)calloc(1, sizeof(VSA_OPTPARAMS));
    if ((*pp_config)->pOptParams == NULL)
        CLEANUP(VSA_E_NO_SPACE);
    (*pp_config)->pOptParams->pOptParam    = (PVSA_OPTPARAM)calloc(opar, sizeof(VSA_OPTPARAM));
    if ((*pp_config)->pOptParams->pOptParam == NULL)
        CLEANUP(VSA_E_NO_SPACE);


    (*pp_config)->pAdapterInfo             = (PVSA_ADAPTERINFO)calloc(1, sizeof(VSA_ADAPTERINFO));
    if ((*pp_config)->pAdapterInfo == NULL)
        CLEANUP(VSA_E_NO_SPACE);

    (*pp_config)->struct_size              =    sizeof(VSA_CONFIG);

    /*--------------------------------------------------------------------*/
    /* loop to fill the supported parameter structure                     */
    /*--------------------------------------------------------------------*/
    for(x=0; x<ipar;x++)
    {
       /*  ipar : number of entries in initparams
           x    : actual index
           we add parameters from the default structure and set this as default config structure 
            */
        switch(_initparams[x].tCode)
        {
        case VS_IP_INITDRIVERS:
           {
              PChar  _drivers = (PChar)malloc(CLAMAV_DRIVERS_LN +1);
               if(_drivers == NULL)
                  CLEANUP(VSA_E_NO_SPACE);
               strncpy((char*)_drivers,CLAMAV_DRIVERS,CLAMAV_DRIVERS_LN);
               _drivers[CLAMAV_DRIVERS_LN]=0;

               VSAddINITParameter ( (*pp_config)->pInitParams->pInitParam,
                                    (*pp_config)->pInitParams->usInitParams,
                                    _initparams[x].tCode,
                                    _initparams[x].tType,
                                    CLAMAV_DRIVERS_LN,
                                    (char*)_drivers
                                  );
           }
        break;
        case VS_IP_INITDRIVERDIRECTORY:
           {
               PChar  _dir = (PChar)malloc(DRIVER_DIRECTORY_LN+1);
               if(_dir == NULL)
                  CLEANUP(VSA_E_NO_SPACE);
               strncpy((char*)_dir,DRIVER_DIRECTORY,DRIVER_DIRECTORY_LN);
               _dir[DRIVER_DIRECTORY_LN]=0;

               VSAddINITParameter ( (*pp_config)->pInitParams->pInitParam,
                                    (*pp_config)->pInitParams->usInitParams,
                                    _initparams[x].tCode,
                                    _initparams[x].tType,
                                    DRIVER_DIRECTORY_LN,
                                    (char*)_dir
                                  );
           }
        break;
        case VS_IP_INITSERVERS:
            {   /* CCQ_OFF */
                PChar  _dir = NULL;
    /*#ifdef _WIN32 */
                len = (sizeof(DEFAULT_PROTOCOL)-1) + (sizeof(DEFAULT_SERVER)-1) + (sizeof(DEFAULT_PORT)-1) + 10;
    /*#else
                len = ((sizeof(DEFAULT_PROTOCOL)-1) + (sizeof(LOCAL_SOCKET_PATH)-1) + 6;
    #endif*/
                if(pClamdaemon) {
                   len = strlen((const char*)pClamdaemon) + 1;
                }
                _dir = (PChar)malloc(len+1);
                if(_dir == NULL)
                   CLEANUP(VSA_E_NO_SPACE);
                if(pClamdaemon) {
                   len = snprintf((char*)_dir,len,"%s",pClamdaemon);
                } else {
                   len = snprintf((char*)_dir,len,"%s://%s:%s",DEFAULT_PROTOCOL,DEFAULT_SERVER,DEFAULT_PORT);
                }

                VSAddINITParameter ( (*pp_config)->pInitParams->pInitParam,
                                     (*pp_config)->pInitParams->usInitParams,
                                     _initparams[x].tCode,
                                     _initparams[x].tType,
                                     len,
                                     (char*)_dir
                                   );
            }/* CCQ_ON */
        break;
        case VS_IP_INITTEMP_PATH:
           {
              PChar  _tmpPath = NULL; /* CCQ_OFF */
               if( getenv("TMPDIR") == NULL)
#ifdef _WIN32
                  _tmpPath = (PChar)strdup(".");
#else
                  _tmpPath = (PChar)strdup("/tmp");
#endif
               else
                  _tmpPath = (PChar)strdup( getenv("TMPDIR") );

               VSAddINITParameter ( (*pp_config)->pInitParams->pInitParam,
                                    (*pp_config)->pInitParams->usInitParams,
                                    _initparams[x].tCode,
                                    _initparams[x].tType,
                                    strlen((const char*)_tmpPath),
                                    (PChar)_tmpPath
                                  );
           }/* CCQ_ON */
        break;
        default:
            VSAddINITParameter ( (*pp_config)->pInitParams->pInitParam,
                                 (*pp_config)->pInitParams->usInitParams,
                                 _initparams[x].tCode,
                                 _initparams[x].tType,
                                 _initparams[x].lLength,
                                 _initparams[x].pvValue
                               );
        break;
        }
    }

    /* default for scanaccesslocal */
    if(pClamdaemon) {
        _optparams[1].pvValue = 0;
    }
    for(x=0; x<opar;x++)
    {
       /*  opar : number of entries in optparams
           x    : actual index
           we add parameters from the default structure and set this as default config structure 
        */
        if(_optparams[x].tType == VS_TYPE_CHAR)
        {
            VSAddOPTParameter((*pp_config)->pOptParams->pOptParam,
                (*pp_config)->pOptParams->usOptParams,
                _optparams[x].tCode,
                _optparams[x].tType,
                _optparams[x].lLength,
                strdup((const char*)_optparams[x].pvValue)
                );
        }
        else
        {
            VSAddOPTParameter((*pp_config)->pOptParams->pOptParam,
                (*pp_config)->pOptParams->usOptParams,
                _optparams[x].tCode,
                _optparams[x].tType,
                _optparams[x].lLength,
                _optparams[x].pvValue
                );
        }
     
    }

    /*--------------------------------------------------------------------*/
    /* set adapter features   */
    /*--------------------------------------------------------------------*/
#ifdef VSI2_COMPATIBLE
    (*pp_config)->uiVsaActionFlags = VSA_AP_CHECKMIMETYPE | VSA_AP_SCAN | VSA_AP_BLOCKACTIVECONTENT;
#else
    (*pp_config)->uiVsaActionFlags = VSA_AP_SCAN;
#endif

    (*pp_config)->uiVsaScanFlags   =     VSA_SP_FILE | VSA_SP_BYTES;

    (*pp_config)->uiVsaEvtMsgFlags =     uigVS_SAP_ALL;
    /* No client I/O callback supported for this VSA version
     * Otherwise you should set here the callback flags for CIO support.
     */
    (*pp_config)->uiVsaCIOMsgFlags =     0;

    /*--------------------------------------------------------------------*/
    /* set adapter info constants                                         */
    /*--------------------------------------------------------------------*/
    (*pp_config)->pAdapterInfo->struct_size          = sizeof(VSA_ADAPTERINFO);
    (*pp_config)->pAdapterInfo->usVsiVersion         = VSI_VERSION;
    (*pp_config)->pAdapterInfo->usVsaMajVersion      = VSA_ADAPTER_MAJVER;
    (*pp_config)->pAdapterInfo->usVsaMinVersion      = VSA_ADAPTER_MINVER;
    (*pp_config)->pAdapterInfo->tAdapterID           = VS_AD_CLAM;
    (*pp_config)->pAdapterInfo->tThreadingModel      = VS_THREAD_FREE; 
    SETERRORTEXT((*pp_config)->pAdapterInfo->pszVendorInfo , VSA_VENDORINFO );
    SETERRORTEXT((*pp_config)->pAdapterInfo->pszAdapterName ,VSA_ADAPTERNAME );

cleanup:
    if (rc == VSA_OK)
    {
        return (VSA_OK);
    }
    else
    {
        freeVSA_CONFIG(pp_config);
        return (rc);
    }

} /* VsaGetConfig */


/**********************************************************************
 *  VsaInit()
 *
 *  Description:
 *     Initializes or creates a new scan engine instance.
 *     Then assigns all the vendor specific data structures from
 *     actual AV product to VSA data structure.<nl>
 *     "REQ" (required) parameters are mandatory. <nl>
 *     "OPT" (optional) parameters are not mandatory.
 *
 *  Returncodes:
 *  VSA_OK                   |      Success
 *  VSA_E_EXPIRED            |      Engine or driver expired
 *  VSA_E_NO_SPACE           |      Any resource allocation failed 
 *  VSA_E_LOAD_FAILED        |      Load failed (such as external process)
 *  VSA_E_BAD_EXPRESSION     |      Regular expression syntax is invalid
 *  VSA_E_NULL_PARAM         |      NULL pointer provided
 *  VSA_E_INVALID_PARAM      |      At least one parameter is invalid
 *  VSA_E_DRIVER_FAILED      |      At least one driver failed
 *  VSA_E_NOT_SUPPORTED      |      At least one parameter or object is not supported
 *  VSA_E_CIO_FAILED         |      Client I/O request action failed.
 *  VSA_E_NOT_INITIALISED    |      Global initialization not successful
 *  VSA_E_CBC_TERMINATED     |      Action was terminated during callback
 *
 **********************************************************************/
VSA_RC 
DLL_EXPORT VsaInit( const PVSA_CALLBACK p_callback, 
                    const PVSA_INITPARAMS p_initparams, 
                          PPVSA_INIT pp_init )
{
    VSA_RC                     rc           = VSA_OK;
    Int                        i            = 0;
    size_t                     len          = 0;
    PChar                      pDriverName;
    PChar                      szinitDrivers= NULL;
    INITDATA                   initConfig   = {NULL,NULL,NULL};
    PCLAMDCON                  pConnection  = NULL;
    struct tm                 _utc_date = { 0,      /* hours                    */
                                            0,      /* daylight                 */
                                            0,      /* day of month (1-31)      */
                                            0,      /* minutes after hour (0-59)*/
                                            0,      /* month (0-11, january=0)  */
                                            0,      /* seconds after min (0-59) */
                                            0,      /* day of week, 0-6,Sun=0   */
                                            0,      /* day of year, 0-365,Jan1=0*/
                                            0};     /* year (current minus 1900 */
    /*   ----- clam param ---- */
    unsigned int sigs = 0;
    if(pp_init == NULL)
        return VSA_E_NULL_PARAM; /* no handle */

    if(bgInit == FALSE) 
    {
        SETERRORTEXT((*pp_init)->pszErrorText, "VsaStartup not yet called or not successful");
        (*pp_init)->iErrorRC = 5;
        return VSA_E_NOT_INITIALISED; /* no successful VsaStartup */
    }

    /* Comment:
     * In the VsaInit function you should either connect/contact your
     * internal engine or allocate memory for the scan instance.
     * The structure VSA_INIT contains several flags which should help you
     * to pass your scan handle, internal license information, flags and so on to
     * the VsaScan function.
     */
    /* Initialize VSA_INIT structure */
    (*pp_init)          =   (PVSA_INIT)calloc(1,sizeof(VSA_INIT));
    if ((*pp_init) == NULL) {
        (*pp_init)->iErrorRC = 5;
        CLEANUP(VSA_E_NO_SPACE);
    }
        /* sizeof */
    (*pp_init)->struct_size = sizeof(VSA_INIT);
    rc = vsaSetInitConfig(p_initparams,&initConfig);
    if(rc) {
        (*pp_init)->iErrorRC = (int)VSA_E_NOT_SUPPORTED;
        SETERRORTEXT((*pp_init)->pszErrorText, "At least one INIT parameter is not support");
        CLEANUP(rc);
    }
    /* CCQ_OFF */
    pConnection = (PCLAMDCON)calloc(1,sizeof(CLAMDCON));
    if(pConnection == NULL) {
        (*pp_init)->iErrorRC = (int)VSA_E_NO_SPACE;
        SETERRORTEXT((*pp_init)->pszErrorText, "Memory allocation failed");
        CLEANUP(VSA_E_NO_SPACE);
    }
    if(initConfig.server) {
        rc = vsaparseURI((PChar)initConfig.server->pvValue,&pConnection->bLocal,&pConnection->pProtocol,&pConnection->pServer,&pConnection->pPort);
    }
    else {
        Char _dir[1024];
        if(pClamdaemon) {
          snprintf((char*)_dir,sizeof(_dir),"%.1022s",pClamdaemon);
        } else {
          snprintf((char*)_dir,sizeof(_dir),"%.20s://%.512s:%.128s",DEFAULT_PROTOCOL,DEFAULT_SERVER,DEFAULT_PORT);
        }
        rc = vsaparseURI(_dir,&pConnection->bLocal,&pConnection->pProtocol,&pConnection->pServer,&pConnection->pPort);
    }
    if(rc) {
        (*pp_init)->iErrorRC = (int)VSA_E_LOAD_FAILED;
        SETERRORTEXT((*pp_init)->pszErrorText, "Parsing INITSERVERS failed");
        CLEANUP(rc);
    }
    rc = vsaConnectd(pConnection->pServer, pConnection->pPort, (PChar)"VERSION",&pDriverName);
    if(rc) {
        Char  _error[1024];
        (*pp_init)->iErrorRC = 7;
        snprintf((char*)_error,sizeof(_error),"Connect to ClamAV daemon (process clamd) failed. Connected host: %.512s on port: %.128s.", pConnection->pServer, pConnection->pPort);
        SETERRORTEXT((*pp_init)->pszErrorText, _error);
        CLEANUP(rc);
    }
    /* CCQ_ON */
    /* Important hint:
     * Set hEngine with a value != NULL,
     * here you should set the HANDLE of your internal
     * engine instance.
     */ 
    (*pp_init)->uiViruses   = 1;
    (*pp_init)->uiExtensions= 0;
    (*pp_init)->uiIntRevNum = 0;
    (*pp_init)->uiSignature = 0xbbbbbbbb; /* add here an own magic */
    (*pp_init)->usDrivers   = 0;
    (*pp_init)->usEngineMajVersion = VSA_ADAPTER_MAJVER;
    (*pp_init)->usEngineMinVersion = VSA_ADAPTER_MINVER;
    SETSTRING( (*pp_init)->pszEngineVersionText, pDriverName );
     /* convert date to calendar date *//*CCQ_CLIB_LOCTIME_OK*/
    (*pp_init)->utcDate     = time(NULL);
    /* set VSA_DRIVERINFO structure */
    (*pp_init)->iErrorRC    = 0;
    (*pp_init)->pDriver     = (PVSA_DRIVERINFO)calloc(MAX_DRIVERS,sizeof(VSA_DRIVERINFO));
    if ((*pp_init)->pDriver == NULL) {
        (*pp_init)->iErrorRC = 5;
        CLEANUP(VSA_E_NO_SPACE);
    }

    /* CCQ_OFF */
    (*pp_init)->hEngine     = (PVoid)pConnection;
    (*pp_init)->uiViruses   = sigs;
    /* CCQ_ON */
    /*
     * Comment: 
     * We allocate one driver info to demonstrate the use case.
     * The VSA specification does not dictate the usage of VSA_DRIVERINFO.
     * The information here will only be displayed at SAP internal applications,
     * but this information should help you later to analyze with which pattern
     * files your engine runs.
     * This information also helps any customer to see which version of pattern
     * files are loaded.
     */    
    do {
       /* CCQ_OFF */       
       while(pDriverName!=NULL)
       {
          (*pp_init)->pDriver[i].pszName = (PChar)malloc(strlen((const char*)pDriverName) + 3);
          if((*pp_init)->pDriver[i].pszName == NULL) {
              (*pp_init)->iErrorRC = 5;
              CLEANUP(VSA_E_NO_SPACE);
          }

          sprintf((char*)(*pp_init)->pDriver[i].pszName,"%s", pDriverName);
          if(pDriverName)
          {
              (*pp_init)->pDriver[i].utcDate   = time(NULL);
              (*pp_init)->pDriver[i].uiViruses = 0;
              (*pp_init)->pDriver[i].iDriverRC = 0;
              (*pp_init)->pDriver[i].usDrvMajVersion  = VSA_ADAPTER_MAJVER;
              (*pp_init)->pDriver[i].usDrvMinVersion  = VSA_ADAPTER_MINVER;
          }
          else
          {
              /* convert date to calendar date *//*CCQ_CLIB_LOCTIME_OK*/
              (*pp_init)->pDriver[i].utcDate = mktime(&_utc_date);
              (*pp_init)->pDriver[i].uiViruses        = 0;
              (*pp_init)->pDriver[i].uiVariants       = 0;  
              (*pp_init)->pDriver[i].iDriverRC        = -1;
              (*pp_init)->pDriver[i].usDrvMajVersion  = 1;
              (*pp_init)->pDriver[i].usDrvMinVersion  = 0;
          }
          (*pp_init)->pDriver[i].struct_size      = sizeof(VSA_DRIVERINFO);
          (*pp_init)->usDrivers++;
          i++;
          if(pDriverName) free( pDriverName );
          pDriverName = NULL;
       }       
    } while( pDriverName );/* CCQ_ON */
    
cleanup:
    if(szinitDrivers) free(szinitDrivers);
    if (rc != VSA_OK)
    {
        if((*pp_init)->pszErrorText==NULL) SETSTRING( (*pp_init)->pszErrorText, "Error in VsaInit occured" );
        if (pp_init && (*pp_init) && (*pp_init)->iErrorRC == 0)
            freeVSA_INIT(pp_init);
    }
    else
    {   /* increase the ref. counter */
        lgRefCounter++;
        SETSTRING( (*pp_init)->pszErrorText, "No error" );
    }
    return (rc);
} /* VsaInit */



/**********************************************************************
 *  VsaScan()
 *
 *  Description:
 *     Performs the scan. Requires a valid instance handle VSA_INIT from
 *     <f VsaInit>. If the VSA should not perform any callback during the
 *     scan action, then the parameter pVsaScanparam can be set to NULL.
 *     The address of a handle to a <t VSA_SCANINFO> structure can optionally
 *     be provided. This means if "ppVsaScaninfo" is set to NULL, the VSA
 *     will not return any information about the scan action.
 *     This allows the caller to decide, if [only] callbacks [or \| and]
 *     [only] the VSA_SCANINFO structure should be returned. <nl>
 *     "REQ" (required) parameters are mandatory. <nl>
 *     "OPT" (optional) parameters are not mandatory.
 *
 *  Returncodes:
 *  Virus error codes (negative values):
 *  VSA_E_CLEAN_FAILED         |    Removing/replacing infection failed
 *  VSA_E_PATTERN_FOUND        |    Pattern was found
 *  VSA_E_MACRO_FOUND          |    Macro was found
 *  VSA_E_VIRUS_FOUND          |    Virus was found
 *  VSA_E_CLEAN_OK             |    The clean action was successful
 *  No error, no virus:
 *  VSA_OK                     |    Success
 *  Program error codes (positive values):
 *  VSA_E_NO_SPACE             |    Any resource allocation failed 
 *  VSA_E_NULL_PARAM           |    NULL pointer provided
 *  VSA_E_INVALID_PARAM        |    At least one parameter is invalid
 *  VSA_E_INVALID_HANDLE       |    The provided handle is invalid
 *  VSA_E_NOT_INITIALISED      |    The adapter was not successfully initialized
 *  VSA_E_NOT_SUPPORTED        |    At least one parameter or object is not supported
 *  VSA_E_INVALID_SCANOBJECT   |    See VSA_SCANPARAM, object is invalid
 *  VSA_E_CIO_FAILED           |    Client I/O failed. Scan could not be performed.
 *  VSA_E_SCAN_FAILED          |    The scan action failed
 *  VSA_E_NOT_SCANNED          |    At least one object was not scanned
 *  VSA_E_CBC_TERMINATED       |    Action was terminated during callback
 *
 **********************************************************************/
VSA_RC 
DLL_EXPORT VsaScan(
                 const PVSA_INIT      p_init, 
                 const PVSA_CALLBACK  p_callback,
                 const PVSA_SCANPARAM p_scanparam,
                 const PVSA_OPTPARAMS p_optparams, 
                 PPVSA_SCANINFO pp_scinfo
                )
{
    VSA_RC              rc              = VSA_OK;
    int                 clam_rc         = 0;
    VS_CALLRC           _vsa_rc         = VS_CB_OK;
    size_t              len             = 0;    
    VSA_EVENTCBFP       cfunc           = NULL;
    UInt                uiMsgFlag       = 0;
    VSA_USRDATA         pvUsrdata       = NULL;
    VSA_ENGINE          heng            = NULL;
    PChar               pszBuffer       = NULL;
    PChar               pszReason       = NULL;
    PVSA_SCANERROR      p_scanerror     = NULL;
    PVSA_VIRUSINFO      p_virusinfo     = NULL;
    PCLAMDCON           pConnection     = NULL;
    FILE                *_fp            = NULL;
    PChar               pAnswer         = NULL;
#ifndef VSI2_COMPATIBLE
    char                command[1024];
#endif
    const char         *virname = NULL;
    USRDATA             usrdata;
#ifdef VSI2_COMPATIBLE
    PChar               pszObjName = NULL;
    Char                szExt[EXT_LN] = ".*";
    Char                szExt2[EXT_LN] = ".*";
    Char                szErrorName[1024];
    Char                szErrorFreeName[1024];
    Char                szMimeType[MIME_LN] = "unknown/unknown";
#endif

    memset(&usrdata,0,sizeof(USRDATA));

    if(bgInit == FALSE) {
        pszReason = (PChar)"Adapter is not initialized";
        CLEANUP(VSA_E_NOT_INITIALISED); /* no successful VsaStartup */
    }

    if(p_init == NULL) {
        pszReason = (PChar)"Adapter initialization handle missing ";
        CLEANUP(VSA_E_NULL_PARAM);
    }

    if(p_scanparam == NULL) {
        pszReason = (PChar)"Scan parameter structure is null";
        CLEANUP(VSA_E_NULL_PARAM);
    }

    /*--------------------------------------------------------------------*/
    /* check structure size to protect yourself against different versions*/
    /*--------------------------------------------------------------------*/
    if(p_scanparam->struct_size != sizeof(VSA_SCANPARAM)) {
        pszReason = (PChar)"Scan parameter structure with wrong initialization size";
        CLEANUP(VSA_E_INVALID_PARAM);
    }

    pConnection = (PCLAMDCON)p_init->hEngine;
    if(pConnection == NULL || pConnection->pServer == NULL || pConnection->pPort == NULL) {
        pszReason = (PChar)"Connection parameter not available";
        CLEANUP(VSA_E_NULL_PARAM);
    }

    /* check callback structure passed to me */
    rc = registerCallback(p_callback,&usrdata);
    if(rc) {
        pszReason = (PChar)"Callback messages not supported";
        CLEANUP(rc);
    }

    uiMsgFlag = usrdata.uiMsgFlags;
    pvUsrdata = usrdata.pvUsrdata;
    cfunc     = usrdata.pvFncptr;
    usrdata.bScanFileLocal = pConnection->bLocal;

    /*
     * allocate VSA_SCANINFO 
     */
    if (pp_scinfo != NULL) {
        (*pp_scinfo)         = (PVSA_SCANINFO)calloc(1,sizeof(VSA_SCANINFO));
        if ((*pp_scinfo) == NULL)
            CLEANUP(VSA_E_NO_SPACE);

        (*pp_scinfo)->struct_size= sizeof(VSA_SCANINFO);
        (*pp_scinfo)->uiJobID    = p_scanparam->uiJobID;
    }
    if(vsaSetOptConfig(p_optparams,&usrdata) != VSA_OK)
    {
        pszReason = (PChar)"Error during parameter setting";
        CLEANUP(VSA_E_NOT_SUPPORTED);
    }
#ifdef VSI2_COMPATIBLE
    /* pre-check based of object-/file-name */
    usrdata.tFileType = VS_OT_UNKNOWN;
    if(p_scanparam->pszObjectName == NULL || *p_scanparam->pszObjectName == 0) {
        pszObjName = (PChar)"BYTES";
    }
    else {
        pszObjName = p_scanparam->pszObjectName;
    }
    /*--------------------------------------------------------------------*/
    /* internal MIME detection                                            */
    /*--------------------------------------------------------------------*/
    getFileType(pszObjName,szExt2,szMimeType,&usrdata.tFileType);
    if((p_scanparam->tActionCode & VSA_AP_CHECKMIMETYPE) == VSA_AP_CHECKMIMETYPE)
    {
        usrdata.bMimeCheck = TRUE;
    }
    if((p_scanparam->tActionCode & VSA_AP_BLOCKACTIVECONTENT) == VSA_AP_BLOCKACTIVECONTENT)
    {
        usrdata.bActiveContent = TRUE;
    }
#else
    /*--------------------------------------------------------------------*/
    /* Check, if the action is VSA_AP_SCAN                                */
    /*--------------------------------------------------------------------*/
    if (p_scanparam->tActionCode != VSA_AP_SCAN)
    {
        pszReason = (PChar)"The VSA does not know this action!";
        CLEANUP(VSA_E_NOT_SUPPORTED);
    }
#endif
    /*--------------------------------------------------------------------*/
    /* Comment:                                                           */
    /* Set scan parameter configuration                                   */ 
    /*--------------------------------------------------------------------*/
    if (rc)
    {
        pszReason = (PChar)"At least one parameter is invalid!";
        CLEANUP(rc);
    }
    /*--------------------------------------------------------------------*/
    /* example callbacks to query whether we should start                 */
    /*--------------------------------------------------------------------*/
    _vsa_rc = CB_FUNC( VS_M_ABORTSCAN, (size_t)p_scanparam->uiJobID );
    if (_vsa_rc == VS_CB_NEXT || _vsa_rc == VS_CB_TERMINATE)
        CLEANUP(VSA_E_CBC_TERMINATED);

    _vsa_rc = CB_FUNC( VS_M_OBJECTFOUND, p_scanparam->pszObjectName );
    if (_vsa_rc == VS_CB_NEXT || _vsa_rc == VS_CB_TERMINATE)
        CLEANUP(VSA_E_CBC_TERMINATED);

#ifdef VSI2_COMPATIBLE
    /*--------------------------------------------------------------------*/
    /* example callbacks to query whether we should start                 */
    /*--------------------------------------------------------------------*/
    if(usrdata.bMimeCheck == TRUE || usrdata.bScanAllFiles == TRUE || usrdata.bActiveContent == TRUE)
    {
        Byte bbyte[65536];
        PByte pBuff = bbyte;
        Bool text = TRUE;
        Bool checkcontent = FALSE;
        int status = 1;
        VS_OBJECTTYPE_T a = VS_OT_UNKNOWN;
        VS_OBJECTTYPE_T b = VS_OT_UNKNOWN;
        size_t current_read = 0;

        if(p_scanparam->tScanCode == VSA_SP_BYTES) {
            usrdata.lObjectSize = p_scanparam->lLength;
        }
        else {
            rc = getFileSize(p_scanparam->pszObjectName,&usrdata.lObjectSize);
            if(rc) {
                pszReason = (PChar)"The file could not be opened!";
                CLEANUP(VSA_E_SCAN_FAILED);
            }
        }
        if(p_scanparam->tScanCode == VSA_SP_BYTES) {
            checkcontent = TRUE;
        }
        else {
            memset(bbyte,0,sizeof(bbyte));
            _fp = fopen((const char*)p_scanparam->pszObjectName,"rb");
            if(_fp != NULL) {
                checkcontent = TRUE;
            }
        }
        if(checkcontent) {
            do {
                if(p_scanparam->tScanCode == VSA_SP_BYTES) {
                    pBuff = p_scanparam->pbByte;
                    current_read =  p_scanparam->lLength;
                    rc = getByteType(pBuff,p_scanparam->lLength,p_scanparam->pszObjectName,szExt2,szExt,szMimeType,0,&status,&text,&a,&b,&usrdata.tFileType,&usrdata.tObjectType);
                }
                else {
                    current_read = fread(pBuff,1,sizeof(bbyte) - 1,_fp);
                    if(current_read == 0) break;
                    rc = getByteType(pBuff,(current_read < sizeof(bbyte) - 1) ? current_read : sizeof(bbyte) - 1,p_scanparam->pszObjectName,szExt2,szExt,szMimeType,0,&status,&text,&a,&b,&usrdata.tFileType,&usrdata.tObjectType);
                }
                if(usrdata.bActiveContent == TRUE)
                {
                    rc = check4ActiveContent(pBuff,current_read,usrdata.tObjectType,usrdata.bPdfAllowOpenAction);
                    if(rc) {
                        if(pp_scinfo != NULL && (*pp_scinfo) != NULL) {
                            addVirusInfo(p_scanparam->uiJobID,
                                p_scanparam->pszObjectName,
                                usrdata.lObjectSize,
                                FALSE,
                                VS_DT_ACTIVECONTENT,
                                VS_VT_PUA,
                                usrdata.tObjectType,
                                VS_AT_BLOCKED,
                                0,
                                (PChar)"Embedded script found",
                                (PChar)"Active content block",
                                (*pp_scinfo)->uiInfections++,
                                &(*pp_scinfo)->pVirusInfo);
                        }
                        SET_VSA_RC(rc);
                        CLEANUP(rc);
                    }
                }
                if(usrdata.bMimeCheck == TRUE)
                {
                    rc = checkContentType(
                        szExt,
                        szMimeType,
                        usrdata.pszScanMimeTypes,
                        usrdata.pszBlockMimeTypes,
                        usrdata.pszScanExtensions,
                        usrdata.pszBlockExtensions,
                        szErrorName,
                        szErrorFreeName);
                    if(rc) {
                        if(pp_scinfo != NULL && (*pp_scinfo) != NULL) {
                            addVirusInfo(p_scanparam->uiJobID,
                                p_scanparam->pszObjectName,
                                usrdata.lObjectSize,
                                FALSE,
                                VS_DT_MIMEVALIDATION,
                                VS_VT_NOVIRUS,
                                usrdata.tObjectType,
                                VS_AT_BLOCKED,
                                0,
                                szErrorName,
                                szErrorFreeName,
                                (*pp_scinfo)->uiInfections++,
                                &(*pp_scinfo)->pVirusInfo);
                        }
                        SET_VSA_RC(rc);
                        CLEANUP(rc);
                    }
                }
                /* no loop for byte scan */
                if(p_scanparam->tScanCode == VSA_SP_BYTES) {
                    current_read = 0;
                }
            } while(current_read > 0 || rc != VSA_OK);
        }
        FCLOSE_SAFE(_fp);
        if(rc) CLEANUP(rc);
        if(usrdata.tFileType != usrdata.tObjectType)
        {
            if(strlen((const char*)szExt2) == 0 || (usrdata.tFileType == VS_OT_UNKNOWN && usrdata.tObjectType == VS_OT_BINARY))
            {
                /* Here we found an unknown binary object, use external MIME type detection
                */
                PChar pMType = vsaGetFileMimeType(p_scanparam->pszObjectName);
                if(pMType && (unsigned int)strlen((const char*)pMType) < (unsigned int)MIME_LN) {
                    sprintf((char*)szMimeType,"%s",pMType);
                }
                if((unsigned)strlen((const char*)szExt2) > 0) {
                    sprintf((char*)szExt,"%s",szExt2);
                }
                if(pMType) free(pMType);
            }
            else
            {
                rc = getFileSize(p_scanparam->pszObjectName,&usrdata.lObjectSize);
                if(usrdata.bMimeCheck == TRUE)
                {
                    sprintf((char*)szErrorName,"Extension (%.100s) is not compatible to MIME type (%.850s)",(const char*)szExt2,(const char*)szMimeType);
                    if(pp_scinfo != NULL && (*pp_scinfo) != NULL) {
                        addVirusInfo(p_scanparam->uiJobID,
                            p_scanparam->pszObjectName,
                            usrdata.lObjectSize,
                            FALSE,
                            VS_DT_MIMEVALIDATION,
                            VS_VT_NOVIRUS,
                            usrdata.tObjectType,
                            VS_AT_BLOCKED,
                            0,
                            szErrorName,
                            (PChar)"The extra content check is active, therefore file extension must be compatible to the detected MIME type",
                            (*pp_scinfo)->uiInfections++,
                            &(*pp_scinfo)->pVirusInfo);
                    }
                    SET_VSA_RC(VSA_E_BLOCKED_BY_POLICY);
                    _vsa_rc = CB_FUNC(VS_M_VIRUS,(*pp_scinfo)->pVirusInfo);
                    if(_vsa_rc == VS_CB_NEXT || _vsa_rc == VS_CB_TERMINATE)
                        CLEANUP(VSA_E_CBC_TERMINATED);
                    CLEANUP(VSA_E_BLOCKED_BY_POLICY);
                }
            }
        }
        else
        {
            if(usrdata.tObjectType != VS_OT_UNKNOWN && szExt2 != NULL && *szExt2 == '*' && szExt != NULL && *szExt == '.' && *(szExt+1) == '*') {
                sprintf((char*)szExt,"%s",szExt2);
            } else if(usrdata.tObjectType == VS_OT_TEXT && szExt2 != NULL && *szExt2 == '*') {
                sprintf((char*)szExt,"%s",szExt2);
            }
        }
    }
    else
    {
        usrdata.tObjectType = usrdata.tFileType;
        if(usrdata.tObjectType != VS_OT_UNKNOWN && szExt2 != NULL && *szExt2 == '*' && szExt != NULL && *szExt == '.' && *(szExt+1) == '*') {
            sprintf((char*)szExt,"%s",szExt2);
        } else if(usrdata.tObjectType == VS_OT_TEXT && szExt2 != NULL && *szExt2 == '*') {
            sprintf((char*)szExt,"%s",szExt2);
        }
    }
    if(usrdata.tObjectType == VS_OT_UNKNOWN)
    {
        /* Here we found an unknown binary object, use external MIME type detection
        */
        PChar pMType = vsaGetFileMimeType(p_scanparam->pszObjectName);
        if(pMType && (unsigned int)strlen((const char*)pMType) < (unsigned int)MIME_LN) {
            sprintf((char*)szMimeType,"%s",pMType);
        }
        if((unsigned)strlen((const char*)szExt2) > 0) {
            sprintf((char*)szExt,"%s",szExt2);
        }
        if(pMType) free(pMType);
    }
    if(pp_scinfo != NULL && (*pp_scinfo) != NULL) {
        rc = addContentInfo(p_scanparam->uiJobID,
            p_scanparam->pszObjectName,
            usrdata.lObjectSize,
            usrdata.tObjectType,
            szExt,
            szMimeType,
            NULL,
            (*pp_scinfo)->uiScanned++,
            &(*pp_scinfo)->pContentInfo);
        if(rc) {
            SET_VSA_RC(rc);
            CLEANUP(rc);
        }
    }
    if(pp_scinfo != NULL && (*pp_scinfo) != NULL)
    {
        usrdata.pScanInfo = (*pp_scinfo);
    }
#endif
    /*--------------------------------------------------------------------*/
    /* Comment:                                                           */
    /* Start here to process the different action types.                  */
    /* First we perform some plausi checks                                */
    /*--------------------------------------------------------------------*/
    /* 
    * Scan local file
    */
    switch(p_scanparam->tScanCode)
    {
    case VSA_SP_BYTES:
#ifdef VSI2_COMPATIBLE
        if(pp_scinfo != NULL && (*pp_scinfo) != NULL)
        {
            usrdata.pScanInfo = (*pp_scinfo);
        }
        rc = scanBuffer(
            p_init->hEngine,
            p_scanparam->uiJobID,
            p_scanparam->pszObjectName,
            p_scanparam->pbByte,
            p_scanparam->lLength,
            &usrdata,
            szErrorName);
        if(rc) SET_VSA_RC(rc);
#else
        usrdata.lObjectSize = p_scanparam->lLength;
        rc = vsaSendBytes2Clamd(pConnection->pServer,pConnection->pPort,NULL,p_scanparam->pbByte,usrdata.lObjectSize,&pAnswer);
        if (rc) 
           {
               pszReason = (PChar)"The buffer could not be scanned!";
               CLEANUP( VSA_E_SCAN_FAILED );
           }
#endif
    break;
    case VSA_SP_FILE:
        {
#ifdef VSI2_COMPATIBLE
            if(pp_scinfo != NULL && (*pp_scinfo) != NULL)
            {
                usrdata.pScanInfo = (*pp_scinfo);
            }
            rc = scanFile(
                p_init->hEngine,
                p_scanparam->uiJobID,
                p_scanparam->pszObjectName,
                &usrdata,
                szErrorName);
            if(rc) SET_VSA_RC(rc);
#else
           rc = getFileSize(p_scanparam->pszObjectName,&usrdata.lObjectSize);
           if (rc) 
           {
               pszReason = (PChar)"The file could not be opened!";
               CLEANUP( VSA_E_SCAN_FAILED );
           } 
           /* CCQ_OFF */
           if((int)strlen((const char*)p_scanparam->pszObjectName) > 1000)
           {
               pszReason = (PChar)"The file name is too long!";
               CLEANUP( VSA_E_SCAN_FAILED );
           }
           if(usrdata.bScanFileLocal == TRUE) {
              sprintf((char*)command,"SCAN %s", p_scanparam->pszObjectName);
              rc = vsaConnectd((PChar)pConnection->pServer,(PChar)pConnection->pPort, (PChar)command,&pAnswer);
              if (rc) 
              {
                 sprintf((char*)command,"The file %256s could not be scanned locally.", p_scanparam->pszObjectName);
                 pszReason = (PChar)command;
                 CLEANUP( VSA_E_SCAN_FAILED );
              }
           } else {
              rc = VSA_E_CIO_FAILED;
              _fp = fopen((const char*)p_scanparam->pszObjectName,"rb");
              if(_fp != NULL)
              rc = vsaSendBytes2Clamd(pConnection->pServer,pConnection->pPort,_fp,NULL,usrdata.lObjectSize,&pAnswer);
              if (rc)
              {
                 sprintf((char*)command,"The file %256s could not be send as stream to server %50s", p_scanparam->pszObjectName,pConnection->pServer);
                 pszReason = (PChar)command;
                 CLEANUP( VSA_E_SCAN_FAILED );
              }
           }
#endif
        }
    break;  
    default:
        pszReason = (PChar)"ClamAV engine supports only the scan of local files";
        CLEANUP(VSA_E_INVALID_SCANOBJECT);
    }
#ifndef VSI2_COMPATIBLE
    pszBuffer = (PChar)strstr((const char*)pAnswer,"OK");
    if(pszBuffer) /* Success */
        clam_rc = 0;
    pszBuffer = (PChar)strstr((const char*)pAnswer,"ERROR");
    if(pszBuffer) /* Scan Error */
    {
        *pszBuffer = 0; /* terminate string */
        clam_rc    = VSA_E_SCAN_FAILED;
    }
    pszBuffer = (PChar)strstr((const char*)pAnswer,"FOUND");
    if(pszBuffer) /* Scan Error */
    {
        *pszBuffer = 0; /* Virus Infection found */
        virname    = strchr((const char*)pAnswer,':');
        if(virname && *(virname+2) && *(virname+1) == ' ')
            virname+=2;
        clam_rc    = 1;
    }
    /* CCQ_ON */
    if (clam_rc != 1)
    {
        pszReason = (PChar)"Not available";
        switch(clam_rc)
        {
        case 0: rc = VSA_OK;
        break;
        case 1: rc = VSA_E_VIRUS_FOUND;
        break;
        case 13:
            pszReason =   (PChar)pAnswer;
            CLEANUP( VSA_E_SCAN_FAILED );
        default:       rc = VSA_E_SCAN_FAILED;
        break;
        }
    }
    else
    {
        rc = VSA_OK;
    }
    /*
     * After the scan
     */
    if( clam_rc == 1 )
    {
        /* found EICAR */
        p_virusinfo = (PVSA_VIRUSINFO)calloc(1,sizeof(VSA_VIRUSINFO));
        
        if(p_virusinfo== NULL)
            CLEANUP(VSA_E_NO_SPACE);
        
        p_virusinfo->struct_size = sizeof(VSA_VIRUSINFO);
        p_virusinfo->bRepairable = FALSE;
        p_virusinfo->lObjectSize = usrdata.lObjectSize;
        SETSTRING( p_virusinfo->pszFreeTextInfo , pAnswer);
        SETSTRING( p_virusinfo->pszObjectName, p_scanparam->pszObjectName);
        SETSTRING( p_virusinfo->pszVirusName, virname);
        p_virusinfo->tActionType = VS_AT_NOACTION;
        p_virusinfo->tDetectType = VS_DT_KNOWNVIRUS;
        p_virusinfo->tVirusType  = VS_VT_VIRUS;
        p_virusinfo->uiVirusID   = 0;
        p_virusinfo->tObjectType = VS_OT_BINARY;

        if(NULL != (PChar)strstr((const char*)virname,"ContainsMacros")) {
            SET_VSA_RC( VSA_E_ACTIVECONTENT_FOUND );
        } else if(NULL != (PChar)strstr((const char*)virname,"Script.PDF.EmbeddedJS")) {
            SET_VSA_RC( VSA_E_ACTIVECONTENT_FOUND );
        } else {
            SET_VSA_RC( VSA_E_VIRUS_FOUND );
        }
        _vsa_rc = CB_FUNC( VS_M_VIRUS, p_virusinfo );
        if (_vsa_rc == VS_CB_NEXT || _vsa_rc == VS_CB_TERMINATE)
            CLEANUP(VSA_E_CBC_TERMINATED);

        if(pp_scinfo != NULL && (*pp_scinfo) != NULL)
        {
            (*pp_scinfo)->uiScanned++;
            (*pp_scinfo)->pVirusInfo = p_virusinfo;
            (*pp_scinfo)->uiInfections++;
        }
        else
        {   
            freevirusinfo(&p_virusinfo);
        }
    }
#endif
    if( rc == VSA_OK )
    {  /*if( scanned > 0 ) *//* only if data was scanned */
       /*{*/
            if(pp_scinfo != NULL && (*pp_scinfo) != NULL)
            {
#ifdef VSI2_COMPATIBLE
                (*pp_scinfo)->uiClean = (*pp_scinfo)->uiScanned;
#else
                (*pp_scinfo)->uiScanned++;
                (*pp_scinfo)->uiClean++;
#endif
            }
            SET_VSA_RC( VSA_OK );
            /* no virus found */
            _vsa_rc = CB_FUNC( VS_M_CLEAN, (size_t)p_scanparam->uiJobID );
            if (_vsa_rc == VS_CB_NEXT || _vsa_rc == VS_CB_TERMINATE)
                CLEANUP(VSA_E_CBC_TERMINATED);
        /*}*/
        /*else
        {
            rc = VSA_E_NOT_SCANNED;
        }*/
    }
#ifdef VSI2_COMPATIBLE
    else
    {
        pszReason = (PChar)szErrorName;
    }
#endif
    /* Exception handling */
cleanup:
    FCLOSE_SAFE(_fp);
    switch(rc)
    {
    case VSA_E_NOT_SUPPORTED:
        SET_VSA_RC( VSA_E_NOT_SUPPORTED );
        setScanError(p_scanparam->uiJobID,
                     p_scanparam->pszObjectName,
                     usrdata.lObjectSize,
                     clam_rc,
                     pszReason,
                     &p_scanerror
                     );
        _vsa_rc = CB_FUNC( VS_M_ERROR, pszReason );
        if (_vsa_rc == VS_CB_NEXT || _vsa_rc == VS_CB_TERMINATE)
            SET_VSA_RC(VSA_E_CBC_TERMINATED);
    break;
    case VSA_E_NOT_SCANNED:
        SET_VSA_RC( VSA_E_NOT_SCANNED );
        setScanError(p_scanparam->uiJobID,
                     p_scanparam->pszObjectName,
                     usrdata.lObjectSize,
                     clam_rc,
                     (PChar)"This object was not scanned",
                     &p_scanerror
                     );
        _vsa_rc = CB_FUNC( VS_M_NOTSCANNED, p_scanerror );
        if (_vsa_rc == VS_CB_NEXT || _vsa_rc == VS_CB_TERMINATE)
            SET_VSA_RC(VSA_E_CBC_TERMINATED);
    break;
    case VSA_E_INVALID_SCANOBJECT:
    case VSA_E_SCAN_FAILED:
        SET_VSA_RC( VSA_E_SCAN_FAILED );
        setScanError(p_scanparam->uiJobID,
                     p_scanparam->pszObjectName,
                     usrdata.lObjectSize,
                     clam_rc,
                     pszReason,
                     &p_scanerror
                     );
        _vsa_rc = CB_FUNC( VS_M_ERROR, pszReason );
        if (_vsa_rc == VS_CB_NEXT || _vsa_rc == VS_CB_TERMINATE)
            SET_VSA_RC(VSA_E_CBC_TERMINATED);
    break;
    default:
    break;    
    }
    if(pAnswer) free(pAnswer);
    if( rc == VSA_E_NOT_SCANNED   ||
        rc == VSA_E_NOT_SUPPORTED ||
        rc == VSA_E_SCAN_FAILED)
    {     
        if(pp_scinfo != NULL && (*pp_scinfo) != NULL)
        {
            (*pp_scinfo)->pScanError    =   p_scanerror;
            (*pp_scinfo)->uiScanErrors++;
            (*pp_scinfo)->uiNotScanned++;
        }
        else
        {
            freescanerror(&p_scanerror);
        }
    }
    if (rc == 0)
        rc = usrdata.vsa_rc; /* set now the saved RC to return value */
    if (rc == 0)
        return VSA_OK;
    else if (usrdata.vsa_rc == 0) /* program error , otherwise the Virus error would be 0 */ 
    {
        VsaReleaseScan(pp_scinfo);
    }
    if(usrdata.pszBlockExtensions) free(usrdata.pszBlockExtensions);
    if(usrdata.pszBlockMimeTypes)  free(usrdata.pszBlockMimeTypes);
    if(usrdata.pszScanExtensions)  free(usrdata.pszScanExtensions);
    if(usrdata.pszScanMimeTypes)   free(usrdata.pszScanMimeTypes);
    return (rc);
} /* VsaScan */


/**********************************************************************
 *  VsaReleaseScan()
 *
 *  Description:
 *     Release the dynamically allocated struture VSA_SCANINFO. The address of the
 *     of the handle is required but the handle can also point to NULL. <nl>
 *     "REQ" (required) parameters are mandatory. <nl>
 *     "OPT" (optional) parameters are not mandatory.
 *  
 *  Returncodes:
 *  VSA_OK                   |      Success
 *  VSA_E_NOT_INITIALISED    |      Global initialization not successful
 *  VSA_E_NULL_PARAM         |      NULL pointer provided
 *
 **********************************************************************/
VSA_RC 
DLL_EXPORT VsaReleaseScan(PPVSA_SCANINFO ppscinfo)
{
    UInt i = 0;

    if(bgInit == FALSE)
        return VSA_E_NOT_INITIALISED; /* no successful VsaStartup */
    if(ppscinfo == NULL)
        return VSA_E_NULL_PARAM;
    /*--------------------------------------------------------------------*/
    /* free the VSA_SCANINFO structure and sub structure VSA_SCANINFO     */
    /*--------------------------------------------------------------------*/
    if( ppscinfo != NULL && (*ppscinfo) != NULL && (*ppscinfo)->pVirusInfo != NULL )
    {
        for(i=0 ; i < (UInt)((*ppscinfo)->uiInfections); i++)
        {
            freevirusinfo2(&((*ppscinfo)->pVirusInfo[i]));
        }
        free((*ppscinfo)->pVirusInfo);
        (*ppscinfo)->pVirusInfo = NULL;
    }
    /*--------------------------------------------------------------------*/
    /* free VSA_SCANERROR                                                 */
    /*--------------------------------------------------------------------*/
    if( ppscinfo != NULL && (*ppscinfo) != NULL && (*ppscinfo)->pScanError != NULL)
    {
        for(i=0 ; i < (UInt)((*ppscinfo)->uiScanErrors); i++)
        {
            freescanerror2(&((*ppscinfo)->pScanError[i]));
        }
        free((*ppscinfo)->pScanError);
        (*ppscinfo)->pScanError = NULL;
    }
    /*--------------------------------------------------------------------*/
    /* free VSA_CONTENTINFO                                               */
    /*--------------------------------------------------------------------*/
    if(ppscinfo != NULL && (*ppscinfo) != NULL && (*ppscinfo)->pContentInfo != NULL)
    {
        for(i = 0; i < (UInt)((*ppscinfo)->uiScanned); i++)
        {
            freecontentinfo2(&((*ppscinfo)->pContentInfo[i]));
        }
        free((*ppscinfo)->pContentInfo);
        (*ppscinfo)->pContentInfo = NULL;
    }
    /*--------------------------------------------------------------------*/
    /* free the pointer and reset it, so that the callee receives NULL    */
    /*--------------------------------------------------------------------*/
    if( (*ppscinfo) != NULL) {
        free((*ppscinfo));
        (*ppscinfo) = NULL;
    }        
    return (VSA_OK);

} /* VsaReleaseScan */


/**********************************************************************
 *  VsaEnd()
 *
 *  Description:
 *     Closes the engine instance. Releases also VSA_CONFIG allocated
 *     by VsaGetConfig - assumes that the actual job is done there. <nl>
 *     "REQ" (required) parameters are mandatory. <nl>
 *     "OPT" (optional) parameters are not mandatory.
 *
 *  Returncodes:
 *  VSA_OK                     |    Success
 *  VSA_E_NULL_PARAM           |    NULL pointer provided
 *  VSA_E_NOT_INITIALISED      |    Global initialization not successful
 *  VSA_E_END_FAILED           |    The AV engine could not be closed
 *  VSA_E_IN_PROGRESS          |    Any thread is still running
 *
 **********************************************************************/
VSA_RC 
DLL_EXPORT VsaEnd(PPVSA_INIT pp_init, PPVSA_CONFIG pp_config)
{ 
    VSA_RC        rc    = VSA_OK;
    
    if(bgInit == FALSE)
        CLEANUP( VSA_E_NOT_INITIALISED ); /* no successful VsaStartup */
    if(pp_init == NULL || pp_config == NULL)
        CLEANUP( VSA_E_NULL_PARAM );
    /*--------------------------------------------------------------------*/
    /* free VSA_INIT                                                      */
    /*--------------------------------------------------------------------*/
    if (pp_init != NULL && (*pp_init) != NULL)
    {
        PCLAMDCON pConnection = (PCLAMDCON)(*pp_init)->hEngine;
        if(pConnection) {
            if(pConnection->pProtocol) free(pConnection->pProtocol);
            if(pConnection->pServer)   free(pConnection->pServer);
            if(pConnection->pPort)     free(pConnection->pPort);
            free(pConnection);
        }
        freeVSA_INIT(pp_init);
    }   
        
    freeVSA_CONFIG(pp_config);

cleanup:

    return (rc);
} /* VsaEnd */


/**********************************************************************
 *  VsaCleanup()
 *
 *  Description:
 *     Global cleanup for the adapter. This function will be called at last
 *     before unloading the VSA.
 *
 *  Returncodes:
 *  VSA_OK                     |    Success
 *  VSA_E_NOT_INITIALISED      |    Global initialization not successful
 *  VSA_E_IN_PROGRESS          |    Any thread is still running
 *
 **********************************************************************/
VSA_RC 
DLL_EXPORT VsaCleanup( void )
{
    /* 
     * cleanup
     */
    if(bgInit == FALSE)
        return VSA_E_NOT_INITIALISED; /* no successful VsaStartup */
    
    if(lgRefCounter != (size_t)0)
        return VSA_E_IN_PROGRESS;     /* any instance is still active */
    /*--------------------------------------------------------------------*/
    /* The cleanup will be called process global                          */
    /*--------------------------------------------------------------------*/
#ifdef _WIN32
    WSACleanup();
#endif
#ifdef VSI2_COMPATIBLE
    if(pLoadError) {
        free(pLoadError);
        pLoadError = NULL;
    }
    vsaCloseMagicLibrary();
#endif
    bgInit = FALSE;
    return VSA_OK;
} /* VsaCleanup */


/**********************************************************************
 **********************************************************************
 *
 *
 *  PRIVATE helper/auxiliary functions, here only for this prototype implementation
 *  If you would built an adapter, then you can decide by yourself, 
 *  which parts you want have here or not.
 *
 *
 **********************************************************************
 **********************************************************************/
static VSA_RC setScanError(UInt            uiJobID,
                           PChar           pszObjectName,
                           size_t          lObjectSize,
                           Int             iErrorRC,
                           PChar           pszErrorText,
                           PPVSA_SCANERROR pp_scanerror)
{

    size_t len = 0;
    VSA_RC rc  = VSA_OK;

    if (pp_scanerror == NULL)
        return VSA_E_NULL_PARAM;

   (*pp_scanerror) = (PVSA_SCANERROR)calloc(1,sizeof(VSA_SCANERROR));
        
    if( (*pp_scanerror) == NULL)
        return VSA_E_NO_SPACE;
  
    (*pp_scanerror)->struct_size = sizeof(VSA_SCANERROR);
    if(pszObjectName)
        SETSTRING( (*pp_scanerror)->pszObjectName, pszObjectName );
    (*pp_scanerror)->lObjectSize = lObjectSize;
    (*pp_scanerror)->iErrorRC    = iErrorRC;
    if(pszErrorText)
        SETSTRING( (*pp_scanerror)->pszErrorText, pszErrorText );
    (*pp_scanerror)->uiJobID     = uiJobID;
    
cleanup:
    return rc;
} /* setScanError */

static VSA_RC vsaSetInitConfig(VSA_INITPARAMS *p_intparams,
                               INITDATA *usrdata
                               )
{
    VSA_RC     rc        = VSA_OK;
    Int        i         = 0,
               arraysize = (p_intparams?p_intparams->usInitParams:0);
    /*
     * set the initial setting
     */
    for (i=0; i<arraysize; i++)
    {
        switch (p_intparams->pInitParam[i].tCode)
        {
        case VS_IP_INITDRIVERDIRECTORY:
           usrdata->initdirectory = &p_intparams->pInitParam[i];
        break;
        case VS_IP_INITDRIVERS:
           usrdata->drivers = &p_intparams->pInitParam[i];
        break;
        case VS_IP_INITTEMP_PATH:
           usrdata->tmpdir = &p_intparams->pInitParam[i];
        break;
        case VS_IP_INITSERVERS:
           usrdata->server = &p_intparams->pInitParam[i];
        break;
        default:
           return VSA_E_NOT_SUPPORTED;
        }
    }
    return rc;
}

static VSA_RC vsaSetOptConfig(VSA_OPTPARAMS *p_optparams, USRDATA *usrdata)
{
    VSA_RC         rc        = VSA_OK;
    Int            i         = 0,
                   arraysize = (p_optparams?p_optparams->usOptParams:0);
    /*
     * set the initial setting
     */
    for (i=0; i<arraysize; i++)
    {
        /* use a switch here for further enhancement later */
        switch (p_optparams->pOptParam[i].tCode)
        {
        case VS_OP_SCANBESTEFFORT:
            if((p_optparams->pOptParam[i].pvValue) != NULL) {
                usrdata->bScanBestEffort = TRUE;
                usrdata->bScanAllFiles = TRUE;
                usrdata->bScanCompressed = TRUE;
            }
            else {
                usrdata->bScanBestEffort = FALSE;
                usrdata->bScanAllFiles = FALSE;
                usrdata->bScanCompressed = FALSE;
            }
            break;
        case VS_OP_SCANALLFILES:
            if((p_optparams->pOptParam[i].pvValue) != NULL) {
                usrdata->bScanAllFiles = TRUE;
            }
            else {
                usrdata->bScanAllFiles = FALSE;
            }
            break;
        case VS_OP_SCANACCESSFILELOCAL:
            if((p_optparams->pOptParam[i].pvValue) != NULL) {
                usrdata->bScanFileLocal = TRUE;
            }
            else {
                usrdata->bScanFileLocal = FALSE;
            }
        break;
        case VS_OP_SCANEXTRACT:
            if((p_optparams->pOptParam[i].pvValue) != NULL) {
                usrdata->bScanCompressed = TRUE;
            }
            else {
                usrdata->bScanCompressed = FALSE;
            }
            break;
        case VS_OP_SCANEXCLUDEMIMETYPES:
            if ((p_optparams->pOptParam[i].pvValue) != NULL) {
                PChar in = (PChar)(p_optparams->pOptParam[i].pvValue);
                size_t inlen = p_optparams->pOptParam[i].lLength;
                /* CCQ_OFF */
                if (usrdata->bActiveContent && inlen > 0 && *in && (strstr((const char*)in, "application/pdf-openaction"))) {
                    usrdata->bPdfAllowOpenAction = TRUE;
                }
                /* CCQ_ON */
            }
            break;
#ifdef VSI2_COMPATIBLE
        case VS_OP_SCANMIMETYPES:
        case VS_OP_SCANEXTENSIONS:
        case VS_OP_BLOCKMIMETYPES:
        case VS_OP_BLOCKEXTENSIONS:
            rc = vsaSetContentTypeParametes(&p_optparams->pOptParam[i],usrdata);
            if(rc) return rc;
            break;
#endif
        default: break; /* ignore unknown parameter during runtime */
        }
    }
    return rc;
}

#ifdef VSI2_COMPATIBLE
static VSA_RC scanFile(
    void           *pEngine,
    UInt            uiJobID,
    PChar           pszObjectName,
    USRDATA        *pUsrData,
    PChar           errorReason)
{
    int         clam_rc = 0;
    const char *virname = NULL;
    VSA_RC           rc = VSA_OK;
    FILE           *_fp = NULL;
    unsigned int options = 0;
    PChar      pszBuffer = NULL;
    PChar      pAnswer = NULL;
    unsigned long int scanned = 0;
    PCLAMDCON   pConnection   = NULL;
    if(pUsrData == NULL)
        return VSA_E_NULL_PARAM;

    pConnection = (PCLAMDCON)pEngine;
    if(pConnection == NULL || pConnection->pServer == NULL || pConnection->pPort == NULL) {
        sprintf((char*)errorReason,"Connection parameter not available");
        CLEANUP(VSA_E_NULL_PARAM);
    }
    if(pUsrData->tObjectType == VS_OT_SAR)
    {
        if(pUsrData->bScanAllFiles == FALSE && pUsrData->bScanBestEffort == FALSE && pUsrData->bScanCompressed == FALSE)
            CLEANUP(VSA_E_NOT_SCANNED);

        rc = scanCompressed(
            pEngine,
            uiJobID,
            pszObjectName,
            pUsrData,
            errorReason);
    }
    else
    {
        char                command[1024];
        /*
        * Scan local file
        */
        /* CCQ_OFF */
        /* CCQ_OFF */
        if((int)strlen((const char*)pszObjectName) > 1000)
        {
            sprintf((char*)errorReason,"The file name is too long!");
            CLEANUP(VSA_E_SCAN_FAILED);
        }
        if(pUsrData->bScanFileLocal == TRUE) {
            sprintf((char*)command,"SCAN %s",pszObjectName);
            rc = vsaConnectd((PChar)pConnection->pServer,(PChar)pConnection->pPort,(PChar)command,&pAnswer);
            if(rc)
            {
                sprintf((char*)errorReason,"The file %256s could not be scanned locally.", pszObjectName);
                CLEANUP(VSA_E_SCAN_FAILED);
            }
        }
        else {
            if(pUsrData->lObjectSize == 0) {
                rc = getFileSize(pszObjectName,&pUsrData->lObjectSize);
                if(rc)
                {
                    sprintf((char*)errorReason,"The file %s could not be opened!",pszObjectName);
                    CLEANUP(VSA_E_SCAN_FAILED);
                }
            }
            rc = VSA_E_CIO_FAILED;
            _fp = fopen((const char*)pszObjectName,"rb");
            if(_fp != NULL)
                rc = vsaSendBytes2Clamd(pConnection->pServer,pConnection->pPort,_fp,NULL,pUsrData->lObjectSize,&pAnswer);
            if(rc)
            {
                sprintf((char*)errorReason,"The file %256s could not be send as stream to server %50s",pszObjectName,pConnection->pServer);
                CLEANUP(VSA_E_SCAN_FAILED);
            }
        }
        pszBuffer = (PChar)strstr((const char*)pAnswer,"OK");
        if(pszBuffer) /* Success */
            clam_rc = 0;
        pszBuffer = (PChar)strstr((const char*)pAnswer,"ERROR");
        if(pszBuffer) /* Scan Error */
        {
            *pszBuffer = 0; /* terminate string */
            clam_rc = VSA_E_SCAN_FAILED;
        }
        pszBuffer = (PChar)strstr((const char*)pAnswer,"FOUND");
        if(pszBuffer) /* Scan Error */
        {
            *pszBuffer = 0; /* Virus Infection found */
            virname = strchr((const char*)pAnswer,':');
            if(virname && *(virname + 2) && *(virname + 1) == ' ')
                virname += 2;
            clam_rc = 1;
        }
        /* CCQ_ON */
        if(clam_rc != 1)
        {
            sprintf((char*)errorReason,"Not available");
            switch(clam_rc)
            {
            case 0: rc = VSA_OK;
                break;
            case 1: rc = VSA_E_VIRUS_FOUND;
                break;
            case 13:
                sprintf((char*)errorReason,"%s",(PChar)pAnswer);
                CLEANUP(VSA_E_SCAN_FAILED);
            default:       rc = VSA_E_SCAN_FAILED;
                break;
            }
        }
        else
        {
            rc = VSA_OK;
        }
        /*
        * After the scan
        */
        if(clam_rc == 1)
        {
            VSA_RC _RC = VSA_E_VIRUS_FOUND;
            if(NULL != (PChar)strstr((const char*)virname,"ContainsMacros")) {
                _RC = VSA_E_ACTIVECONTENT_FOUND;
            } else if(NULL != (PChar)strstr((const char*)virname,"Script.PDF.EmbeddedJS")) {
                _RC = VSA_E_ACTIVECONTENT_FOUND;
            }
            if(pUsrData != NULL && pUsrData->pScanInfo != NULL) {
                rc = addVirusInfo(uiJobID,
                    pszObjectName,
                    pUsrData->lObjectSize,
                    FALSE,
                    VS_DT_KNOWNVIRUS,
                    VS_VT_TEST,
                    pUsrData->tObjectType,
                    VS_AT_NOACTION,
                    0,
                    (PChar)virname,
                    (PChar)pAnswer,
                    pUsrData->pScanInfo->uiInfections,
                    &pUsrData->pScanInfo->pVirusInfo);
                if(rc) CLEANUP(rc);
                pUsrData->pScanInfo->uiInfections++;
                pUsrData->vsa_rc = _RC;
                if(pUsrData->pvFncptr)
                    pUsrData->vsa_rc = (VSA_RC)pUsrData->pvFncptr((VSA_ENGINE)pEngine,(VS_MESSAGE_T)VS_M_VIRUS,pUsrData->pScanInfo->pVirusInfo,(VSA_USRDATA)pUsrData->pvUsrdata);
                if(pUsrData->vsa_rc == VS_CB_NEXT || pUsrData->vsa_rc == VS_CB_TERMINATE)
                    CLEANUP(VSA_E_CBC_TERMINATED);
            }
            CLEANUP(_RC);
        }
        rc = VSA_OK;
    }
cleanup:
    if(pAnswer) free(pAnswer);
    FCLOSE_SAFE(_fp);
    return rc;
} /* scanFile */

static VSA_RC scanCompressed(
    void           *pEngine,
    UInt            uiJobID,
    PChar           pszObjectName,
    USRDATA        *pUsrData,
    PChar           errorReason)
{
    VSA_RC          rc = VSA_OK;
    int             counter = 0;
    size_t          lLength = 0;
    PChar           pszFileName = NULL;
    Char            szExt[EXT_LN] = ".*";
    PByte           _decompr = NULL;
    Char            szMimeType[MIME_LN] = "unknown/unknown";
    struct SAREntry *_loc = NULL,
        *sentry = ParseEntriesFromFile(pszObjectName);

    if(sentry == NULL) {
        if(pUsrData->bMimeCheck == TRUE || pUsrData->bScanAllFiles == TRUE)
        {
            if(pUsrData != NULL && pUsrData->pScanInfo != NULL) {
                rc = addVirusInfo(uiJobID,
                    pszObjectName,
                    pUsrData->lObjectSize,
                    FALSE,
                    VS_DT_MIMEVALIDATION,
                    VS_VT_CORRUPTED,
                    pUsrData->tObjectType,
                    VS_AT_BLOCKED,
                    0,
                    (PChar)"Corrupted SAR",
                    (PChar)"The archive structure is invalid",
                    pUsrData->pScanInfo->uiInfections,
                    &(pUsrData->pScanInfo->pVirusInfo));
                if(rc) CLEANUP(rc);
                pUsrData->pScanInfo->uiInfections++;
                pUsrData->vsa_rc = VSA_E_BLOCKED_BY_POLICY;
            }
            CLEANUP(VSA_E_BLOCKED_BY_POLICY);
        }
        else
        {
            if(pUsrData != NULL && pUsrData->pScanInfo != NULL) {
                addScanError(uiJobID,
                    pszObjectName,
                    pUsrData->lObjectSize,
                    13,
                    (PChar)"Corrupted SAR file",
                    pUsrData->pScanInfo->uiScanErrors++,
                    &pUsrData->pScanInfo->pScanError);
            }
            CLEANUP(VSA_E_SCAN_FAILED);
        }
    }
    _loc = sentry;
    while(_loc != NULL) {
        if(_loc->type != FT_RG) {
            if(_loc->type != FT_RG) {
                addScanError(uiJobID,
                    (PChar)_loc->name,
                    strlen((const char*)_loc->name),
                    13,
                    (PChar)"Not supported yet",
                    pUsrData->pScanInfo->uiScanErrors,
                    &pUsrData->pScanInfo->pScanError);
                CLEANUP(VSA_E_NOT_SCANNED);
            }
        }
        if(_decompr == NULL) {
            _decompr = (PByte)malloc(_loc->uncompressed_size);
        }
        else {
            _decompr = (PByte)realloc(_decompr,_loc->uncompressed_size);
        }
        if(_decompr == NULL) {
            sprintf((char*)errorReason,"The file buffer for %256s cannot be allocated",_loc->name);
            CLEANUP(VSA_E_SCAN_FAILED);
        }
        lLength = _loc->uncompressed_size;
        pszFileName = (PChar)_loc->name;
        _loc = _loc->next;
        lLength = ExtractEntryFromFile(pszObjectName,counter++,_decompr,lLength);
        if(lLength == 0)
        {
            addScanError(uiJobID,
                pszObjectName,
                lLength,
                13,
                (PChar)"Not extracted",
                pUsrData->pScanInfo->uiScanErrors,
                &pUsrData->pScanInfo->pScanError);
            pUsrData->pScanInfo->uiScanErrors++;
            pUsrData->pScanInfo->uiNotScanned++;
            CLEANUP(VSA_E_NOT_SCANNED);
        }
        else
        {
            Bool text = TRUE;
            int status = 1;
            VS_OBJECTTYPE_T a = VS_OT_UNKNOWN;
            VS_OBJECTTYPE_T b = VS_OT_UNKNOWN;
            rc = getFileType(pszFileName,szExt,szMimeType,&a);
            if(rc) CLEANUP(rc);
            rc = getByteType(_decompr,lLength,pszFileName,NULL,szExt,szMimeType,0,&status,&text,&a,&b,&pUsrData->tFileType,&pUsrData->tObjectType);
            if(rc) CLEANUP(rc);
            rc = addContentInfo(uiJobID,
                pszFileName!=NULL?pszFileName:sentry->name,
                lLength,
                pUsrData->tObjectType,
                szExt,
                szMimeType,
                NULL,
                pUsrData->pScanInfo->uiScanned++,
                &pUsrData->pScanInfo->pContentInfo);
            if(rc) CLEANUP(rc);
            /*
            * Comment:
            * Perform the Active Content Check inside of archive
            */
            if(pUsrData->bActiveContent == TRUE && pUsrData->bScanAllFiles == TRUE && pUsrData->bScanCompressed == TRUE)
            {
                rc = check4ActiveContent(
                    _decompr,
                    lLength,
                    pUsrData->tObjectType,
                    pUsrData->bPdfAllowOpenAction);
                if(rc) CLEANUP(rc);
            }
            /*
            * Comment:
            * Perform the MIME Check inside of archive
            */
            if(pUsrData->bMimeCheck == TRUE && pUsrData->bScanAllFiles == TRUE && pUsrData->bScanCompressed == TRUE)
            {
                Char szErrorName[1024];
                Char szErrorFreeName[1024];
                rc = checkContentType(
                    szExt,
                    szMimeType,
                    pUsrData->pszScanMimeTypes,
                    pUsrData->pszBlockMimeTypes,
                    pUsrData->pszScanExtensions,
                    pUsrData->pszBlockExtensions,
                    szErrorName,
                    szErrorFreeName);
                if(rc) CLEANUP(rc);
            }
            rc = scanBuffer(
                pEngine,
                uiJobID,
                sentry->name,
                _decompr,
                lLength,
                pUsrData,
                errorReason);
        }
    }
cleanup:
    if(_decompr) {
        free(_decompr);
        _decompr = NULL;
    }
    FreeInfo(sentry);
    return rc;
} /* scanCompressed */

static VSA_RC scanBuffer(
    void           *pEngine,
    UInt            uiJobID,
    PChar           pszObjectName,
    PByte           pObject,
    size_t          lObjectSize,
    USRDATA        *pUsrData,
    PChar           errorReason)
{
    VSA_RC         rc = VSA_OK;
    VS_CALLRC _vsa_rc = VS_CB_OK;
    PChar      pAnswer = NULL;
    PChar    pszBuffer = NULL;
    PCLAMDCON  pConnection = NULL;
    int         clam_rc = 0;
    const char *virname = NULL;
    if(pUsrData == NULL) {
        sprintf((char*)errorReason,"User parameter not available");
        return VSA_E_NULL_PARAM;
    }
    pConnection = (PCLAMDCON)pEngine;
    if(pConnection == NULL || pConnection->pServer == NULL || pConnection->pPort == NULL) {
        sprintf((char*)errorReason,"Connection parameter not available");
        CLEANUP(VSA_E_NULL_PARAM);
    }
    if(pUsrData->tObjectType == VS_OT_SAR)
    {
        if(pUsrData->bScanAllFiles == FALSE && pUsrData->bScanBestEffort == FALSE && pUsrData->bScanCompressed == FALSE)
            CLEANUP(VSA_E_NOT_SCANNED);

        rc = scanCompressedBuffer(
                                    pEngine,
                                    uiJobID,
                                    pszObjectName,
                                    pObject,
                                    lObjectSize,
                                    pUsrData,
                                    errorReason);
    }
    else
    {
        rc = vsaSendBytes2Clamd(pConnection->pServer,pConnection->pPort,NULL,pObject,lObjectSize,&pAnswer);
        if(rc)
        {
            sprintf((char*)errorReason,"The file %256s could not be send as stream to server %50s",pszObjectName,pConnection->pServer);
            CLEANUP(VSA_E_SCAN_FAILED);
        }
        pszBuffer = (PChar)strstr((const char*)pAnswer,"OK");
        if(pszBuffer) /* Success */
            clam_rc = 0;
        pszBuffer = (PChar)strstr((const char*)pAnswer,"ERROR");
        if(pszBuffer) /* Scan Error */
        {
            *pszBuffer = 0; /* terminate string */
            clam_rc = VSA_E_SCAN_FAILED;
        }
        pszBuffer = (PChar)strstr((const char*)pAnswer,"FOUND");
        if(pszBuffer) /* Scan Error */
        {
            *pszBuffer = 0; /* Virus Infection found */
            virname = strchr((const char*)pAnswer,':');
            if(virname && *(virname + 2) && *(virname + 1) == ' ')
                virname += 2;
            clam_rc = 1;
        }
        /* CCQ_ON */
        if(clam_rc != 1)
        {
            sprintf((char*)errorReason,"Not available");
            switch(clam_rc)
            {
            case 0: rc = VSA_OK;
                break;
            case 1: rc = VSA_E_VIRUS_FOUND;
                break;
            case 13:
                sprintf((char*)errorReason,"%s",(PChar)pAnswer);
                CLEANUP(VSA_E_SCAN_FAILED);
            default:       rc = VSA_E_SCAN_FAILED;
                break;
            }
        }
        else
        {
            rc = VSA_OK;
        }
        /*
        * After the scan
        */
        if(clam_rc == 1)
        {
            if(pUsrData != NULL && pUsrData->pScanInfo != NULL) {
                rc = addVirusInfo(uiJobID,
                    pszObjectName,
                    pUsrData->lObjectSize,
                    FALSE,
                    VS_DT_KNOWNVIRUS,
                    VS_VT_TEST,
                    pUsrData->tObjectType,
                    VS_AT_NOACTION,
                    0,
                    (PChar)virname,
                    (PChar)"No info available",
                    pUsrData->pScanInfo->uiInfections,
                    &pUsrData->pScanInfo->pVirusInfo);
                if(rc) CLEANUP(rc);
                pUsrData->pScanInfo->uiInfections++;
                pUsrData->vsa_rc = VSA_E_VIRUS_FOUND;
                if(pUsrData->pvFncptr)
                    pUsrData->vsa_rc = (VSA_RC)pUsrData->pvFncptr((VSA_ENGINE)pEngine,(VS_MESSAGE_T)VS_M_VIRUS,pUsrData->pScanInfo->pVirusInfo,(VSA_USRDATA)pUsrData->pvUsrdata);
                if(pUsrData->vsa_rc == VS_CB_NEXT || pUsrData->vsa_rc == VS_CB_TERMINATE)
                    CLEANUP(VSA_E_CBC_TERMINATED);
            }
            CLEANUP(VSA_E_VIRUS_FOUND);
        }
        rc = VSA_OK;
    }
cleanup:
    if(pAnswer) free(pAnswer);
    return rc;
} /* scanBuffer */

static VSA_RC scanCompressedBuffer(
    void           *pEngine,
    UInt            uiJobID,
    PChar           pszObjectName,
    PByte           pObject,
    size_t          lObjectSize,
    USRDATA        *pUsrData,
    PChar           errorReason)
{
    VSA_RC          rc = VSA_OK;
    int             counter = 0;
    size_t          lLength = 0;
    PChar           pszFileName = NULL;
    Char            szExt[EXT_LN] = ".*";
    PByte           _decompr = NULL;
    Char            szMimeType[MIME_LN] = "unknown/unknown";
    struct SAREntry *_loc = NULL,
        *sentry = ParseEntriesFromBuffer(pObject,(SAP_INT)lObjectSize);

    if(sentry == NULL) {
        if(pUsrData->bMimeCheck == TRUE || pUsrData->bScanAllFiles == TRUE)
        {
            rc = addVirusInfo(uiJobID,
                pszObjectName,
                lObjectSize,
                FALSE,
                VS_DT_MIMEVALIDATION,
                VS_VT_CORRUPTED,
                pUsrData->tObjectType,
                VS_AT_BLOCKED,
                0,
                (PChar)"Corrupted SAR",
                (PChar)"The archive structure is invalid",
                pUsrData->pScanInfo->uiInfections,
                &(pUsrData->pScanInfo->pVirusInfo));
            if(rc) CLEANUP(rc);
            pUsrData->pScanInfo->uiInfections++;
            CLEANUP(VSA_E_BLOCKED_BY_POLICY);
        }
        else
        {
            addScanError(uiJobID,
                pszObjectName,
                lObjectSize,
                13,
                (PChar)"Corrupted SAR file",
                pUsrData->pScanInfo->uiScanErrors++,
                &pUsrData->pScanInfo->pScanError);
            CLEANUP(VSA_E_SCAN_FAILED);
        }
    }
    _loc = sentry;
    while(_loc != NULL) {
        if(_loc->type != FT_RG) {
            if(_loc->type != FT_RG) {
                addScanError(uiJobID,
                    (PChar)_loc->name,
                    strlen((const char*)_loc->name),
                    13,
                    (PChar)"Not supported yet",
                    pUsrData->pScanInfo->uiScanErrors,
                    &pUsrData->pScanInfo->pScanError);
                CLEANUP(VSA_E_NOT_SCANNED);
            }
        }
        if(_decompr == NULL) {
            _decompr = (PByte)malloc(_loc->uncompressed_size);
        }
        else {
            _decompr = (PByte)realloc(_decompr,_loc->uncompressed_size);
        }
        if(_decompr == NULL) {
            sprintf((char*)errorReason,"The file buffer for %256s cannot be allocated",_loc->name);
            CLEANUP(VSA_E_SCAN_FAILED);
        }
        lLength = _loc->uncompressed_size;
        pszFileName = (PChar)_loc->name;
        _loc = _loc->next;

        lLength = ExtractEntryFromBuffer(pObject,(SAP_INT)lObjectSize,counter++,_decompr,lLength);
        if(lLength == 0)
        {
            addScanError(uiJobID,
                pszObjectName,
                lObjectSize,
                13,
                (PChar)"Not extracted",
                pUsrData->pScanInfo->uiScanErrors,
                &pUsrData->pScanInfo->pScanError);
            pUsrData->pScanInfo->uiScanErrors++;
            pUsrData->pScanInfo->uiNotScanned++;
            CLEANUP(VSA_E_NOT_SCANNED);
        }
        else
        {
            Bool text = TRUE;
            int status = 1;
            VS_OBJECTTYPE_T a = VS_OT_UNKNOWN;
            VS_OBJECTTYPE_T b = VS_OT_UNKNOWN;
            rc = getFileType(pszFileName,szExt,szMimeType,&a);
            if(rc) CLEANUP(rc);
            rc = getByteType(_decompr,lLength,pszFileName,NULL,szExt,szMimeType,0,&status,&text,&a,&b,&pUsrData->tFileType,&pUsrData->tObjectType);
            if(rc) CLEANUP(rc);
            rc = addContentInfo(uiJobID,
                sentry->name,
                lLength,
                pUsrData->tObjectType,
                szExt,
                szMimeType,
                NULL,
                pUsrData->pScanInfo->uiScanned++,
                &pUsrData->pScanInfo->pContentInfo);
            if(rc) CLEANUP(rc);
            /*
            * Comment:
            * Perform the Active Content Check inside of archive
            */
            if(pUsrData->bActiveContent == TRUE && pUsrData->bScanAllFiles == TRUE && pUsrData->bScanCompressed == TRUE)
            {
                rc = check4ActiveContent(
                    _decompr,
                    lLength,
                    pUsrData->tObjectType,
                    pUsrData->bPdfAllowOpenAction);
                if(rc) CLEANUP(rc);
            }
            /*
            * Comment:
            * Perform the MIME Check inside of archive
            */
            if(pUsrData->bMimeCheck == TRUE && pUsrData->bScanAllFiles == TRUE && pUsrData->bScanCompressed == TRUE)
            {
                Char szErrorName[1024];
                Char szErrorFreeName[1024];
                rc = checkContentType(
                    szExt,
                    szMimeType,
                    pUsrData->pszScanMimeTypes,
                    pUsrData->pszBlockMimeTypes,
                    pUsrData->pszScanExtensions,
                    pUsrData->pszBlockExtensions,
                    szErrorName,
                    szErrorFreeName);
                if(rc) CLEANUP(rc);
            }
            rc = scanBuffer(
                pEngine,
                uiJobID,
                sentry->name,
                _decompr,
                lLength,
                pUsrData,
                errorReason);
        }
    }
cleanup:
    if(_decompr) {
        free(_decompr);
        _decompr = NULL;
    }
    FreeInfo(sentry);
    return rc;
} /* scanCompressedBuffer */

static VSA_RC vsaSetContentTypeParametes(VSA_OPTPARAM *param,
    USRDATA *pUsrData
    )
{
    PChar dest = NULL;
    Bool  mime = FALSE;
    PChar in = (PChar)param->pvValue;
    size_t inlen = 0;
    UInt i = 0;

    if(in == NULL) return VSA_OK;
    inlen = strlen((const char*)in);
    dest = (PChar)calloc(1,inlen * 2);
    if(dest == NULL) return VSA_E_NO_SPACE;

    switch(param->tCode)
    {
    case VS_OP_SCANMIMETYPES:
        pUsrData->pszScanMimeTypes = dest;
        mime = TRUE;
        break;
    case VS_OP_SCANEXTENSIONS:
        pUsrData->pszScanExtensions = dest;
        mime = FALSE;
        break;
    case VS_OP_BLOCKMIMETYPES:
        pUsrData->pszBlockMimeTypes = dest;
        mime = TRUE;
        break;
    case VS_OP_BLOCKEXTENSIONS:
        pUsrData->pszBlockExtensions = dest;
        mime = FALSE;
        break;
    default:
        free(dest);
        return VSA_OK;
    }
    for(i = 0; i < inlen; i++)
    {
        if(i == 0 && mime == FALSE && in[i] != '.')
        {
            addScanError(0,(PChar)in,0,-1,(PChar)"Invalid extension",pUsrData->pScanInfo->uiScanErrors++,&pUsrData->pScanInfo->pScanError);
            return VSA_E_INVALID_PARAM;
        }
        dest[i] = tolower((int)in[i]);
    }
    if(i>0 && i < (inlen * 2) && dest[i] != ';')
        dest[i] = ';';
    return VSA_OK;
} /* vsaSetContentTypeParametes */
#endif

static VSA_RC getFileSize(Char *pszfilename, size_t *size)
{
      VSA_RC rc = VSA_OK;

      struct stat     buf;
        if (pszfilename == NULL)
            return VSA_E_NULL_PARAM;
        
        if (0!=(stat((const char*)pszfilename,&buf)))
            return VSA_E_SCAN_FAILED;
      
        (*size)  = buf.st_size;

        return rc;
}

static VSA_RC registerCallback(VSA_CALLBACK *p_callback, USRDATA *usrdata)
{

    VSA_RC rc = VSA_OK;

    /* initialize the helper structure USRDATA */
    memset(usrdata,0,sizeof(USRDATA));

    if (p_callback != NULL)
    {
        if (p_callback->struct_size != sizeof(VSA_CALLBACK))
            CLEANUP(VSA_E_INVALID_PARAM);
        if (p_callback->pEventCBFP != NULL && p_callback->uiEventMsgFlags != 0)
        {
            if (uigVS_SAP_ALL > (p_callback->uiEventMsgFlags) &&  /* only known messages */
                uigVS_SAP_ALL & (p_callback->uiEventMsgFlags))
            {
                usrdata->uiMsgFlags = p_callback->uiEventMsgFlags;
            }
            else if ( (int)(p_callback->uiEventMsgFlags) == VS_M_ALL )
            {
                usrdata->uiMsgFlags = uigVS_SAP_ALL;     /* constant for all msg */
                
            }
            else
            {
                usrdata->uiMsgFlags = uigVS_SAP_ALL;     /* wished msg not supported, use default */
            }
            usrdata->pvFncptr   = p_callback->pEventCBFP;
            usrdata->pvUsrdata  = p_callback->pvUsrData;
        }
        if ( p_callback->pEventCBFP       == NULL ||  
             p_callback->uiEventMsgFlags == 0
            )
        {

            p_callback->pEventCBFP        = NULL;
            p_callback->uiEventMsgFlags   = 0;
                  /* may somebody forgot this feature to set MsgFlags?
                   * anyway you want handle this (trace or error), i deactivate
                   * here the CALLBACK mechanism
                   */
        }
    }       

cleanup:
    return (rc);
}

static void freeVSA_INIT(VSA_INIT **pp_init)
{
  if(pp_init != NULL && (*pp_init) != NULL)
  {
    /* cleanup the driver structures */
    if ((*pp_init) != NULL && (*pp_init)->pDriver != NULL){
        int i = 0;
        for (i=0; i<(*pp_init)->usDrivers; i++)
        {
            if ((*pp_init) != NULL && (*pp_init)->pDriver != NULL && (*pp_init)->pDriver[i].pszName != NULL){
                free((*pp_init)->pDriver[i].pszName);   
                (*pp_init)->pDriver[i].pszName = NULL;
            }
        }
        free((*pp_init)->pDriver);
        (*pp_init)->pDriver = NULL;
    }    
    if ((*pp_init) != NULL && (*pp_init)->pszEngineVersionText != NULL)
        free((*pp_init)->pszEngineVersionText);
    if ((*pp_init) != NULL && (*pp_init)->pszErrorText != NULL)
        free((*pp_init)->pszErrorText);

    /* free the rest of the p_init */
    if ((*pp_init) != NULL) {
        free((*pp_init));    
    }
    /* set now to NULL */
    (*pp_init) = NULL;

    /* dec. the ref counter */
    if(lgRefCounter > (size_t)0)
        lgRefCounter--;
  }
}

static void freeVSA_CONFIG(VSA_CONFIG **pp_config)
{
  if(pp_config != NULL && (*pp_config) != NULL)
  {
    if ((*pp_config)->pInitParams != NULL && (*pp_config)->pInitParams->pInitParam != NULL)
    {
        int i=0;
        for(i=0; i<(*pp_config)->pInitParams->usInitParams; i++)
        {
            if ((*pp_config)->pInitParams->pInitParam[i].tType == VS_TYPE_CHAR &&
                (*pp_config)->pInitParams->pInitParam[i].pvValue != NULL)
                    free(((*pp_config)->pInitParams->pInitParam[i].pvValue));
        }
        free((*pp_config)->pInitParams->pInitParam);
    }
    if ((*pp_config)->pInitParams != NULL)
        free((*pp_config)->pInitParams);
    if ((*pp_config)->pOptParams != NULL && (*pp_config)->pOptParams->pOptParam != NULL)
    {
        int i=0;
        for(i=0; i<(*pp_config)->pOptParams->usOptParams; i++)
        {
            if ((*pp_config)->pOptParams->pOptParam[i].tType == VS_TYPE_CHAR &&
                (*pp_config)->pOptParams->pOptParam[i].pvValue != NULL)
                    free((*pp_config)->pOptParams->pOptParam[i].pvValue);
        }
        free((*pp_config)->pOptParams->pOptParam);
    }
    if ((*pp_config)->pOptParams != NULL)
        free((*pp_config)->pOptParams);

    if ((*pp_config)->pAdapterInfo != NULL )
    {
        if((*pp_config)->pAdapterInfo->pszVendorInfo != NULL)
          free((*pp_config)->pAdapterInfo->pszVendorInfo);
        if((*pp_config)->pAdapterInfo->pszAdapterName != NULL)
          free((*pp_config)->pAdapterInfo->pszAdapterName);
        /* free adapterinfo structure */
        free((*pp_config)->pAdapterInfo);
        (*pp_config)->pAdapterInfo = NULL;
    }
    
    free(*pp_config);
    /* set now to NULL */
    (*pp_config) = NULL;
  }
}

static void freevirusinfo(VSA_VIRUSINFO **vsainf)
{
  if(vsainf != NULL && (*vsainf) != NULL) {
    if ((*vsainf)->pszVirusName != NULL) {
        free((*vsainf)->pszVirusName);
        (*vsainf)->pszVirusName = NULL;
    }
    if ((*vsainf)->pszObjectName != NULL){
        free((*vsainf)->pszObjectName);
        (*vsainf)->pszObjectName = NULL;
    }
    if ((*vsainf)->pszFreeTextInfo != NULL){
        free((*vsainf)->pszFreeTextInfo);
        (*vsainf)->pszFreeTextInfo = NULL;
    } 
    if ((*vsainf) != NULL) {
        free((*vsainf));
        (*vsainf) = NULL;
    }
  }
}

static void freevirusinfo2(VSA_VIRUSINFO *vsainf)
{
  if(vsainf != NULL ) {
    if ((*vsainf).pszVirusName != NULL) {
        free((*vsainf).pszVirusName);
        (*vsainf).pszVirusName = NULL;
    }
    if ((*vsainf).pszObjectName != NULL){
        free((*vsainf).pszObjectName);
        (*vsainf).pszObjectName = NULL;
    }
    if ((*vsainf).pszFreeTextInfo != NULL){
        free((*vsainf).pszFreeTextInfo);
        (*vsainf).pszFreeTextInfo = NULL;
    }    
  }
}

static void freescanerror(VSA_SCANERROR **vsierror)
{
  if (vsierror != NULL && (*vsierror) != NULL) {
    if ((*vsierror)->pszObjectName != NULL) {
        free((*vsierror)->pszObjectName);
        (*vsierror)->pszObjectName = NULL;
    }
    if ((*vsierror)->pszErrorText!= NULL) {
        free((*vsierror)->pszErrorText);
        (*vsierror)->pszErrorText= NULL;
    }
    if ((*vsierror) != NULL) {
        free((*vsierror));
        (*vsierror) = NULL;
    }
  }
}
static void freescanerror2(VSA_SCANERROR *vsierror)
{
  if (vsierror != NULL ) {
    if ((*vsierror).pszObjectName != NULL) {
        free((*vsierror).pszObjectName);
        (*vsierror).pszObjectName = NULL;
    }
    if ((*vsierror).pszErrorText!= NULL) {
        free((*vsierror).pszErrorText);
        (*vsierror).pszErrorText= NULL;
    }

  }
}

static void freecontentinfo2(VSA_CONTENTINFO *vsacontent)
{
    if(vsacontent != NULL) {
        if(vsacontent->pszObjectName != NULL) {
            free(vsacontent->pszObjectName);
            vsacontent->pszObjectName = NULL;
        }
        if(vsacontent->pszExtension != NULL) {
            free(vsacontent->pszExtension);
            vsacontent->pszExtension = NULL;
        }
        if(vsacontent->pszContentType != NULL) {
            free(vsacontent->pszContentType);
            vsacontent->pszContentType = NULL;
        }
        if(vsacontent->pszCharSet != NULL) {
            free(vsacontent->pszCharSet);
            vsacontent->pszCharSet = NULL;
        }
    }
} /* freecontentinfo */

/* CCQ_OFF */
/*
 * Parse Connection URI
 */
static VSA_RC vsaparseURI( PChar uri, PChar bLocal, PPChar prot, PPChar server, PPChar port)
{
    PChar  ptr,
           _uri;
    VSA_RC rc  = VSA_OK;
    if(uri == NULL || *uri == 0) {
        (*prot)   = (PChar)strdup((const char*)DEFAULT_PROTOCOL);
        (*server) = (PChar)strdup((const char*)DEFAULT_SERVER);
        (*port)   = (PChar)strdup((const char*)DEFAULT_PORT);
        *bLocal   = TRUE;
        return VSA_OK;
    }
    _uri = uri;
    ptr = (PChar)strstr((char*)_uri,(const char*)"://");
    if(ptr!=NULL) {
       SETSTRINGLN((*prot),_uri,(ptr-_uri));
       _uri = ptr + 3; /* :// */
    }
    ptr = (PChar)strstr((char*)_uri,(const char*)":");
    if(ptr!=NULL) {
       SETSTRINGLN((*server),_uri,(ptr-_uri));
       SETSTRINGLN((*port),ptr+1,strlen((const char*)ptr+1));
    } else {
       SETSTRINGLN((*server),_uri,strlen((const char*)_uri));
    }
    if( !memcmp((*server),DEFAULT_SERVER,(sizeof(DEFAULT_SERVER)-1)) ||
        !memcmp((*server),"localhost",9) )
    {
       *bLocal = TRUE;
    } else {
       *bLocal = FALSE;
    }
cleanup:
    if( (*prot) == NULL )
        (*prot)   = (PChar)strdup((const char*)DEFAULT_PROTOCOL);
    if( (*server) == NULL )
        (*server) = (PChar)strdup((const char*)DEFAULT_SERVER);
    if( (*port) == NULL )
        (*port)   = (PChar)strdup((const char*)DEFAULT_PORT);
    return rc;
}

/*
 * Connect to Server, send command and return the answer
 */
static VSA_RC vsaConnectd( PChar server, PChar port, PChar zCommand, PPChar zAnswer)
{/*
#ifndef _WIN32
  struct    sockaddr_un strAddr;
  socklen_t lenAddr;
#endif  */
  struct    addrinfo hints, *res, *r;
  char      buff[1024];
  int       buf_len= 0;
  int       err = VSA_E_LOAD_FAILED, s = -1;

  /* initialize data */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_INET;
  hints.ai_socktype = SOCK_STREAM;

  if ((err = getaddrinfo((const char*)server, (const char*)port, &hints, &res)) != 0) 
  {
      return VSA_E_LOAD_FAILED;
  }

  for( r = res; r != NULL; r = res->ai_next )
  {
/*#ifdef _WIN32*/
    if((s =(int)socket (PF_INET, SOCK_STREAM, 0))<0)
/*#else
    if((s =socket (PF_UNIX, SOCK_STREAM, 0))<0)
#endif*/
    {
        continue;
    } 

/*#ifdef _WIN32*/
    if (connect(s, r->ai_addr,(int)r->ai_addrlen) == -1)
/*#else    
    strAddr.sun_family=AF_UNIX; 
    strcpy(strAddr.sun_path, LOCAL_SOCKET_PATH);
    lenAddr=sizeof(strAddr.sun_family)+strlen((const char*)strAddr.sun_path);
    if (connect((struct sockaddr*)&strAddr, lenAddr) == -1)
#endif*/    
    {
      freeaddrinfo(res);
      _closemysocket(s);
      return VSA_E_LOAD_FAILED;
    } 
    else 
    {
      break;
    }
  }
  if (res != NULL)
  {
    freeaddrinfo(res);
  }
  else
  {
      _closemysocket(s);
      return VSA_E_LOAD_FAILED;
  }
    _sendmysocket(s, (const char*)zCommand, (int)strlen((const char*)zCommand));/* send command to server           */
    if((buf_len=_readmysocket(s, buff, (sizeof(buff)-1)))<=0)                   /* reciving information from server */
    {
      _closemysocket(s);
      return VSA_E_CIO_FAILED;
    }
    *zAnswer = (PChar)malloc(buf_len + 1);
    if(*zAnswer != NULL)
    {
        memcpy(*zAnswer,buff,buf_len);
        if ((*zAnswer)[buf_len-1] == '\n')
           (*zAnswer)[buf_len-1] = 0;
        else
           (*zAnswer)[buf_len] = 0;
        _closemysocket(s);
        return VSA_OK;
    }
    else
    {
      _closemysocket(s);
      return VSA_E_CIO_FAILED;
    }
}

/*
 * Connect to Server, send command and return the answer
 */
static VSA_RC vsaSendBytes2Clamd( PChar server, PChar port, FILE *pFP, PByte pByte, size_t lByte, PPChar zAnswer)
{
/*
#ifndef _WIN32
  struct    sockaddr_un strAddr;
  socklen_t lenAddr;
#endif  */
  struct    addrinfo hints, *res, *r;
  char      buff[4096];
  char      bufflen[4];
  char      endstream[5];
  int       buf_len= 0;
  PByte     ptr    = pByte;
  size_t    restlen= lByte;
  const char  zCommand[11] = "zINSTREAM\0";
  int       err = VSA_E_LOAD_FAILED, s = -1;

  /* initialize data */
  memset(&hints, 0, sizeof(hints));
  memset(endstream,0,sizeof(endstream));
  hints.ai_family = PF_INET;
  hints.ai_socktype = SOCK_STREAM;

  if ((err = getaddrinfo((const char*)server, (const char*)port, &hints, &res)) != 0) 
  {
      return VSA_E_LOAD_FAILED;
  }

  for( r = res; r != NULL; r = res->ai_next )
  {
/*#ifdef _WIN32*/
    if((s =(int)socket (PF_INET, SOCK_STREAM, 0))<0)
/*#else
    if((s =socket (PF_UNIX, SOCK_STREAM, 0))<0)
#endif*/
    {
        continue;
    } 

/*#ifdef _WIN32*/
    if (connect(s, r->ai_addr,(int)r->ai_addrlen) == -1)
/*#else    
    strAddr.sun_family=AF_UNIX; 
    strcpy(strAddr.sun_path, LOCAL_SOCKET_PATH);
    lenAddr=sizeof(strAddr.sun_family)+strlen((const char*)strAddr.sun_path);
    if (connect((struct sockaddr*)&strAddr, lenAddr) == -1)
#endif*/    
    {
      freeaddrinfo(res);
      _closemysocket(s);
      return VSA_E_LOAD_FAILED;
    } 
    else 
    {
      break;
    }
  }
  if (res != NULL)
  {
    freeaddrinfo(res);
  }
  else
  {
      _closemysocket(s);
      return VSA_E_LOAD_FAILED;
  }
  err = _sendmysocket(s, (const char*)zCommand, (int)(sizeof(zCommand)-1));/* sending byte stream to server */
  if(pFP) {
    buf_len = (int)fread(buff,1,sizeof(buff),pFP);
    if(buf_len == EOF) buf_len = 0;
    else ptr = (PByte)buff;
  } else {
    buf_len = (int)(restlen < sizeof(buff) ? restlen : sizeof(buff));
  }
  do {
        INT_2_BYTES(bufflen,buf_len);
        err = _sendmysocket(s, (const char*)bufflen, 4);
        if(err != 4) {
            restlen = 0;
            break;
        }
        err = _sendmysocket(s, (const char*)ptr, (int)buf_len);
        if(err != buf_len) {
            restlen = 0;
            break;
        }
        restlen-=buf_len;
        ptr+=buf_len;
        if(pFP) {
          buf_len = (int)fread(buff,1,sizeof(buff),pFP);
          if(buf_len == EOF) buf_len = 0;
          ptr = (PByte)buff;
        } else {
          buf_len = (int)(restlen < sizeof(buff) ? restlen : sizeof(buff));
        }
  } while( restlen > 0 );
  _sendmysocket(s, (const char*)endstream, (int)sizeof(endstream));
  if((buf_len=_readmysocket(s, buff, (sizeof(buff)-1)))<=0)             /* reciving information from server */
  {
      (*zAnswer) = (PChar)strdup("No answer received from server. ERROR ");
      return VSA_OK;
  }
  *zAnswer = (PChar)malloc(buf_len + 1);
  if(*zAnswer != NULL)
  {
        memcpy(*zAnswer,buff,buf_len);
        if ((*zAnswer)[buf_len-1] == '\n')
           (*zAnswer)[buf_len-1] = 0;
        else
           (*zAnswer)[buf_len] = 0;
  }
  else
  {
      return VSA_E_CIO_FAILED;
  }
  _closemysocket(s);
  return VSA_OK;
}
/* CCQ_ON */

