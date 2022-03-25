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

/*source--------------------------------------------------------------*/
/*                                                                    */
/* Description:                                                       */
/* ============                                                       */
/*                                                                    */
/*                                                                    */
/*                                                                    */
/*  Author:    Markus Strehle, SAP AG (mailto:markus.strehle@sap.com) */
/*  Reviewer:                                                         */
/*  Version:       1.104.x                                            */
/*                                                                    */
/*  Created:                                                          */
/*    20 June 2005  Markus Strehle                                    */
/*                                                                    */
/*  Modified:                                                         */
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
/*      vsaSetScanConfig                                              */
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
/* system includes (OS-dependent)                                     */
/*--------------------------------------------------------------------*/
#ifdef _WIN32
#ifndef WIN32_MEAN_AND_LEAN
#define WIN32_MEAN_AND_LEAN
#endif
#include <windows.h>
#elif defined(__sun) || defined(sinix) || defined(__linux) || defined(_AIX) || (defined(__hpux) && defined(__ia64))
#include <dlfcn.h>
#elif defined(__hppa) && !(defined(__hpux) && defined(__ia64))
#include <dl.h>
# elif defined(__MVS__)
#include <string.h>
#include <dll.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stddef.h>
#include <sys/stat.h>

/*--------------------------------------------------------------------*/
/* ClamAV includes                                                    */
#include "clamav.h"
/*--------------------------------------------------------------------*/
/* Own includes                                                       */
/*--------------------------------------------------------------------*/
#include "vsaxxtyp.h"
#include "vsclam.h"
#ifdef VSI2_COMPATIBLE
#include "csdecompr.h"
#include "vsmime.h"
#endif

/*--------------------------------------------------------------------*/
/* static globals                                                     */
/*--------------------------------------------------------------------*/
static Bool           bgInit                =   FALSE;
static size_t         lgRefCounter          =   0;
static time_t         tEngineDate           =   0;
static PChar          pLibPath              =   NULL;
static PChar          pDbPath               =   NULL;
static PChar          pLoadError            =   NULL;
static const char        builddate[]        =   "[DATE]CLAMSAP: " __DATE__ ", " __TIME__ ;
#ifdef __cplusplus
static const char        version[]          =   "@[CPP]CLAMSAP: " VSA_ADAPTER_VERSION;
#else
static const char        version[]          =   "@[ C ]CLAMSAP: " VSA_ADAPTER_VERSION;
#endif

/* all known messages, provided also in VSA_CONFIG */
static const UInt     uigVS_SAP_ALL = VS_M_ERROR              |
                                      VS_M_ABORTSCAN          |
                                      VS_M_VIRUS              |
                                      VS_M_CLEAN              |
                                      VS_M_NOTSCANNED         |
                                      VS_M_OBJECTFOUND;

/*         CLAMAV function pointers                */
static struct clamav_function_s clamav_fps[] =
{
                DLL_DEFINE(cl_init),
                DLL_DEFINE(cl_engine_new),
                DLL_DEFINE(cl_engine_free),
                DLL_DEFINE(cl_retdbdir),
                DLL_DEFINE(cl_strerror),
                DLL_DEFINE(cl_cvdfree),
                DLL_DEFINE(cl_cvdhead),
                DLL_DEFINE(cl_engine_set_str),
                DLL_DEFINE(cl_engine_get_num),
                DLL_DEFINE(cl_engine_compile),
                DLL_DEFINE(cl_load),
                DLL_DEFINE(cl_engine_set_num),
                DLL_DEFINE(cl_retflevel),
                DLL_DEFINE(cl_scanfile),
                { NULL }
};

static clamav_function_pointers clptr;
static clamav_function_pointers *pClamFPtr = &clptr;
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

static VSA_RC scanCompressed(
    void           *pEngine,
    UInt            uiJobID,
    PChar           pszObjectName,
    USRDATA        *pUsrData,
    PChar           errorReason);

static VSA_RC vsaSetContentTypeParametes(VSA_OPTPARAM *,
    USRDATA *
    );
#endif

static VSA_RC vsaResetConfig(PChar confDir,PChar dataDir);
static VSA_RC vsaLoadEngine(PPChar         ppszErrorText, time_t *pEngineDate);

static VSA_RC setScanError(UInt            uiJobID,
                           PChar           pszObjectName,
                           size_t          lObjectSize,
                           Int             iErrorRC,
                           PChar           pszErrorText,
                           PPVSA_SCANERROR pp_scanerror);
/*
 *  Assign the VSA_OPTPARAM values to
 *  internal configuration.
 */
static VSA_RC vsaSetScanConfig(VSA_SCANPARAM *,
                               VSA_OPTPARAMS *, 
                               USRDATA *,
                               struct cl_engine *engine
                               );

static VSA_RC vsaSetInitConfig(VSA_INITPARAMS *,
                               INITDATA *
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


#ifdef _WIN32
#define CLAM_LOAD_ERROR_MESSAGE     "ClamAV engine (clamav.dll) could not be loaded"
#elif defined(__hppa) && !(defined(__hpux) && defined(__ia64))
#define CLAM_LOAD_ERROR_MESSAGE     "ClamAV engine (libclamav.sl) could not be loaded"
#else
#define CLAM_LOAD_ERROR_MESSAGE     "ClamAV engine (libclamav.so) could not be loaded"
#endif

#ifdef _WIN32
#define   CLAMKEY "Software\\ClamAV"
static HMODULE hLibClamAvDLL = 0;
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
        /*
        * Comment:
        * Initialize the table for CRC check
        */
        memset(pClamFPtr,0,sizeof(clamav_function_pointers));
        /* load clamav library and initialize it */
        vsaLoadEngine(&pLoadError,&tEngineDate);
        if(pClamFPtr->bLoaded) pClamFPtr->fp_cl_init(CL_INIT_DEFAULT);
        /*if(rc) return VSA_E_LOAD_FAILED;*/
#ifdef VSI2_COMPATIBLE
        InitializeTable();
        if(pLoadError) {
            free(pLoadError);
            pLoadError = NULL;
        }
        /* load libmagic library */
        vsaLoadMagicLibrary(&pLoadError);
        /*if(rc) return VSA_E_LOAD_FAILED;*/
#endif
        /* CCQ_OFF */
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
        { VS_IP_INITDIRECTORY          ,   VS_TYPE_CHAR   ,      0,     0},
        { VS_IP_INITDRIVERDIRECTORY    ,   VS_TYPE_CHAR   ,      0,     0},
        { VS_IP_INITTEMP_PATH          ,   VS_TYPE_CHAR   ,      0,     0}

    };

    static MY_OPTPARAMS _optparams[] = {
        { VS_OP_SCANBESTEFFORT         ,   VS_TYPE_BOOL   ,      0,     (void*)1},
        { VS_OP_SCANALLFILES           ,   VS_TYPE_BOOL   ,      0,     (void*)1},
        { VS_OP_SCANHEURISTICLEVEL     ,   VS_TYPE_INT    ,      0,     (void*)0},
        { VS_OP_SCANONLYHEURISTIC      ,   VS_TYPE_BOOL   ,      0,     (void*)0},
        { VS_OP_SCANLIMIT              ,   VS_TYPE_SIZE_T ,      0,     (void*)0},
        { VS_OP_SCANEXTRACT            ,   VS_TYPE_BOOL   ,      0,     (void*)1},
        { VS_OP_SCANEXTRACT_SIZE       ,   VS_TYPE_SIZE_T ,      0,     (void*)0},
        { VS_OP_SCANEXTRACT_DEPTH      ,   VS_TYPE_INT    ,      0,     (void*)0},
        { VS_OP_SCANEXCLUDEMIMETYPES   ,   VS_TYPE_CHAR   ,      0,     (void*)""}
#ifdef VSI2_COMPATIBLE
        ,
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
            case VS_IP_INITDIRECTORY:
            {
                PChar  _dir = NULL;
                const char *_clamdir = (const char *)pLibPath;
                size_t _clamdirlen   = _clamdir != NULL ? strlen(_clamdir):0;
                if(_clamdir == NULL ) {
                   _clamdir = ".";
                   _clamdirlen = 1;
                }
                _dir = (PChar)malloc(_clamdirlen+1);
                if(_dir == NULL)
                   CLEANUP(VSA_E_NO_SPACE);
                strncpy((char*)_dir,_clamdir,_clamdirlen);
                _dir[_clamdirlen]=0;

                VSAddINITParameter ( (*pp_config)->pInitParams->pInitParam,
                                     (*pp_config)->pInitParams->usInitParams,
                                     _initparams[x].tCode,
                                     _initparams[x].tType,
                                     _clamdirlen,
                                     (char*)_dir
                                   );
            }
        break;
        case VS_IP_INITDRIVERDIRECTORY:
           {
               PChar  _dir = NULL;
               const char *_clamdir = pDbPath == NULL && pClamFPtr->bLoaded == TRUE ? pClamFPtr->fp_cl_retdbdir() : (const char*)pDbPath;
               size_t _clamdirlen   = _clamdir != NULL ? strlen(_clamdir):DRIVER_DIRECTORY_LN;
               if(_clamdir == NULL ) {
                  _clamdir = DRIVER_DIRECTORY;
                  _clamdirlen = DRIVER_DIRECTORY_LN;
               }
               _dir = (PChar)malloc(_clamdirlen+1);
               if(_dir == NULL)
                  CLEANUP(VSA_E_NO_SPACE);
               strncpy((char*)_dir,_clamdir,_clamdirlen);
               _dir[_clamdirlen]=0;

               VSAddINITParameter ( (*pp_config)->pInitParams->pInitParam,
                                    (*pp_config)->pInitParams->usInitParams,
                                    _initparams[x].tCode,
                                    _initparams[x].tType,
                                    _clamdirlen,
                                    (char*)_dir
                                  );
           }
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
    (*pp_config)->uiVsaActionFlags =     VSA_AP_SCAN;
#endif

    (*pp_config)->uiVsaScanFlags   =     VSA_SP_FILE;

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
    VSA_RC                      rc      =   VSA_OK;
    Int                         i       =   0;
    size_t                      len     =   0;
    PChar                      pDriverName;
    PChar                      szinitDrivers = NULL;
    INITDATA                   initConfig = {NULL,NULL,NULL,NULL};

    /*   ----- clam param ---- */
    unsigned int dboptions = 0, sigs = 0;
    int ret = 0;
    struct cl_engine *engine = NULL;

    if(pp_init == NULL)
        return VSA_E_NULL_PARAM; /* no handle */

    /* Comment:
     * In the VsaInit function you should either connect/contact your
     * internal engine or allocate memory for the scan instance.
     * The structure VSA_INIT contains several flags which should help you
     * to pass your scan handle, internal license information, flags and so on to
     * the VsaScan function.
     */
    /* Initialize VSA_INIT structure */
    (*pp_init)          =   (PVSA_INIT)calloc(1,sizeof(VSA_INIT));
    if ((*pp_init) == NULL)
        CLEANUP(VSA_E_NO_SPACE);
        /* sizeof */
    (*pp_init)->struct_size = sizeof(VSA_INIT);

    if(bgInit == FALSE)
    {
        SETERRORTEXT((*pp_init)->pszErrorText, "VsaStartup not yet called or not successful");
        (*pp_init)->iErrorRC = 5;
        return VSA_E_NOT_INITIALISED; /* no successful VsaStartup */
    }
    rc = vsaSetInitConfig(p_initparams,&initConfig);
    if(rc) CLEANUP(rc);
    if(pClamFPtr == NULL || pClamFPtr->dll_hdl == NULL || pClamFPtr->bLoaded == FALSE)
    {
        if((const char*)initConfig.initdirectory) {
            if(pDbPath) free(pDbPath);
            pDbPath = (PChar)strdup((const char*)initConfig.initdirectory->pvValue);
        }
        if((const char*)initConfig.enginedirectory) {
            if(pLibPath) free(pLibPath);
            pLibPath = (PChar)strdup((const char*)initConfig.enginedirectory->pvValue);
        }
        vsaResetConfig(pLibPath,pDbPath);
        if(pClamFPtr == NULL || pClamFPtr->dll_hdl == NULL || pClamFPtr->bLoaded == FALSE)
        {
            if(pLoadError) { SETERRORTEXT((*pp_init)->pszErrorText,pLoadError); }
            else           { SETERRORTEXT((*pp_init)->pszErrorText,CLAM_LOAD_ERROR_MESSAGE); }
            (*pp_init)->iErrorRC = 7;
            return VSA_E_LOAD_FAILED; /* no successful VsaStartup */
        }
    }
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
    (*pp_init)->usEngineMajVersion = pClamFPtr->fp_cl_retflevel();
    (*pp_init)->usEngineMinVersion = 0;
    SETSTRING( (*pp_init)->pszEngineVersionText, VSA_VERSION_STRING );
    /* set VSA_DRIVERINFO structure */
        (*pp_init)->iErrorRC   = 0;
    (*pp_init)->pDriver = (PVSA_DRIVERINFO)calloc(MAX_DRIVERS,sizeof(VSA_DRIVERINFO));
    if ((*pp_init)->pDriver == NULL)
        CLEANUP(VSA_E_NO_SPACE);

    /* CCQ_OFF */
    engine = pClamFPtr->fp_cl_engine_new( );
    if (engine == NULL)
    {
        SETERRORTEXT((*pp_init)->pszErrorText, "ClamAV engine initialization failed");
        (*pp_init)->iErrorRC = 7;
        CLEANUP(VSA_E_LOAD_FAILED);
    }
    if((const char*)initConfig.initdirectory) {
        ret = pClamFPtr->fp_cl_load((const char*)initConfig.initdirectory->pvValue,engine,&sigs,dboptions);
        if(ret)
        {
            if((const char*)initConfig.initdirectory) {
                if(pDbPath) free(pDbPath);
                pDbPath = (PChar)strdup((const char*)initConfig.initdirectory->pvValue);
            }
            if((const char*)initConfig.enginedirectory) {
                if(pLibPath) free(pLibPath);
                pLibPath = (PChar)strdup((const char*)initConfig.enginedirectory->pvValue);
            }
            vsaResetConfig(pLibPath,pDbPath);
            if(pClamFPtr == NULL || pClamFPtr->dll_hdl == NULL || pClamFPtr->bLoaded == FALSE)
            {
                if(pLoadError) { SETERRORTEXT((*pp_init)->pszErrorText,pLoadError); }
                else           { SETERRORTEXT((*pp_init)->pszErrorText,CLAM_LOAD_ERROR_MESSAGE); }
                (*pp_init)->iErrorRC = 7;
                return VSA_E_LOAD_FAILED; /* no successful VsaStartup */
            }
            ret = pClamFPtr->fp_cl_load(pClamFPtr->fp_cl_retdbdir(),engine,&sigs,dboptions);
        }
    }
    else {
        ret = pClamFPtr->fp_cl_load(pClamFPtr->bLoaded == TRUE ? pClamFPtr->fp_cl_retdbdir() : DRIVER_DIRECTORY,engine,&sigs,dboptions);
    }
    if(ret)
    {
        char _error[MAX_PATH_LN * 2];
#ifdef _WIN32
        _snprintf((char*)_error,MAX_PATH_LN * 2,"ClamAV engine could not load signature DB files. Use freshclam to ensure availability of main.cvd and daily.cvd in %s",pClamFPtr != 0? pClamFPtr->fp_cl_retdbdir(): DRIVER_DIRECTORY);
#else
        snprintf((char*)_error,MAX_PATH_LN * 2,"ClamAV engine could not load signature DB files. Use freshclam to ensure availability of main.cvd and daily.cvd in /var/lib/clamav.");
#endif
        SETERRORTEXT((*pp_init)->pszErrorText,_error);
        (*pp_init)->iErrorRC = ret;
        pClamFPtr->fp_cl_engine_free(engine);
        CLEANUP(VSA_E_DRIVER_FAILED);
    }
#ifndef CL_SCAN_STDOPT
    pClamFPtr->fp_cl_engine_set_num(engine, CL_ENGINE_PCRE_MATCH_LIMIT, (long long) 2000);
    pClamFPtr->fp_cl_engine_set_num(engine, CL_ENGINE_PCRE_RECMATCH_LIMIT, (long long) 2000);
#endif
    /* CCQ_ON */
    if((ret = pClamFPtr->fp_cl_engine_compile(engine)))
    {  /* CCQ_OFF */
       pClamFPtr->fp_cl_engine_free(engine);
       (*pp_init)->iErrorRC   = ret;
       SETERRORTEXT((*pp_init)->pszErrorText, "ClamAV engine could not compile signature DB files");
       CLEANUP(VSA_E_LOAD_FAILED);
    }
     /* convert date to calendar date *//*CCQ_CLIB_LOCTIME_OK*/
    (*pp_init)->utcDate     = tEngineDate;
    if((const char*)initConfig.initdirectory) {
        ret = pClamFPtr->fp_cl_engine_set_str(engine,CL_ENGINE_TMPDIR,(const char*)initConfig.tmpdir->pvValue);
    }
    (*pp_init)->hEngine     = (PVoid)engine;
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
       struct cl_cvd *p_driver;/* CCQ_OFF */
       if((const char*)initConfig.drivers) {
           szinitDrivers = (PChar)strdup((const char*)initConfig.drivers->pvValue);
       }
       else {
           szinitDrivers = (PChar)strdup((const char*)CLAMAV_DRIVERS);
       }
       pDriverName = (PChar)strtok((char*)szinitDrivers,",");/*CCQ_FUNCTION_WITH_MEMORY_OK*/
       while(pDriverName!=NULL)
       {
          if(initConfig.initdirectory) {
              (*pp_init)->pDriver[i].pszName = (PChar)malloc(initConfig.initdirectory->lLength + strlen((const char*)pDriverName) + 3);
          }
          else {
              (*pp_init)->pDriver[i].pszName = (PChar)malloc(DRIVER_DIRECTORY_LN + strlen((const char*)pDriverName) + 3);
          }
          if((*pp_init)->pDriver[i].pszName == NULL)
             CLEANUP(VSA_E_NO_SPACE);

          if(initConfig.initdirectory) {
              sprintf((char*)(*pp_init)->pDriver[i].pszName,"%s%s%s",(char*)initConfig.initdirectory->pvValue,DIR_SEP,pDriverName);
          }
          else {
              sprintf((char*)(*pp_init)->pDriver[i].pszName,"%s%s%s",(char*)DRIVER_DIRECTORY,DIR_SEP,pDriverName);
          }
          if(getFileSize((*pp_init)->pDriver[i].pszName,NULL)) /* search for *.cvd */
          {   /* if *.cvd not found, then try it with *.cld */
              (*pp_init)->pDriver[i].pszName[(int)strlen((const char*)(*pp_init)->pDriver[i].pszName)-2] = 'l';
              if(getFileSize((*pp_init)->pDriver[i].pszName,NULL))
              { /* if not found, then not available */
                  (*pp_init)->pDriver[i].pszName = NULL;
              }
          }
          p_driver = NULL; /* Initialize the structure */
          if( (*pp_init)->pDriver[i].pszName )
          {
              p_driver = pClamFPtr->fp_cl_cvdhead((const char*)(*pp_init)->pDriver[i].pszName );
          }
          if(p_driver)
          {
              (*pp_init)->usDrivers++;
              (*pp_init)->pDriver[i].uiViruses = p_driver->sigs;
              (*pp_init)->pDriver[i].iDriverRC = 0;
              (*pp_init)->pDriver[i].utcDate   = p_driver->stime;
              (*pp_init)->pDriver[i].usDrvMajVersion  = (*pp_init)->usEngineMajVersion;
              (*pp_init)->pDriver[i].usDrvMinVersion  = p_driver->version;
              pClamFPtr->fp_cl_cvdfree(p_driver);
          }
          else
          {
              /* convert date to calendar date *//*CCQ_CLIB_LOCTIME_OK*/
              (*pp_init)->pDriver[i].utcDate = (time_t)pClamFPtr->fp_cl_engine_get_num(engine,CL_ENGINE_DB_TIME,&ret);
              (*pp_init)->pDriver[i].uiViruses        = 0;
              (*pp_init)->pDriver[i].uiVariants       = 0;  
              (*pp_init)->pDriver[i].iDriverRC        = -1;
              (*pp_init)->pDriver[i].usDrvMajVersion  = 1;
              (*pp_init)->pDriver[i].usDrvMinVersion  = 0;
          }
          (*pp_init)->pDriver[i].struct_size      = sizeof(VSA_DRIVERINFO);
          i++;
          pDriverName = (PChar)strtok(NULL,","); /*CCQ_FUNCTION_WITH_MEMORY_OK*/
       }       
    } while( pDriverName );/* CCQ_ON */

    /* check drivers */
    if( (*pp_init)->usDrivers < MIN_DRIVERS )
    {
       (*pp_init)->iErrorRC   = 9;
       SETERRORTEXT((*pp_init)->pszErrorText, "ClamAV engine drivers not fully loaded");
       CLEANUP(VSA_E_DRIVER_FAILED);
    }
cleanup:
    if(szinitDrivers) free(szinitDrivers);
    if (rc != VSA_OK)
    {
        if((*pp_init)->pszErrorText==NULL) SETSTRING( (*pp_init)->pszErrorText, pClamFPtr->fp_cl_strerror(ret) );
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
    VS_CALLRC           _vsa_rc         = VS_CB_OK;
    VSA_EVENTCBFP       cfunc           = NULL;
    UInt                uiMsgFlag       = 0;
    VSA_USRDATA         pvUsrdata       = NULL;
    VSA_ENGINE          heng            = NULL;
    PChar               pszReason       = NULL;
    PVSA_SCANERROR      p_scanerror     = NULL;
    PVSA_VIRUSINFO      p_virusinfo     = NULL;
    FILE                *_fp            = NULL;
    USRDATA             usrdata;
    Char                szErrorName[1024];
#ifdef VSI2_COMPATIBLE
    PChar               pszObjName      = NULL;
    Char                szExt[EXT_LN]   = ".*";
    Char                szExt2[EXT_LN]  = ".*";
    Char                szErrorFreeName[1024];
    Char                szMimeType[MIME_LN] = "unknown/unknown";
#else
    int                 clam_rc = 0;
    size_t              len = 0;
    const char          *virname = NULL;
    unsigned long int   scanned = 0;
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

    /* check callback structure passed to me */
    rc = registerCallback(p_callback,&usrdata);
    if(rc) {
        pszReason = (PChar)"Callback messages not supported";
        CLEANUP(rc);
    }

    uiMsgFlag = usrdata.uiMsgFlags;
    pvUsrdata = usrdata.pvUsrdata;
    cfunc     = usrdata.pvFncptr;
    usrdata.cl_scan_options.parse |= ~0; /* enable all parsers */

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
    if(pClamFPtr == NULL || pClamFPtr->dll_hdl == NULL || pClamFPtr->bLoaded == FALSE)
    {
        pszReason = (PChar)CLAM_LOAD_ERROR_MESSAGE;
        CLEANUP(VSA_E_LOAD_FAILED);
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
    rc = vsaSetScanConfig(p_scanparam, p_optparams,&usrdata,(struct cl_engine*)p_init->hEngine);
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
    if(usrdata.bMimeCheck == TRUE || usrdata.bScanAllFiles == TRUE)
    {
        Byte bbyte[65536];
        PByte pBuff = bbyte;
        Bool text = TRUE;
        int status = 1;
        VS_OBJECTTYPE_T a = VS_OT_UNKNOWN;
        VS_OBJECTTYPE_T b = VS_OT_UNKNOWN;
        size_t current_read = 0;

        rc = getFileSize(p_scanparam->pszObjectName,&usrdata.lObjectSize);
        if(rc) {
            pszReason = (PChar)"The file could not be opened!";
            CLEANUP(VSA_E_SCAN_FAILED);
        }
        memset(bbyte,0,sizeof(bbyte));
        _fp = fopen((const char*)p_scanparam->pszObjectName,"rb");
        if(_fp) {
            do {
                current_read = fread(pBuff,1,sizeof(bbyte)-1,_fp);
                if(current_read == 0) break;
                rc = getByteType(pBuff,(current_read < sizeof(bbyte)-1)?current_read:sizeof(bbyte)-1,p_scanparam->pszObjectName,szExt2,szExt,szMimeType,0,&status,&text,&a,&b,&usrdata.tFileType,&usrdata.tObjectType);
                if(usrdata.bActiveContent == TRUE)
                {
                    rc = check4ActiveContent(pBuff,sizeof(bbyte) - 1,usrdata.tObjectType, usrdata.bPdfAllowOpenAction);
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
                                    usrdata.bScanMimeTypesWildCard,
                                    usrdata.bBlockMimeTypesWildCard,
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
#endif
    /*--------------------------------------------------------------------*/
    /* Comment:                                                           */
    /* Start here to process the different action types.                  */
    /* First we perform some plausi checks                                */
    /*--------------------------------------------------------------------*/
    switch(p_scanparam->tScanCode)
    {
    case VSA_SP_FILE:
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
        if(rc) SET_VSA_RC( rc );
#else
        rc = getFileSize(p_scanparam->pszObjectName,&usrdata.lObjectSize);
        if(rc) {
            pszReason = (PChar)"The file could not be opened!";
            CLEANUP(VSA_E_SCAN_FAILED);
        }           /* CCQ_OFF */
#ifdef CL_SCAN_STDOPT
        clam_rc = pClamFPtr->fp_cl_scanfile(
            (const char*)p_scanparam->pszObjectName,
            (const char**)&virname,
            &scanned,
            (const struct cl_engine *)p_init->hEngine,
            CL_SCAN_STDOPT);
#else
{
        clam_rc = pClamFPtr->fp_cl_scanfile(
            (const char*)p_scanparam->pszObjectName,
            (const char**)&virname,
            &scanned,
            (const struct cl_engine *)p_init->hEngine,
            &usrdata.cl_scan_options);
}
#endif
        /* CCQ_ON */
        if(clam_rc != CL_CLEAN)
        {
            pszReason = (PChar)pClamFPtr->fp_cl_strerror(clam_rc);
            switch(clam_rc)
            {
            case CL_VIRUS: rc = VSA_E_VIRUS_FOUND;
                break;
            default:       rc = VSA_E_SCAN_FAILED;
                pszReason = (PChar)"ClamAV engine with internal,unknown error.";
                break;
            }
        }
        else
        {
            rc = VSA_OK;
        }
#endif
        break;
    default:
        pszReason = (PChar)"ClamAV engine supports only the scan of local files";
        CLEANUP(VSA_E_INVALID_SCANOBJECT);
    }

#ifndef VSI2_COMPATIBLE
    /*
    * After the scan
    */
    if(clam_rc == CL_VIRUS)
    {
        /* found EICAR */
        p_virusinfo = (PVSA_VIRUSINFO)calloc(1,sizeof(VSA_VIRUSINFO));

        if(p_virusinfo == NULL)
            CLEANUP(VSA_E_NO_SPACE);

        p_virusinfo->struct_size = sizeof(VSA_VIRUSINFO);
        p_virusinfo->bRepairable = FALSE;
        p_virusinfo->lObjectSize = usrdata.lObjectSize;
        SETSTRING(p_virusinfo->pszFreeTextInfo,"No info available");
        SETSTRING(p_virusinfo->pszObjectName,p_scanparam->pszObjectName);
        SETSTRING(p_virusinfo->pszVirusName,virname);
        p_virusinfo->tActionType = VS_AT_NOACTION;
        p_virusinfo->tDetectType = VS_DT_KNOWNVIRUS;
        p_virusinfo->tVirusType = VS_VT_VIRUS;
        p_virusinfo->uiVirusID = 0;
        p_virusinfo->tObjectType = VS_OT_BINARY;

        SET_VSA_RC(VSA_E_VIRUS_FOUND);
        _vsa_rc = CB_FUNC(VS_M_VIRUS,p_virusinfo);
        if(_vsa_rc == VS_CB_NEXT || _vsa_rc == VS_CB_TERMINATE)
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
                     (Int)rc,
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
                     (Int)rc,
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
                     (Int)rc,
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
    if( ppscinfo != NULL && (*ppscinfo) != NULL && (*ppscinfo)->pContentInfo != NULL)
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
        if((*pp_init)->hEngine && pClamFPtr && pClamFPtr->fp_cl_engine_free)  /* CCQ_OFF */
           pClamFPtr->fp_cl_engine_free((struct cl_engine *)(*pp_init)->hEngine);
        freeVSA_INIT(pp_init);   /* CCQ_ON */
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
#ifdef VSI2_COMPATIBLE
    vsaCloseMagicLibrary();
#endif
    bgInit = FALSE;
    if(pLibPath) {
        free(pLibPath);
        pLibPath = NULL;
    }
    if(pDbPath) {
        free(pDbPath);
        pDbPath = NULL;
    }
    if(pLoadError) {
        free(pLoadError);
        pLoadError = NULL;
    }
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
static VSA_RC vsaResetConfig(PChar confDir,PChar dataDir)
{
    VSA_RC         rc = VSA_OK;
#ifdef _WIN32
    HKEY           hKey = NULL;
    if(RegOpenKey(HKEY_CURRENT_USER,CLAMKEY,&hKey) == ERROR_SUCCESS)
    {
        if(confDir != 0)
            RegSetValueEx(hKey,
            "ConfDir",
            0,
            REG_SZ,
            (CONST BYTE*)confDir,
            (DWORD)strlen((const char*)confDir));
        if(dataDir != 0)
            RegSetValueEx(hKey,
            "DataDir",
            0,
            REG_SZ,
            (CONST BYTE*)dataDir,
            (DWORD)strlen((const char*)dataDir));
        RegCloseKey(hKey);
    }
    else 
    {
        if(RegCreateKey(HKEY_CURRENT_USER,CLAMKEY,&hKey) == ERROR_SUCCESS) {
            if(confDir != 0)
                RegSetValueEx(hKey,
                "ConfDir",
                0,
                REG_SZ,
                (CONST BYTE*)confDir,
                (DWORD)strlen((const char*)confDir));
            if(dataDir != 0)
                RegSetValueEx(hKey,
                "DataDir",
                0,
                REG_SZ,
                (CONST BYTE*)dataDir,
                (DWORD)strlen((const char*)dataDir));
            RegCloseKey(hKey);
        }
        else
        {
            return rc;
        }
    }
    if(hLibClamAvDLL != 0) {
        FreeLibrary(hLibClamAvDLL);
        hLibClamAvDLL = 0;
    }
    memset(pClamFPtr,0,sizeof(clamav_function_pointers));
#endif
    /* load clamav library and initialize it */
    vsaLoadEngine(&pLoadError,&tEngineDate);
#ifdef _WIN32
    if(pClamFPtr->bLoaded) { pClamFPtr->fp_cl_init(CL_INIT_DEFAULT); }
#endif
    return rc;
}

static VSA_RC vsaLoadEngine(PPChar ppszErrorText, time_t *pEngineDate)
{
    VSA_RC         rc        = VSA_OK;
    int            i,
                   fptr_index;
    DLL_ADR      * base_fptr;
    char          _conf[MAX_PATH_LN];
    struct stat   _lStat;
    size_t         len      = 0;
#ifdef _WIN32
    HINSTANCE hInst;
    FARPROC   pFunc;
    HKEY      hKey          = NULL;
    unsigned int  _conflen  = MAX_PATH_LN;
    LPCTSTR   lpLibrary     = (LPCTSTR)("libclamav.dll");

    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, CLAMKEY, 0, KEY_QUERY_VALUE , &hKey) == ERROR_SUCCESS 
    || RegOpenKeyEx(HKEY_CURRENT_USER,CLAMKEY,0,KEY_QUERY_VALUE,&hKey) == ERROR_SUCCESS
    || RegOpenKeyEx(HKEY_LOCAL_MACHINE, CLAMKEY, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY , &hKey) == ERROR_SUCCESS
    || RegOpenKeyEx(HKEY_LOCAL_MACHINE, CLAMKEY, 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY , &hKey) == ERROR_SUCCESS) {
        _conflen  = MAX_PATH_LN;
        if(ERROR_SUCCESS == RegQueryValueEx(hKey,
                      "ConfDir",
                      0,
                      NULL,
                      (LPBYTE)_conf,
                      (LPDWORD)&_conflen)) 
        {
            if(pLibPath==NULL) SETSTRINGLN(pLibPath,_conf,_conflen);
        }
        _conflen  = MAX_PATH_LN;
        if(ERROR_SUCCESS == RegQueryValueEx(hKey,
                      "DataDir",
                      0,
                      NULL,
                      (LPBYTE)_conf,
                      (LPDWORD)&_conflen)) 
        {
            if(pDbPath==NULL) SETSTRINGLN(pDbPath,_conf,_conflen);
        }
        RegCloseKey(hKey);
    }

    if(pLibPath==NULL) {
        _snprintf((char*)_conf,MAX_PATH_LN,"%s",lpLibrary);
    } else {
        _snprintf((char*)_conf,MAX_PATH_LN,"%s\\%s",pLibPath,lpLibrary);
        SetDllDirectory((LPCTSTR)pLibPath);
    }
    clptr.bLoaded = FALSE;
    if (stat (_conf, &_lStat) < 0) {
        char _temp[MAX_PATH_LN];
        _snprintf((char*)_temp,MAX_PATH_LN,"Library %s is not found",_conf);
        if(ppszErrorText!= NULL) SETSTRING((*ppszErrorText),_temp);
        rc = VSA_E_LOAD_FAILED;
        goto cleanup;
    } else {
        if(pEngineDate) *pEngineDate = _lStat.st_mtime;
    }
    if(hLibClamAvDLL == 0) {
        hInst = LoadLibrary((LPCSTR)_conf);
        hLibClamAvDLL = hInst;
    }
    if (NULL==hInst) {
        LPSTR pTr;
        len   = strlen((const char*)_conf);
        pTr   = (LPSTR)(_conf)+len+1;
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,NULL,GetLastError(),0,pTr,MAX_PATH_LN-(int)len-1,NULL);
        _conf[len] = '\n';
        if(ppszErrorText!= NULL) SETSTRING((*ppszErrorText),_conf);
        rc = VSA_E_LOAD_FAILED;
        goto cleanup;
    }
    clptr.dll_hdl = (DLL_HDL)hInst;
    base_fptr  = (DLL_ADR *) &(clptr.CLAMAV_FIRST_FUNC);
    for ( i=0 ; clamav_fps[i].function_name!=NULL ; i++ ) {
        fptr_index = clamav_fps[i].function_index;
        base_fptr[fptr_index] = NULL;
        if (NULL==(pFunc = GetProcAddress ((HMODULE)hInst,clamav_fps[i].function_name))) {
           char _temp[MAX_PATH_LN];
           _snprintf((char*)_temp,MAX_PATH_LN,"Function %s was not found in %s",clamav_fps[i].function_name,_conf);
           if(ppszErrorText!= NULL) SETSTRING((*ppszErrorText),_temp);
           rc = VSA_E_LOAD_FAILED;
           goto cleanup;
        } else {
           base_fptr[fptr_index] = (DLL_ADR)pFunc;
        }
    }
    clptr.bLoaded = TRUE;
#elif defined(__sun) || defined(sinix) || defined(__linux) || defined(_AIX) || (defined(__hpux) && defined(__ia64))
    void * hInst;
    void * pFunc;
    const char  *lpLibrary = "libclamav.so";
    const char  *lpLibPath = "/usb/lib";

    snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    i = stat (_conf, &_lStat);
    if(i < 0) {
        lpLibPath = "/lib";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    } else {
        hInst = dlopen(_conf,RTLD_LAZY);
        if(hInst == NULL) { i = -1; }
        else {
            if(pEngineDate)    { *pEngineDate = _lStat.st_mtime; }
            if(pLibPath==NULL) { SETSTRINGLN(pLibPath,lpLibPath,strlen(lpLibPath)); }
        }
    }
    i = stat (_conf, &_lStat);
    if(i < 0) {
        lpLibPath = "/lib64";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    } else {
        hInst = dlopen(_conf,RTLD_LAZY);
        if(hInst == NULL) { i = -1; }
        else {
            if(pEngineDate)    { *pEngineDate = _lStat.st_mtime; }
            if(pLibPath==NULL) { SETSTRINGLN(pLibPath,lpLibPath,strlen(lpLibPath)); }
        }
    }
    i = stat (_conf, &_lStat);
    if(i < 0) {
        lpLibPath = "/usr/lib64";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    } else {
        hInst = dlopen(_conf,RTLD_LAZY);
        if(hInst == NULL) { i = -1; }
        else { if(pEngineDate) *pEngineDate = _lStat.st_mtime; }
    }
    i = stat (_conf, &_lStat);
    if(i < 0) {
        lpLibrary = "libclamav.so.7";
        lpLibPath = "/usr/lib64";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    } else {
        hInst = dlopen(_conf,RTLD_LAZY);
        if(hInst == NULL) { i = -1; }
        else { if(pEngineDate) *pEngineDate = _lStat.st_mtime; }
    }
    i = stat (_conf, &_lStat);
    if(i < 0) {
        lpLibrary = "libclamav.so.9";
        lpLibPath = "/usr/lib64";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    } else {
        hInst = dlopen(_conf,RTLD_LAZY);
        if(hInst == NULL) { i = -1; }
        else { if(pEngineDate) *pEngineDate = _lStat.st_mtime; }
    }
    i = stat (_conf, &_lStat);
    if(i < 0) {
        lpLibrary = "libclamav.so.6";
        lpLibPath = "/usr/lib64";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    } else {
        hInst = dlopen(_conf,RTLD_LAZY);
        if(hInst == NULL) { i = -1; }
        else { if(pEngineDate) *pEngineDate = _lStat.st_mtime; }
    }
    i = stat (_conf, &_lStat);
    if(i < 0) {
       lpLibrary = "libclamav.so";
       hInst = dlopen(lpLibrary,RTLD_LAZY);
       if(hInst == NULL) {
         rc = VSA_E_LOAD_FAILED;
         goto cleanup;
       }
    } else {
        hInst = dlopen(_conf,RTLD_LAZY);
        if(hInst == NULL) { i = -1; rc = VSA_E_LOAD_FAILED; goto cleanup; }
        else {
            if(pEngineDate)    { *pEngineDate = _lStat.st_mtime; }
            if(pLibPath==NULL) { SETSTRINGLN(pLibPath,lpLibPath,strlen(lpLibPath)); }
        }
    }
    clptr.dll_hdl = (DLL_HDL)hInst;
    base_fptr  = (DLL_ADR *) &(clptr.CLAMAV_FIRST_FUNC);
    for ( i=0 ; clamav_fps[i].function_name!=NULL ; i++ ) {
        fptr_index = clamav_fps[i].function_index;
        base_fptr[fptr_index] = NULL;
        if (NULL==(pFunc = dlsym (hInst,clamav_fps[i].function_name))) {
           char _temp[MAX_PATH_LN];
           snprintf((char*)_temp,MAX_PATH_LN,"Function %s was not found in %s",clamav_fps[i].function_name,_conf);
           if(ppszErrorText!= NULL) SETSTRING((*ppszErrorText),_temp);
           rc = VSA_E_LOAD_FAILED;
           goto cleanup;
        } else {
           base_fptr[fptr_index] = (DLL_ADR)pFunc;
        }
    }
    clptr.bLoaded = TRUE;
#elif defined(__hppa) && !(defined(__hpux) && defined(__ia64))
    shl_t   hInst;
    void * pFunc;
    const char  *lpLibrary = "libclamav.sl";
    const char  *lpLibPath = "/usb/lib";
    snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    i = stat (_conf, &_lStat);
    if(i < 0) {
        lpLibPath = "/lib";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    } else {
        hInst = (shl_t) shl_load (_conf,BIND_DEFERRED | BIND_VERBOSE, 0);
        if(hInst == (shl_t) 0) { i = -1; }
        else { 
	  if(pEngineDate) *pEngineDate = _lStat.st_mtime; 
	  if(pLibPath==NULL) SETSTRINGLN(pLibPath,lpLibPath,strlen(lpLibPath));
	}
    }
    i = stat (_conf, &_lStat);
    if(i < 0) {
        lpLibPath = "/lib64";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    } else {
        hInst = (shl_t) shl_load (_conf,BIND_DEFERRED | BIND_VERBOSE, 0);
        if(hInst == (shl_t) 0) { i = -1; }
        else { 
	  if(pEngineDate) *pEngineDate = _lStat.st_mtime; 
	  if(pLibPath==NULL) SETSTRINGLN(pLibPath,lpLibPath,strlen(lpLibPath));
	}
    }
    i = stat (_conf, &_lStat);
    if(i < 0) {
        lpLibPath = "/usr/lib64";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    } else {
        hInst = (shl_t) shl_load (_conf,BIND_DEFERRED | BIND_VERBOSE, 0);
        if(hInst == (shl_t) 0) { i = -1; }
        else { 
	  if(pEngineDate) *pEngineDate = _lStat.st_mtime; 
	  if(pLibPath==NULL) SETSTRINGLN(pLibPath,lpLibPath,strlen(lpLibPath));
	}
    }
    i = stat (_conf, &_lStat);
    if(i < 0) {
       hInst = (shl_t) shl_load (lpLibrary,BIND_DEFERRED | BIND_VERBOSE, 0);
       if(hInst == (shl_t) 0) {	 
         rc = VSA_E_LOAD_FAILED;
         goto cleanup;
       }
    } else {
        hInst = (shl_t) shl_load (_conf,BIND_DEFERRED | BIND_VERBOSE, 0);
        if(hInst == (shl_t) 0) { i = -1; rc = VSA_E_LOAD_FAILED; goto cleanup;}
        else { 
	  if(pEngineDate) *pEngineDate = _lStat.st_mtime; 
	  if(pLibPath==NULL) SETSTRINGLN(pLibPath,lpLibPath,strlen(lpLibPath));
	}
    }
    clptr.dll_hdl = (DLL_HDL)hInst;
    base_fptr  = (DLL_ADR *) &(clptr.CLAMAV_FIRST_FUNC);
    for ( i=0 ; clamav_fps[i].function_name!=NULL ; i++ ) {
        fptr_index = clamav_fps[i].function_index;
        base_fptr[fptr_index] = NULL;
        if(shl_findsym(&hInst,clamav_fps[i].function_name,TYPE_PROCEDURE,(void**)&pFunc) != 0) {
           char _temp[MAX_PATH_LN];
           snprintf((char*)_temp,MAX_PATH_LN,"Function %s was not found in %s",clamav_fps[i].function_name,_conf);
           if(ppszErrorText!= NULL) SETSTRING((*ppszErrorText),_temp);
           rc = VSA_E_LOAD_FAILED;
           goto cleanup;
        } else {
           base_fptr[fptr_index] = (DLL_ADR)pFunc;
        }
    }
    clptr.bLoaded = TRUE;
# elif defined(__MVS__)
    dllhandle * hInst;
    void * pFunc;
    const char  *lpLibrary = "libclamav.so";
    const char  *lpLibPath = "/usb/lib";
    snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    i = stat (_conf, &_lStat);
    if(i < 0) {
        lpLibPath = "/lib";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    } else {
        hInst = (dllhandle *)dllload(_conf);
        if(hInst == NULL) { i = -1; }
        else { 
	  if(pEngineDate) *pEngineDate = _lStat.st_mtime; 
	  if(pLibPath==NULL) SETSTRINGLN(pLibPath,lpLibPath,strlen(lpLibPath));
	}
    }
    i = stat (_conf, &_lStat);
    if(i < 0) {
        lpLibPath = "/lib64";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    } else {
        hInst = (dllhandle *)dllload(_conf);
        if(hInst == NULL) { i = -1; }
        else { 
	  if(pEngineDate) *pEngineDate = _lStat.st_mtime; 
	  if(pLibPath==NULL) SETSTRINGLN(pLibPath,lpLibPath,strlen(lpLibPath));
	}
    }
    i = stat (_conf, &_lStat);
    if(i < 0) {
        lpLibPath = "/usr/lib64";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    } else {
        hInst = (dllhandle *)dllload(_conf);
        if(hInst == NULL) { i = -1; }
        else { 
	  if(pEngineDate) *pEngineDate = _lStat.st_mtime; 
	  if(pLibPath==NULL) SETSTRINGLN(pLibPath,lpLibPath,strlen(lpLibPath));
	}
    }
    i = stat (_conf, &_lStat);
    if(i < 0) {
        hInst = (dllhandle *)dllload(lpLibrary);
        if(hInst == NULL) {
         rc = VSA_E_LOAD_FAILED;
         goto cleanup;
	}
    } else {
       hInst = (dllhandle *)dllload(_conf);
       if(hInst == NULL) { i = -1; rc = VSA_E_LOAD_FAILED; goto cleanup; }
        else { 
	  if(pEngineDate) *pEngineDate = _lStat.st_mtime; 
	  if(pLibPath==NULL) SETSTRINGLN(pLibPath,lpLibPath,strlen(lpLibPath));
	}
    }
    clptr.dll_hdl = (DLL_HDL)hInst;
    base_fptr  = (DLL_ADR *) &(clptr.CLAMAV_FIRST_FUNC);
    for ( i=0 ; clamav_fps[i].function_name!=NULL ; i++ ) {
        fptr_index = clamav_fps[i].function_index;
        base_fptr[fptr_index] = NULL;
        if (NULL==(pFunc = (void*)dllqueryfn ((dllhandle *)hInst,clamav_fps[i].function_name))) {
           char _temp[MAX_PATH_LN];
           snprintf((char*)_temp,MAX_PATH_LN,"Function %s was not found in %s",clamav_fps[i].function_name,_conf);
           if(ppszErrorText!= NULL) SETSTRING((*ppszErrorText),_temp);
           rc = VSA_E_LOAD_FAILED;
           goto cleanup;
        } else {
           base_fptr[fptr_index] = (DLL_ADR)pFunc;
        }
    }
    clptr.bLoaded = TRUE;
#else
    if(ppszErrorText!= NULL) SETSTRING((*ppszErrorText),"Platform not supported");
    return VSA_E_LOAD_FAILED;
#endif
cleanup:
    return rc;
} /* vsaLoadEngine */

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


static VSA_RC vsaSetScanConfig(VSA_SCANPARAM *p_scanparam,VSA_OPTPARAMS *p_optparams, USRDATA *usrdata, struct cl_engine *engine)
{
    VSA_RC     rc        = VSA_OK;
    Int        i         = 0,
               arraysize = (p_optparams?p_optparams->usOptParams:0);
    if(pClamFPtr==NULL||pClamFPtr->bLoaded==FALSE)
        return VSA_E_LOAD_FAILED;
    /*
     * set the optional setting
     */
    for (i=0; i<arraysize; i++)
    {
        switch (p_optparams->pOptParam[i].tCode)
        {/* SCANBESTEFFORT should provide a scan with "best effort" of the engine.
          * this interface of Sym. Scan Engine does not allow to set such parameters.
          * but at least the adapter must know the parameter type!
          */
        case VS_OP_SCANBESTEFFORT:
            if((p_optparams->pOptParam[i].pvValue) != NULL) {
                usrdata->bScanBestEffort = TRUE;
                usrdata->bScanAllFiles = TRUE;
                usrdata->bScanCompressed = TRUE;
                usrdata->cl_scan_options.parse |= ~0; /* enable all parsers */
                usrdata->cl_scan_options.heuristic |= ~0; /* enable all heuristics */
                usrdata->cl_scan_options.mail |= ~0; /* enable all mail */
                usrdata->cl_scan_options.general |= ~0;
            }
            else {
                usrdata->bScanBestEffort = FALSE;
                usrdata->bScanAllFiles = FALSE;
                usrdata->bScanCompressed = FALSE;
                usrdata->cl_scan_options.parse = 0;
                usrdata->cl_scan_options.general = 0;
                usrdata->cl_scan_options.heuristic = 0;
                usrdata->cl_scan_options.mail = 0;
                usrdata->cl_scan_options.dev = 0;
            }
            break;
        case VS_OP_SCANALLFILES:
            if((p_optparams->pOptParam[i].pvValue) != NULL) {
                usrdata->bScanAllFiles = TRUE;
                usrdata->cl_scan_options.parse |= ~0; /* enable all parsers */
            }
            else {
                usrdata->bScanAllFiles = FALSE;
            }
            break;
        case VS_OP_SCANEXTRACT:
            if((p_optparams->pOptParam[i].pvValue) != NULL) {
                usrdata->bScanCompressed = TRUE;
                usrdata->cl_scan_options.parse |= 0x1;
            }
            else {
                usrdata->bScanCompressed = FALSE;
                usrdata->cl_scan_options.parse |= ~0x1;
            }
            break;
        case VS_OP_SCANLIMIT:
             if ((p_optparams->pOptParam[i].pvValue)!=NULL)
                 pClamFPtr->fp_cl_engine_set_num(engine, CL_ENGINE_MAX_SCANSIZE, (long long) ((size_t)p_optparams->pOptParam[i].pvValue));
        break;
        case VS_OP_SCANEXTRACT_SIZE:
             if ((p_optparams->pOptParam[i].pvValue)!=NULL)
                 pClamFPtr->fp_cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, (long long) ((size_t)p_optparams->pOptParam[i].pvValue));
        break;
        case VS_OP_SCANEXTRACT_DEPTH:
             if ((p_optparams->pOptParam[i].pvValue)!=NULL)
                pClamFPtr->fp_cl_engine_set_num(engine, CL_ENGINE_MAX_RECURSION, (long long) ((size_t)p_optparams->pOptParam[i].pvValue));
        break;
        case VS_OP_SCANHEURISTICLEVEL:
             if ((p_optparams->pOptParam[i].pvValue)!=NULL) {
                usrdata->cl_scan_options.heuristic = (unsigned int)p_optparams->pOptParam[i].pvValue;
                usrdata->cl_scan_options.general |= 0xf;
             } else {
                usrdata->cl_scan_options.heuristic = 0;
                usrdata->cl_scan_options.general = 0;
             }
        break;
        case VS_OP_SCANONLYHEURISTIC:
             if ((p_optparams->pOptParam[i].pvValue)!=NULL) {
                usrdata->cl_scan_options.general |= 0x8;
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
        default:
        break;
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
    int         clam_rc  = 0;
    const char *virname  = NULL;
    VSA_RC           rc  = VSA_OK;
    unsigned long int scanned = 0;
    if(pUsrData == NULL)
        return VSA_E_NULL_PARAM;

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
        /*
        * Comment:
        * Perform the scan!
        * This example adapter performs a plain memory compare,
        * because this coding should not demonstrate virus scan functionality,
        * but implementing SAP virus scan interface.
        * Normally you should compare the byte signatures!
        */
        /*
        * Scan local file
        */
#ifdef CL_SCAN_STDOPT
        /* CCQ_OFF */
        clam_rc = pClamFPtr->fp_cl_scanfile(
                (const char*)pszObjectName,
                (const char**)&virname,
                &scanned,
                (const struct cl_engine *)pEngine,
                CL_SCAN_STDOPT);
#else
            /* CCQ_OFF */
        clam_rc = pClamFPtr->fp_cl_scanfile(
                (const char*)pszObjectName,
                (const char**)&virname,
                &scanned,
                (const struct cl_engine *)pEngine,
                &(pUsrData->cl_scan_options));
#endif
            /* CCQ_ON */
        if(clam_rc != CL_CLEAN)
        {
            sprintf((char*)errorReason,"%s",(PChar)pClamFPtr->fp_cl_strerror(clam_rc));
            switch(clam_rc)
            {
            case CL_VIRUS: rc = VSA_E_VIRUS_FOUND;
                break;
            default:       rc = VSA_E_SCAN_FAILED;
                sprintf((char*)errorReason,"ClamAV engine with internal,unknown error.");
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
        if(clam_rc == CL_VIRUS)
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
    }
cleanup:
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
            rc = getByteType(_decompr,lLength,NULL,NULL,szExt,szMimeType,0,&status,&text,&a,&b,&pUsrData->tFileType,&pUsrData->tObjectType);
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
                    pUsrData->bScanMimeTypesWildCard,
                    pUsrData->bBlockMimeTypesWildCard,
                    szErrorName,
                    szErrorFreeName);
                if(rc) CLEANUP(rc);
            }
            {
                FILE *fpOut = NULL;
                Char szFileName[1024];
                Char szEntryName[512];
                PChar  _tmpPath = NULL; /* CCQ_OFF */
                if(getenv("TMPDIR") == NULL) {
#ifdef _WIN32
                    _tmpPath = (PChar)strdup(".");
#else
                    _tmpPath = (PChar)strdup("/tmp");
#endif
                } else {
                    _tmpPath = (PChar)strdup(getenv("TMPDIR"));
                }
                sprintf((char*)szFileName,"%.500s%.10s%.510s",(char*)_tmpPath, DIR_SEP, (char*)getCleanFilePatch(sentry->name, 511, (PChar)&szEntryName));
                if(_tmpPath) free(_tmpPath);

                fpOut = fopen((const char*)szFileName,"wb");
                if(fpOut != NULL) {
                    fwrite(_decompr,1,lLength,fpOut);
                    fclose(fpOut);
                }
                rc = scanFile(
                    pEngine,
                    pUsrData->uiJobID,
                    szFileName,
                    pUsrData,
                    errorReason);
                unlink((const char*)szFileName);
                /* CCQ_ON */
            }
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
        if (mime == TRUE && in[i] == '*')
        {
            if (param->tCode == VS_OP_SCANMIMETYPES)
            {
                pUsrData->bScanMimeTypesWildCard = TRUE;
            }
            else if (param->tCode == VS_OP_BLOCKMIMETYPES)
            {
                pUsrData->bBlockMimeTypesWildCard = TRUE;
            }
        }
    }
    if(i>0 && i < (inlen * 2) && dest[i] != ';')
        dest[i] = ';';
    return VSA_OK;
} /* vsaSetContentTypeParametes */
#endif

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
        case VS_IP_INITDIRECTORY:
           usrdata->enginedirectory = &p_intparams->pInitParam[i];
        break;
        case VS_IP_INITDRIVERS:
           usrdata->drivers = &p_intparams->pInitParam[i];
        break;
        case VS_IP_INITTEMP_PATH:
           usrdata->tmpdir = &p_intparams->pInitParam[i];
        break;
        default:
        break;
        }
    }
    return rc;
}

static VSA_RC getFileSize(Char *pszfilename, size_t *size)
{
      VSA_RC rc = VSA_OK;

      struct stat     buf;
        if (pszfilename == NULL)
            return VSA_E_NULL_PARAM;
        
        if (0!=(stat((const char*)pszfilename,&buf)))
            return VSA_E_SCAN_FAILED;
      
        if(size!=NULL)
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

