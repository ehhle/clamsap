 
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

/*--------------------------------------------------------------------*/
/* Adapter defines                                                    */
/*--------------------------------------------------------------------*/
#ifdef SAPwithUNICODE
#undef SAPwithUNICODE
#undef UNICODE
#undef _UNICODE
#endif

/*--------------------------------------------------------------------*/
/* system includes (OS-dependent)                                     */
/*--------------------------------------------------------------------*/
#ifdef _WIN32
#ifndef WIN32_MEAN_AND_LEAN
#define WIN32_MEAN_AND_LEAN
#include <windows.h>
#include <Urlmon.h>
#endif
#endif

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <locale.h>
#include <string.h>
#include <sys/stat.h>

/*--------------------------------------------------------------------*/
/* SAP includes                                                       */
/*--------------------------------------------------------------------*/
#include "vsaxxtyp.h"
#include "vsmime.h"

#define CLEANUP(x)          { rc = x; goto cleanup; }

/*         MAGCI function pointers                */
static struct magic_function_s magic_fps[] =
{
    DLL_MAGIC_DEFINE(magic_open),
    DLL_MAGIC_DEFINE(magic_close),
    DLL_MAGIC_DEFINE(magic_load),
    DLL_MAGIC_DEFINE(magic_buffer),
    DLL_MAGIC_DEFINE(magic_file),
    {NULL}
};

static magic_function_pointers clptr = {NULL,NULL,NULL,NULL,NULL,FALSE,NULL};
static magic_function_pointers *pMagicFPtr = &clptr;
static magic_t gMagic;

static Bool isHTMLCharacter(int c);
static void setByteType(PChar fileName,
                        PChar fileExt,
                        PChar ext,
                        PChar mimetype,
                        PChar defaultExt,
                        PChar defaultMimeType,
                        PByte pBuffer,
                        size_t lBuffer);

static PChar vsaGetByteMimeType(void *pBuffer, size_t lBuffer);

typedef enum TYPE_STATUS {
    UNKNOWN,
    BEGIN,
    SEARCH,
    LOOKAHEAD,
    ENDSIGNATURE
} TYPE_STATUS;
/*--------------------------------------------------------------------*/
/* helper functions                                                   */
/*--------------------------------------------------------------------*/
int vsaLoadMagicLibrary(PPChar ppszErrorText)
{
    VSA_RC         rc = VSA_OK;
#ifndef _WIN32
    int            i,
        fptr_index;
    DLL_MAGIC_ADR * base_fptr;
    char          _conf[MAX_PATH_LN];
    struct stat   _lStat;
    size_t         len = 0;
#endif

#ifdef _WIN32
    clptr.dll_hdl = 0;
    clptr.bLoaded = TRUE;
    goto cleanup;
#elif defined(__sun) || defined(sinix) || defined(__linux) || defined(_AIX) || (defined(__hpux) && defined(__ia64))
    void * hInst;
    void * pFunc;
    const char  *lpLibrary = "libmagic.so";
    const char  *lpLibPath = "/usb/lib";

    if(clptr.bLoaded == TRUE) goto libmagic;
    memset(pMagicFPtr,0,sizeof(magic_function_pointers));

    snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    i = stat(_conf,&_lStat);
    if(i < 0) {
        lpLibPath = "/lib";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    }
    else {
        hInst = dlopen(_conf,RTLD_LAZY);
        if(hInst == NULL) { i = -1; }
    }
    i = stat(_conf,&_lStat);
    if(i < 0) {
        lpLibPath = "/lib64";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    }
    else {
        hInst = dlopen(_conf,RTLD_LAZY);
        if(hInst == NULL) { i = -1; }
    }
    i = stat(_conf,&_lStat);
    if(i < 0) {
        lpLibPath = "/usr/lib64";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    }
    else {
        hInst = dlopen(_conf,RTLD_LAZY);
        if(hInst == NULL) { i = -1; }
    }
    i = stat(_conf,&_lStat);
    if(i < 0) {
        lpLibrary = "libmagic.so.1";
        lpLibPath = "/usr/lib64";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    }
    else {
        hInst = dlopen(_conf,RTLD_LAZY);
        if(hInst == NULL) { i = -1; }
    }
    i = stat(_conf,&_lStat);
    if(i < 0) {
        hInst = dlopen(lpLibrary,RTLD_LAZY);
        if(hInst == NULL) {
            rc = VSA_E_LOAD_FAILED;
            goto cleanup;
        }
    }
    else {
        hInst = dlopen(_conf,RTLD_LAZY);
        if(hInst == NULL) { i = -1; rc = VSA_E_LOAD_FAILED; goto cleanup; }
    }
    clptr.dll_hdl = (DLL_MAGIC_HDL)hInst;
    base_fptr = (DLL_MAGIC_ADR *)&(clptr.MAGIC_FIRST_FUNC);
    for(i = 0; magic_fps[i].function_name != NULL; i++) {
        fptr_index = magic_fps[i].function_index;
        base_fptr[fptr_index] = NULL;
        if(NULL == (pFunc = dlsym(hInst,magic_fps[i].function_name))) {
            char _temp[MAX_PATH_LN];
            snprintf((char*)_temp,MAX_PATH_LN,"Function %s was not found in %s",magic_fps[i].function_name,_conf);
            if(ppszErrorText != NULL) SETERRORSTRING((*ppszErrorText),_temp);
            rc = VSA_E_LOAD_FAILED;
            goto cleanup;
        }
        else {
            base_fptr[fptr_index] = (DLL_MAGIC_ADR)pFunc;
        }
    }
    clptr.bLoaded = TRUE;
#elif defined(__hppa) && !(defined(__hpux) && defined(__ia64))
    shl_t   hInst;
    void * pFunc;
    const char  *lpLibrary = "libmagic.sl";
    const char  *lpLibPath = "/usb/lib";

    if(clptr.bLoaded == TRUE) goto libmagic;
    memset(pMagicFPtr,0,sizeof(magic_function_pointers));

    snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    i = stat(_conf,&_lStat);
    if(i < 0) {
        lpLibPath = "/lib";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    }
    else {
        hInst = (shl_t)shl_load(_conf,BIND_DEFERRED | BIND_VERBOSE,0);
        if(hInst == (shl_t)0) { i = -1; }
    }
    i = stat(_conf,&_lStat);
    if(i < 0) {
        lpLibPath = "/lib64";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    }
    else {
        hInst = (shl_t)shl_load(_conf,BIND_DEFERRED | BIND_VERBOSE,0);
        if(hInst == (shl_t)0) { i = -1; }
    }
    i = stat(_conf,&_lStat);
    if(i < 0) {
        lpLibPath = "/usr/lib64";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    }
    else {
        hInst = (shl_t)shl_load(_conf,BIND_DEFERRED | BIND_VERBOSE,0);
        if(hInst == (shl_t)0) { i = -1; }
    }
    i = stat(_conf,&_lStat);
    if(i < 0) {
        hInst = (shl_t)shl_load(lpLibrary,BIND_DEFERRED | BIND_VERBOSE,0);
        if(hInst == (shl_t)0) {
            rc = VSA_E_LOAD_FAILED;
            goto cleanup;
        }
    }
    else {
        hInst = (shl_t)shl_load(_conf,BIND_DEFERRED | BIND_VERBOSE,0);
        if(hInst == (shl_t)0) { i = -1; rc = VSA_E_LOAD_FAILED; goto cleanup; }
    }
    clptr.dll_hdl = (DLL_MAGIC_HDL)hInst;
    base_fptr = (DLL_MAGIC_ADR *)&(clptr.MAGIC_FIRST_FUNC);
    for(i = 0; magic_fps[i].function_name != NULL; i++) {
        fptr_index = magic_fps[i].function_index;
        base_fptr[fptr_index] = NULL;
        if(shl_findsym(&hInst,magic_fps[i].function_name,TYPE_PROCEDURE,(void**)&pFunc) != 0) {
            char _temp[MAX_PATH_LN];
            snprintf((char*)_temp,MAX_PATH_LN,"Function %s was not found in %s",magic_fps[i].function_name,_conf);
            if(ppszErrorText != NULL) SETERRORSTRING((*ppszErrorText),_temp);
            rc = VSA_E_LOAD_FAILED;
            goto cleanup;
        }
        else {
            base_fptr[fptr_index] = (DLL_MAGIC_ADR)pFunc;
        }
    }
    clptr.bLoaded = TRUE;
# elif defined(__MVS__)
    dllhandle * hInst;
    void * pFunc;
    const char  *lpLibrary = "libmagic.so";
    const char  *lpLibPath = "/usb/lib";

    if(clptr.bLoaded == TRUE) goto libmagic;
    memset(pMagicFPtr,0,sizeof(magic_function_pointers));

    snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    i = stat(_conf,&_lStat);
    if(i < 0) {
        lpLibPath = "/lib";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    }
    else {
        hInst = (dllhandle *)dllload(_conf);
        if(hInst == NULL) { i = -1; }
    }
    i = stat(_conf,&_lStat);
    if(i < 0) {
        lpLibPath = "/lib64";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    }
    else {
        hInst = (dllhandle *)dllload(_conf);
        if(hInst == NULL) { i = -1; }
    }
    i = stat(_conf,&_lStat);
    if(i < 0) {
        lpLibPath = "/usr/lib64";
        snprintf((char*)_conf,MAX_PATH_LN,"%s/%s",lpLibPath,lpLibrary);
    }
    else {
        hInst = (dllhandle *)dllload(_conf);
        if(hInst == NULL) { i = -1; }
    }
    i = stat(_conf,&_lStat);
    if(i < 0) {
        hInst = (dllhandle *)dllload(lpLibrary);
        if(hInst == NULL) {
            rc = VSA_E_LOAD_FAILED;
            goto cleanup;
        }
    }
    else {
        hInst = (dllhandle *)dllload(_conf);
        if(hInst == NULL) { i = -1; rc = VSA_E_LOAD_FAILED; goto cleanup; }
    }
    clptr.dll_hdl = (DLL_MAGIC_HDL)hInst;
    base_fptr = (DLL_MAGIC_ADR *)&(clptr.MAGIC_FIRST_FUNC);
    for(i = 0; magic_fps[i].function_name != NULL; i++) {
        fptr_index = magic_fps[i].function_index;
        base_fptr[fptr_index] = NULL;
        if(NULL == (pFunc = (void*)dllqueryfn((dllhandle *)hInst,magic_fps[i].function_name))) {
            char _temp[MAX_PATH_LN];
            snprintf((char*)_temp,MAX_PATH_LN,"Function %s was not found in %s",magic_fps[i].function_name,_conf);
            if(ppszErrorText != NULL) SETERRORSTRING((*ppszErrorText),_temp);
            rc = VSA_E_LOAD_FAILED;
            goto cleanup;
        }
        else {
            base_fptr[fptr_index] = (DLL_MAGIC_ADR)pFunc;
        }
    }
    clptr.bLoaded = TRUE;
#else
    if(ppszErrorText != NULL) SETERRORSTRING((*ppszErrorText),"Platform not supported");
    return VSA_E_LOAD_FAILED;
#endif
libmagic:
#ifndef _WIN32
    if(pMagicFPtr->bLoaded) {
        gMagic = pMagicFPtr->fp_magic_open(0x000020 | 0x000200 | 0x000010 | 0x000400);
        rc = pMagicFPtr->fp_magic_load(gMagic,NULL);
    }
#endif
cleanup:
    return rc;
}

void vsaCloseMagicLibrary(void)
{
#ifdef _WIN32
    return;
#else
    if(pMagicFPtr->bLoaded) {
        pMagicFPtr->fp_magic_close(gMagic);
        #ifdef _WIN32
        #elif defined(__sun) || defined(sinix) || defined(__linux) || defined(_AIX) || (defined(__hpux) && defined(__ia64))
            dlclose(clptr.dll_hdl);
        #elif defined(__hppa) && !(defined(__hpux) && defined(__ia64))
            shl_unload((shl_t)clptr.dll_hdl);
        #else
        #endif
        memset(pMagicFPtr,0,sizeof(magic_function_pointers));
    }
    return;
#endif
}

PChar vsaGetFileMimeType(PChar pszFileName)
{
    VSA_RC rc = VSA_OK;
    PChar pMimeType = NULL;
    size_t len = 0;
#ifdef _WIN32
    LPWSTR pM = 0;
    LPWSTR pInM = (LPWSTR)malloc((strlen((const char*)pszFileName) * 2) + 2);
    if(pInM == NULL) goto cleanup;
    MultiByteToWideChar(CP_UTF8,0,pszFileName,(int)strlen((const char*)pszFileName),pInM,(int)strlen((const char*)pszFileName) * 2);
    if(FindMimeFromData(NULL,pInM,NULL,0,NULL,(0x00000001 | 0x00000002),&pM,0)) goto cleanup;
    pMimeType = (PChar)malloc(1024 * sizeof(char));
    if(pMimeType == NULL) {
        goto cleanup;
    }
    WideCharToMultiByte(CP_ACP, 0, pM, SysStringLen(pM), pMimeType, 1023, NULL, FALSE);
cleanup:
    if(pInM) free(pInM);
    if(pM) free(pM);
    return pMimeType;
#else
    const char *pMTyp = 0;
    if(pMagicFPtr && pMagicFPtr->bLoaded) {
       magic_t lMagic = pMagicFPtr->fp_magic_open(0x000200 | 0x000010 | 0x000400);
       pMagicFPtr->fp_magic_load(lMagic,NULL);
       pMTyp = pMagicFPtr->fp_magic_file(lMagic, (const char *)pszFileName);
       if(pMTyp != 0) {
          const char *p = strrchr((const char*)pMTyp,(int)';');
          if(p == NULL) /* no extras */ {
             SETSTRING(pMimeType,pMTyp);
          } else {
             size_t magLen = (p - pMTyp);
             if(magLen > 0 && magLen < MAX_PATH_LN) {
                SETSTRINGLN(pMimeType,pMTyp,magLen);
             } else {
                SETSTRING(pMimeType,pMTyp);
             }
          }
       }
       pMagicFPtr->fp_magic_close(lMagic);
       /*pMTyp = pMagicFPtr->fp_magic_file(gMagic, (const char *)pszFileName);*/
    }
    if(pMTyp == 0) return NULL;
cleanup:
    if(rc != VSA_OK) return NULL;
    return pMimeType;
#endif
}

VSA_RC addContentInfo(
    UInt              uiJobID,
    PChar             pszObjectName,
    size_t            lObjectSize,
    VS_OBJECTTYPE_T   tContentType,
    PChar             pszExtension,
    PChar             pszContentType,
    PChar             pszCharSet,
    UInt              lContent,
    PPVSA_CONTENTINFO pp_content)
{
    size_t len = 0;
    VSA_RC rc = VSA_OK;
    if(pp_content == NULL)
        return VSA_E_NULL_PARAM;

    if((*pp_content) == NULL && lContent == 0) {
        (*pp_content) = (PVSA_CONTENTINFO)calloc(1,sizeof(VSA_CONTENTINFO));
    }
    else {
        (*pp_content) = (PVSA_CONTENTINFO)realloc((*pp_content),(lContent + 1) * sizeof(VSA_CONTENTINFO));
    }
    if((*pp_content) == NULL)
        return VSA_E_NO_SPACE;

    (*pp_content)[lContent].struct_size = sizeof(VSA_CONTENTINFO);
    (*pp_content)[lContent].match_so = 0;
    (*pp_content)[lContent].match_eo = 0;
    (*pp_content)[lContent].uiJobID = uiJobID;
    (*pp_content)[lContent].lObjectSize = lObjectSize;
    (*pp_content)[lContent].tObjectType = tContentType;
    if(pszObjectName) {
        SETSTRING((*pp_content)[lContent].pszObjectName,pszObjectName);
    }
    if(pszExtension) {
        SETSTRING((*pp_content)[lContent].pszExtension,pszExtension);
    }
    else {
        SETSTRING((*pp_content)[lContent].pszExtension,".*");
    }
    if(pszContentType) {
        SETSTRING((*pp_content)[lContent].pszContentType,pszContentType);
    }
    else {
        SETSTRING((*pp_content)[lContent].pszContentType,"unknown/unknown");
    }
    if(pszCharSet) {
        SETSTRING((*pp_content)[lContent].pszCharSet,pszCharSet);
    }
    else {
        SETSTRING((*pp_content)[lContent].pszCharSet,"");
    }
cleanup:
    return rc;
} /* addContentInfo */

VSA_RC addScanError(UInt            uiJobID,
    PChar           pszObjectName,
    size_t          lObjectSize,
    Int             iErrorRC,
    PChar           pszErrorText,
    UInt            lError,
    PPVSA_SCANERROR pp_scanerror)
{
    size_t len = 0;
    VSA_RC rc = VSA_OK;

    if(pp_scanerror == NULL)
        return VSA_E_NULL_PARAM;

    if((*pp_scanerror) == NULL && lError == 0) {
        (*pp_scanerror) = (PVSA_SCANERROR)calloc(1,sizeof(VSA_SCANERROR));
    }
    else {
        (*pp_scanerror) = (PVSA_SCANERROR)realloc((*pp_scanerror),(lError + 1) * sizeof(VSA_SCANERROR));
    }
    if((*pp_scanerror) == NULL)
        return VSA_E_NO_SPACE;

    if((*pp_scanerror) == NULL)
        return VSA_E_NO_SPACE;

    (*pp_scanerror)[lError].struct_size = sizeof(VSA_SCANERROR);
    (*pp_scanerror)[lError].lObjectSize = lObjectSize;
    (*pp_scanerror)[lError].iErrorRC = iErrorRC;
    (*pp_scanerror)[lError].uiJobID = uiJobID;
    if(pszErrorText) {
        SETSTRING((*pp_scanerror)[lError].pszErrorText,pszErrorText);
    }
    else {
        SETSTRING((*pp_scanerror)[lError].pszErrorText,"Generic error");
    }
    if(pszObjectName) {
        SETSTRING((*pp_scanerror)[lError].pszObjectName,pszObjectName);
    }

cleanup:
    return rc;
} /* addScanError */

VSA_RC addVirusInfo(UInt            uiJobID,
    PChar           pszObjectName,
    size_t          lObjectSize,
    Bool            bRepairable,
    VS_DETECTTYPE_T tDetectType,
    VS_VIRUSTYPE_T  tVirusType,
    VS_OBJECTTYPE_T tObjectType,
    VS_ACTIONTYPE_T tActionType,
    UInt            uiVirusID,
    PChar           pszVirusName,
    PChar           pszFreeTextInfo,
    UInt            lInfected,
    PPVSA_VIRUSINFO pp_virusinfo)
{
    size_t len = 0;
    VSA_RC rc = VSA_OK;
    if(pp_virusinfo == NULL)
        return VSA_E_NULL_PARAM;

    if((*pp_virusinfo) == NULL && lInfected == 0) {
        (*pp_virusinfo) = (PVSA_VIRUSINFO)calloc(1,sizeof(VSA_VIRUSINFO));
    }
    else {
        (*pp_virusinfo) = (PVSA_VIRUSINFO)realloc((*pp_virusinfo),(lInfected + 1) * sizeof(VSA_VIRUSINFO));
    }
    if((*pp_virusinfo) == NULL)
        return VSA_E_NO_SPACE;

    (*pp_virusinfo)[lInfected].struct_size = sizeof(VSA_VIRUSINFO);
    (*pp_virusinfo)[lInfected].bRepairable = bRepairable;
    (*pp_virusinfo)[lInfected].uiVirusID = uiVirusID;
    (*pp_virusinfo)[lInfected].uiJobID = uiJobID;
    (*pp_virusinfo)[lInfected].lObjectSize = lObjectSize;
    (*pp_virusinfo)[lInfected].tActionType = tActionType;
    (*pp_virusinfo)[lInfected].tDetectType = tDetectType;
    (*pp_virusinfo)[lInfected].tObjectType = tObjectType;
    (*pp_virusinfo)[lInfected].tVirusType = tVirusType;
    if(pszObjectName) {
        SETSTRING((*pp_virusinfo)[lInfected].pszObjectName,pszObjectName);
    }
    if(pszVirusName) {
        SETSTRING((*pp_virusinfo)[lInfected].pszVirusName,pszVirusName);
    }
    else {
        SETSTRING((*pp_virusinfo)[lInfected].pszVirusName,"Scanner.Limits.Exceeded");
    }
    if(pszFreeTextInfo) {
        SETSTRING((*pp_virusinfo)[lInfected].pszFreeTextInfo,pszFreeTextInfo);
    }
    else {
        SETSTRING((*pp_virusinfo)[lInfected].pszFreeTextInfo,"");
    }

cleanup:
    return rc;
} /* addVirusInfo */

VSA_RC getFileType(PChar filename,PChar ext,PChar mimetype,VS_OBJECTTYPE_T *tType)
{
    const char *p = NULL;
    int i;
    memset(ext,0,EXT_LN);
    ext[0] = '*';
    ext[1] = 0;
    if(filename == NULL || *filename == 0)
    {
        if(tType == NULL){
            return VSA_OK;
        }
        *tType = VS_OT_UNKNOWN;
    }
    if(tType == NULL) {
        return VSA_OK;
    }
    p = strrchr((const char*)filename,(int)'.');
    if(p == NULL) /* no file extension */
    {
        ext[0] = 0;
    }
    else  if(p != NULL && (strlen((const char*)p) > (size_t)2))
    {
        p++;
        ext[0] = '.';
        for(i = 0;i<(EXT_LN-2) && p[i] != 0;i++)
            ext[i + 1] = tolower(p[i]);
        if(
            ((ext[1] == 'e' && ext[2] == 'x' && ext[3] == 'e') ||
            (ext[1] == 'b' && ext[2] == 'i' && ext[3] == 'n') ||
            (ext[1] == 'r' && ext[2] == 'a' && ext[3] == 'w') ||
            (ext[1] == 'r' && ext[2] == 'e' && ext[3] == 'o') ||
            (ext[1] == 'c' && ext[2] == 'o' && ext[3] == 'm'))
            )
        {
            strcpy((char *)mimetype,(const char *)"application/octet-stream");
            *tType = VS_OT_BINARY;
        }
        else if(
            (ext[1] == 't' && ext[2] == 'x' && ext[3] == 't') ||
            (ext[1] == 't' && ext[2] == 'r' && ext[3] == 'c') ||
            (ext[1] == 'l' && ext[2] == 'o' && ext[3] == 'g')
            )
        {
            strcpy((char *)mimetype,(const char *)"text/plain");
            *tType = VS_OT_TEXT;
        }
        else if(ext[1] == 's' && ext[2] == 'a' && ext[3] == 'r')
        {
            strcpy((char *)mimetype,(const char *)"application/vnd.sar");
            *tType = VS_OT_SAR;
        }
        else if(ext[1] == 'z' && ext[2] == 'i' && ext[3] == 'p')
        {
            strcpy((char *)mimetype,(const char *)"application/zip");
            *tType = VS_OT_ZIP;
        }
        else if(ext[1] == 'r' && ext[2] == 'a' && ext[3] == 'r')
        {
            strcpy((char *)mimetype,(const char *)"application/rar");
            *tType = VS_OT_RAR;
        }
        else if(ext[1] == 'h' && ext[2] == 't' && ext[3] == 'm')
        {
            strcpy((char *)mimetype,(const char *)"text/html");
            *tType = VS_OT_HTML;
        }
        else if(ext[1] == 'x' && ext[2] == 'm' && ext[3] == 'l')
        {
            strcpy((char *)mimetype,(const char *)"text/xml");
            *tType = VS_OT_XML;
        }
        else if(ext[1] == 'x' && ext[2] == 's' && ext[3] == 'l')
        {
            strcpy((char *)mimetype,(const char *)"text/xsl");
            *tType = VS_OT_XSL;
        }
        else if(ext[1] == 'p' && ext[2] == 'd' && ext[3] == 'f')
        {
            strcpy((char *)mimetype,(const char *)"application/pdf");
            *tType = VS_OT_PDF;
        }
        else if(ext[1] == 'g' && ext[2] == 'i' && ext[3] == 'f')
        {
            strcpy((char *)mimetype,(const char *)"image/gif");
            *tType = VS_OT_GIF;
        }
        else if(ext[1] == 'j' && ext[2] == 'p' && (ext[3] == 'g' || ext[3] == 'e'))
        {
            strcpy((char *)mimetype,(const char *)"image/jpeg");
            *tType = VS_OT_JPEG;
        }
        else if(ext[1] == 'p' && ext[2] == 'n' && ext[3] == 'g')
        {
            strcpy((char *)mimetype,(const char *)"image/png");
            *tType = VS_OT_PNG;
        }
        else if(ext[1] == 's' && ext[2] == 'w' && ext[3] == 'f')
        {
            strcpy((char *)mimetype,(const char *)"application/x-shockwave-flash");
            *tType = VS_OT_FLASH;
        }
        else if(ext[1] == 'x' && ext[2] == 'a' && ext[3] == 'p')
        {
            strcpy((char *)mimetype,(const char *)"application/x-silverlight");
            *tType = VS_OT_SILVERLIGHT;
        }
        else if(ext[1] == 'r' && ext[2] == 't' && ext[3] == 'f')
        {
            strcpy((char *)mimetype,(const char *)"test/rtf");
            *tType = VS_OT_RTF;
        }
        else if(ext[1] == 'p' && ext[2] == 's' && ext[3] == '\0')
        {
            strcpy((char *)mimetype,(const char *)"application/postscript");
            *tType = VS_OT_POSTSCRIPT;
        }
        else if(ext[1] == 'r' && ext[2] == 'a' && ext[3] == 'r')
        {
            strcpy((char *)mimetype,(const char *)"application/rar");
            *tType = VS_OT_RAR;
        }
        else if(ext[1] == 'j' && ext[2] == 's' && ext[3] == '\0')
        {
            strcpy((char *)mimetype,(const char *)"application/javascript");
            *tType = VS_OT_JSCRIPT;
        }
        else if(ext[1] == 'j' && ext[2] == 'a' && ext[3] == 'r')
        {
            strcpy((char *)mimetype,(const char *)"application/x-jar");
            *tType = VS_OT_JAR;
        }
        else if(ext[1] == 'c' && ext[2] == 'l' && ext[3] == 'a' && ext[4] == 's' && ext[5] == 's')
        {
            strcpy((char *)mimetype,(const char *)"application/x-java-class");
            *tType = VS_OT_JAVA;
        }
        else if(ext[1] == 'e' && ext[2] == 's' && ext[3] == '\0')
        {
            strcpy((char *)mimetype,(const char *)"application/ecmascript");
            *tType = VS_OT_EMCASCRIPT;
        }
        else if(ext[1] == 'a' && ext[2] == 'l' && ext[3] == 'f')
        {
            strcpy((char *)mimetype,(const char *)"application/x-alf");
            *tType = VS_OT_ALF;
        }
        else if(ext[1] == 'o' && ext[2] == 't' && ext[3] == 'f')
        {
            strcpy((char *)mimetype,(const char *)"application/x-otf");
            *tType = VS_OT_OTF;
        }
        else if(ext[1] == 's' && ext[2] == 'i' && ext[3] == 'm')
        {
            strcpy((char *)mimetype,(const char *)"application/x-sim");
            *tType = VS_OT_SIM;
        }
        else if(ext[1] == 'x' && ext[2] == 'l' && ext[3] == 's' && ext[4] == 'x')
        {
            strcpy((char *)mimetype,(const char *)"application/vnd.ms-excel");
            *tType = VS_OT_MSO;
        }
        else if(ext[1] == 'x' && ext[2] == 'l' && ext[3] == 's')
        {
            strcpy((char *)mimetype,(const char *)"application/vnd.ms-excel");
            *tType = VS_OT_MSO;
        }
        else if(ext[1] == 'x' && ext[2] == 'l' && ext[3] == 't')
        {
            strcpy((char *)mimetype,(const char *)"application/vnd.ms-excel");
            *tType = VS_OT_MSO;
        }
        else if(ext[1] == 'x' && ext[2] == 'l' && ext[3] == 'a')
        {
            strcpy((char *)mimetype,(const char *)"application/vnd.ms-excel");
            *tType = VS_OT_MSO;
        }
        else if(ext[1] == 'd' && ext[2] == 'o' && ext[3] == 'c' && ext[4] == 'x')
        {
            strcpy((char *)mimetype,(const char *)"application/msword");
            *tType = VS_OT_MSO;
        }
        else if(ext[1] == 'd' && ext[2] == 'o' && ext[3] == 't' && ext[4] == 'x')
        {
            strcpy((char *)mimetype,(const char *)"application/msword");
            *tType = VS_OT_MSO;
        }
        else if(ext[1] == 'd' && ext[2] == 'o' && ext[3] == 'c')
        {
            strcpy((char *)mimetype,(const char *)"application/msword");
            *tType = VS_OT_MSO;
        }
        else if(ext[1] == 'd' && ext[2] == 'o' && ext[3] == 't')
        {
            strcpy((char *)mimetype,(const char *)"application/msword");
            *tType = VS_OT_MSO;
        }
        else if(ext[1] == 'm' && ext[2] == 's' && ext[3] == 'g')
        {
            strcpy((char *)mimetype,(const char *)"application/vnd.ms-outlook");
            *tType = VS_OT_MSO;
        }
        else if(ext[1] == 'p' && ext[2] == 'p' && ext[3] == 't' && ext[4] == 'x')
        {
            strcpy((char *)mimetype,(const char *)"application/vnd.ms-powerpoint");
            *tType = VS_OT_MSO;
        }
        else if(ext[1] == 'p' && ext[2] == 'p' && ext[3] == 't')
        {
            strcpy((char *)mimetype,(const char *)"application/vnd.ms-powerpoint");
            *tType = VS_OT_MSO;
        }
        else if(ext[1] == 'p' && ext[2] == 'p' && ext[3] == 's')
        {
            strcpy((char *)mimetype,(const char *)"application/vnd.ms-powerpoint");
            *tType = VS_OT_MSO;
        }
        else if(ext[1] == 'p' && ext[2] == 'p' && ext[3] == 'a')
        {
            strcpy((char *)mimetype,(const char *)"application/vnd.ms-powerpoint");
            *tType = VS_OT_MSO;
        }
        else if(ext[1] == 'p' && ext[2] == 'o' && ext[3] == 't')
        {
            strcpy((char *)mimetype,(const char *)"application/vnd.ms-powerpoint");
            *tType = VS_OT_MSO;
        }
        else if(ext[1] == 'f' && ext[2] == 'l' && ext[3] == 'v')
        {
            strcpy((char *)mimetype,(const char *)"video/x-flv");
            *tType = VS_OT_FLASHVIDEO;
        }
        else if(ext[1] == 'k' && ext[2] == 'e' && ext[3] == 'p')
        {
            strcpy((char *)mimetype,(const char *)"application/x-kep");
            *tType = VS_OT_KEP;
        }
        else if(ext[1] == 'i' && ext[2] == 'n' && ext[3] == 'i')
        {
            strcpy((char *)mimetype,(const char *)"application/x-ini");
            *tType = VS_OT_INI;
        }
        else if(ext[1] == 's' && ext[2] == 'a' && ext[3] == 'p')
        {
            strcpy((char *)mimetype,(const char *)"application/x-sapshortcut");
            *tType = VS_OT_SAPSHORTCUT;
        }
        else if(ext[1] == 'o' && ext[2] == 'd')
        {
            *tType = VS_OT_MSO;
            if(ext[3] == 't')
               strcpy((char *)mimetype,(const char *)"application/vnd.oasis.opendocument.text");
            else if(ext[3] == 'b')
                strcpy((char *)mimetype,(const char *)"application/vnd.oasis.opendocument.database");
            else if(ext[3] == 'f')
                strcpy((char *)mimetype,(const char *)"application/vnd.oasis.opendocument.formula");
            else if(ext[3] == 'g')
                strcpy((char *)mimetype,(const char *)"application/vnd.oasis.opendocument.graphics-template");
            else if(ext[3] == 'm')
                strcpy((char *)mimetype,(const char *)"application/vnd.oasis.opendocument.text-master");
            else if(ext[3] == 'i')
                strcpy((char *)mimetype,(const char *)"application/vnd.oasis.opendocument.image");
            else if(ext[3] == 'c')
                strcpy((char *)mimetype,(const char *)"application/vnd.oasis.opendocument.chart");
            else if(ext[3] == 's')
                strcpy((char *)mimetype,(const char *)"application/vnd.oasis.opendocument.spreadsheet");
            else if(ext[3] == 'p')
                strcpy((char *)mimetype,(const char *)"application/vnd.oasis.opendocument.presentation");
            else {
                strcpy((char *)mimetype,(const char *)"unknown/unknown");
                *tType = VS_OT_UNKNOWN;
            }
        }
        else if(ext[1] == 'a' && ext[2] == 'r' && ext[3] == 'c' && ext[4] == 'h' && ext[5] == 'i' && ext[6] == 'v' && ext[7] == 'e')
        {
            strcpy((char *)mimetype,(const char *)"application/x-archive");
            *tType = VS_OT_ARCHIVE;
        }
        else
        {
            strcpy((char *)mimetype,(const char *)"unknown/unknown");
            *tType = VS_OT_UNKNOWN;
        }

    }
    return VSA_OK;
} /* getFileType */

VSA_RC getByteType(PByte pByte,
                   size_t lByte,
                   PChar fileName,
                   PChar fileExt,
                   PChar ext,
                   PChar mimetype,
                   size_t index,
                   int *ststatus,
                   Bool *intext,
                   VS_OBJECTTYPE_T *st_type,
                   VS_OBJECTTYPE_T *st_tEnd,
                   VS_OBJECTTYPE_T *inFileType,
                   VS_OBJECTTYPE_T *inObjectType)
{
    PByte       ptr             = NULL;
    VSA_RC      rc              = VSA_OK;
    Bool        text            = intext ? *intext : TRUE;
    VS_OBJECTTYPE_T tFileType   = inFileType ? *inFileType : VS_OT_UNKNOWN;
    VS_OBJECTTYPE_T tObjectType = inObjectType ? *inObjectType : VS_OT_UNKNOWN;
    size_t   i = 0;
    TYPE_STATUS status = ststatus ? (TYPE_STATUS)(*ststatus) : BEGIN;

    if(pByte == NULL || lByte == 0 || index >= lByte ) {
        CLEANUP(VSA_OK);
    }
    for(i = index; i < lByte; i++)
    {
        ptr = pByte + i;
        if(text == TRUE) {
            if(0 == isprint((int)*ptr)) {
                unsigned int n = (unsigned int)*ptr;
                if(n == '\n' || n == '\r' || n == '\t') continue;
                if((*st_type) == VS_OT_HTML || (*st_type) == VS_OT_XML || (*st_type) == VS_OT_XSL ||
                    tFileType == VS_OT_HTML || tFileType == VS_OT_XML || tFileType == VS_OT_XSL) {
                    text = isHTMLCharacter(n);
                }
                else {
                    setlocale(LC_ALL,"en_US.UTF-8");
                    if(0 == isprint((int)*ptr)) {
                        text = FALSE;
                    }
                    setlocale(LC_ALL,"");
                }
                if(i > 0 && text == FALSE && tFileType == VS_OT_UNKNOWN && (*st_type) == VS_OT_UNKNOWN) goto cleanup;
            }
        }
        switch(status)
        {
        case BEGIN:
            switch(*ptr)
            {
            case '%':
                if(lByte > 7 && 0 == memcmp(ptr,"%PDF-",5)) (*st_type) = VS_OT_PDF;
                if(lByte > 15 && 0 == memcmp(ptr,"%!PS-Adobe",10)) (*st_type) = VS_OT_POSTSCRIPT;
                break;
            case '\004':
                if(lByte > 16 && 0 == memcmp(ptr,"\004%!PS-Adobe",11)) (*st_type) = VS_OT_POSTSCRIPT;
                break;
            case '<':
                if(lByte > 32 && 0 == memcmp(ptr,"<?xml-stylesheet",16)) (*st_type) = VS_OT_XSL;
                else if(lByte > 10 && 0 == memcmp(ptr,"<?xml",5)) (*st_type) = VS_OT_XML;
                else if(lByte > 30 && 0 == memcmp(ptr,"<xsl:stylesheet",15)) (*st_type) = VS_OT_XSL;
                else if(lByte > 10 && 0 == memcmp(ptr,"<html",5)) (*st_type) = VS_OT_HTML;
                else if(lByte > 10 && 0 == memcmp(ptr,"<HTML",5)) (*st_type) = VS_OT_HTML;
                else (*st_type) = VS_OT_XHTML;
                status = SEARCH;
                break;
            case '\\':
                if(lByte > 6 && 0 == memcmp(ptr,"\\rtf",4)) { (*st_tEnd) = (*st_type) = VS_OT_RTF; CLEANUP(VSA_OK); }
                break;
            case 'P':
                if(lByte > 6 && 0 == memcmp(ptr,"PK\003\004",4))  (*st_type) = VS_OT_ZIP;
                else if(lByte > 5 && 0 == memcmp(ptr,"P\002\000",3)) { (*st_tEnd) = (*st_type) = VS_OT_KEP; CLEANUP(VSA_OK); }
                break;
            case 'R':
                if(lByte > 10 && 0 == memcmp(ptr,"Rar!",4)) { (*st_tEnd) = (*st_type) = VS_OT_RAR; CLEANUP(VSA_OK); }
                break;
            case 'C':
                if(lByte > 10 && 0 == memcmp(ptr,"CAR 2.0",7)) { (*st_tEnd) = (*st_type) = VS_OT_SAR; CLEANUP(VSA_OK); }
                if(lByte > 10 && 0 == memcmp(ptr,"CWS",3)) { (*st_tEnd) = (*st_type) = VS_OT_FLASH; CLEANUP(VSA_OK); }
                break;
            case 'F':
                if(lByte > 10 && 0 == memcmp(ptr,"FWS",3)) { (*st_tEnd) = (*st_type) = VS_OT_FLASH; CLEANUP(VSA_OK); }
                if(lByte > 10 && 0 == memcmp(ptr,"FLV",3)) { (*st_tEnd) = (*st_type) = VS_OT_FLASHVIDEO; CLEANUP(VSA_OK); }
                break;
            case '\x89':
                if(lByte > 5 && 0 == memcmp(ptr,"\x89PNG",4)) { (*st_tEnd) = (*st_type) = VS_OT_PNG; CLEANUP(VSA_OK); }
                break;
            case 'G':
                if(lByte > 5 && 0 == memcmp(ptr,"GIF8",4)) { (*st_tEnd) = (*st_type) = VS_OT_GIF;  }
                if(lByte > 5 && 0 == memcmp(ptr,"GIF",3)) { (*st_tEnd) = (*st_type) = VS_OT_IMAGE;  }
                break;
            case 'i':
                if(lByte > 5 && 0 == memcmp(ptr,"iTut",4)) { (*st_tEnd) = (*st_type) = VS_OT_SIM; CLEANUP(VSA_OK); }
                break;
            case '\377':
                if(lByte > 5 && 0 == memcmp(ptr,"\377\330\377\340",4)) { (*st_tEnd) = (*st_type) = VS_OT_JPEG; CLEANUP(VSA_OK); }
                if(lByte > 5 && 0 == memcmp(ptr,"\377\330\377\341",4)) { (*st_tEnd) = (*st_type) = VS_OT_JPEG; CLEANUP(VSA_OK); }
                if(lByte > 5 && 0 == memcmp(ptr,"\377\330\377\342",4)) { (*st_tEnd) = (*st_type) = VS_OT_JPEG; CLEANUP(VSA_OK); }
                if(lByte > 5 && 0 == memcmp(ptr,"\377\330\377\350",4)) { (*st_tEnd) = (*st_type) = VS_OT_JPEG; CLEANUP(VSA_OK); }
                if(lByte > 5 && 0 == memcmp(ptr,"\377\330\377\356",4)) { (*st_tEnd) = (*st_type) = VS_OT_JPEG; CLEANUP(VSA_OK); }
                if(lByte > 5 && 0 == memcmp(ptr,"\377\330",2)) { (*st_tEnd) = (*st_type) = VS_OT_IMAGE; CLEANUP(VSA_OK); }
                break;
            case '\xca':
                if(lByte > 5 && 0 == memcmp(ptr,"\xca\xfe\xba\xbe",4)) { (*st_tEnd) = (*st_type) = VS_OT_JAVA; CLEANUP(VSA_OK); }
                break;
            case '\xd0':
                if(lByte > 10 && 0 == memcmp(ptr,"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",8)) { (*st_tEnd) = (*st_type) = VS_OT_MSO; CLEANUP(VSA_OK); }
                break;
            case '\x10':
                if(lByte > 10 && 0 == memcmp(ptr,"\x10\x07\x00\x65\x00\x08\xEE\x01",8)) { (*st_tEnd) = (*st_type) = VS_OT_ARCHIVE; CLEANUP(VSA_OK); }
                break;
            default: break;
            }
            status = SEARCH;
            break;
        case SEARCH:
            switch(*ptr)
            {
            case '%':
                status = LOOKAHEAD;
                break;
            case '<':
                if((*st_type) != VS_OT_UNKNOWN) continue;
                if((lByte - i) > 32 && 0 == memcmp(ptr,"<?xml-stylesheet",16)) (*st_type) = VS_OT_XSL;
                else if((lByte - i) > 5 && 0 == memcmp(ptr,"<?xml",5)) (*st_type) = VS_OT_XML;
                else if((lByte - i) > 15 && 0 == memcmp(ptr,"<xsl:stylesheet",15)) (*st_type) = VS_OT_XSL;
                else if((*st_type) == VS_OT_XML && (lByte - i) > 5 && 0 == memcmp(ptr,"</xml>",6)) { (*st_tEnd) = VS_OT_XML; CLEANUP(VSA_OK); }
                else if((*st_type) == VS_OT_HTML && (lByte - i) > 5 && 0 == memcmp(ptr,"</html>",7)) { (*st_tEnd) = VS_OT_HTML; CLEANUP(VSA_OK); }
                else if((*st_type) == VS_OT_HTML && (lByte - i) > 5 && 0 == memcmp(ptr,"</HTML>",7)) { (*st_tEnd) = VS_OT_HTML; CLEANUP(VSA_OK); }
                else if((*st_type) == VS_OT_UNKNOWN && tFileType==VS_OT_TEXT && tObjectType==VS_OT_TEXT && text==TRUE) { (*st_type) = VS_OT_TEXT; }
                else (*st_type) = VS_OT_XHTML;
                break;
            case '\\':
                if((*st_type) != VS_OT_UNKNOWN) continue;
                if(lByte > 6 && 0 == memcmp(ptr,"\\rtf",4)) (*st_type) = VS_OT_RTF;
                break;
            case 'M':
                if((*st_type) == VS_OT_ZIP && (tFileType == VS_OT_JAR || tFileType == VS_OT_MSO)) {
                    if((lByte - i) > 10 && 0 == memcmp(ptr,"META-INF/",9)) { (*st_tEnd) = (*st_type) = VS_OT_JAR; CLEANUP(VSA_OK); }
                    if((lByte - i) > 12 && 0 == memcmp(ptr,"MANIFEST.MF",11)) { (*st_tEnd) = (*st_type) = VS_OT_JAR; CLEANUP(VSA_OK); }
                    if((lByte - i) > 7 && 0 == memcmp(ptr,".class",6)) { (*st_tEnd) = (*st_type) = VS_OT_JAR; CLEANUP(VSA_OK); }
                } else if ((*st_type) >= VS_OT_IMAGE && (*st_type) < VS_OT_VIDEO) {
                    if((lByte - i) > 10 && 0 == memcmp(ptr,"META-INF/",9)) { (*st_tEnd) = VS_OT_JAR;  }
                    if((lByte - i) > 12 && 0 == memcmp(ptr,"MANIFEST.MF",11)) { (*st_tEnd) = VS_OT_JAR;  }
                }
                break;
            case 'm':
                if((*st_type) == VS_OT_ZIP) {
                    if((lByte - i) > 25 && 0 == memcmp(ptr,"mimetypeapplication/vnd",23)) { (*st_type) = VS_OT_MSO; i=i+18; status = LOOKAHEAD; }
                }
                break;
            case 'A':
                if((*st_type) == VS_OT_ZIP) {
                    if((lByte - i) > 17 && 0 == memcmp(ptr,"AppManifest.xaml",16)) { (*st_tEnd) = (*st_type) = VS_OT_SILVERLIGHT; CLEANUP(VSA_OK); }
                }
                break;
            case 'c':
                if((*st_type) == VS_OT_ZIP) {
                    if((lByte - i) > 6 && 0 == memcmp(ptr - 1,".class",6)) { (*st_tEnd) = (*st_type) = VS_OT_JAR; CLEANUP(VSA_OK); }
                }
                break;
            case '[':
                if((*st_type) == VS_OT_ZIP) {
                    if((lByte - i) > 20 && 0 == memcmp(ptr,"[Content_Types].xml",19)) { (*st_tEnd) = (*st_type) = VS_OT_MSO; CLEANUP(VSA_OK); }
                }
                break;
            case '?':
                if((*st_type) == VS_OT_XML) {
                    if((lByte - i) > 30 && 0 == memcmp(ptr,"?xml-stylesheet",15)) { (*st_tEnd) = (*st_type) = VS_OT_XSL; CLEANUP(VSA_OK); }
                }
                break;
            case 'P':
                if((*st_type) == VS_OT_ZIP && (tFileType == VS_OT_JAR || tFileType == VS_OT_MSO)) {
                    if((lByte - i) > 6 && 0 == memcmp(ptr,"PK\005\006",4)) { (*st_tEnd) = (*st_type); status = ENDSIGNATURE; }

                } else if ((*st_type) >= VS_OT_IMAGE && (*st_type) < VS_OT_VIDEO) {
                    if((lByte - i) > 6 && 0 == memcmp(ptr,"PK\005\006",4)) {
                        if((*st_tEnd)==VS_OT_JAR) { (*st_type) = (*st_tEnd) = VS_OT_JAR; }
                        else { (*st_type) = (*st_tEnd) = VS_OT_ZIP; }
                        status = ENDSIGNATURE;
                    }
                } else if((*st_type) == VS_OT_MSO && tFileType == VS_OT_MSO) {
                    if((lByte - i) > 6 && 0 == memcmp(ptr,"PK\005\006",4)) { status = ENDSIGNATURE; }
                }
                break;
            default: break;
            }
            break;
        case LOOKAHEAD:
            switch(*ptr)
            {
            case '%':
                if(((*st_type) == VS_OT_POSTSCRIPT || (*st_type) == VS_OT_PDF)
                    && (lByte - i) > 3
                    && 0 == memcmp(ptr,"%EOF",4))
                {
                    (*st_tEnd) = (*st_type);
                }
                break;
            case '\x2f':
                if((*st_type) == VS_OT_MSO) {
                    if((lByte - i) > 25 && 0 == memcmp(ptr,"/vnd.o",6)) { status = LOOKAHEAD; }
                }
                break;
            default: status = SEARCH; break;
            }
            break;
       case ENDSIGNATURE:
            switch(*ptr)
            {
            case '\000':
                if((*st_type) == VS_OT_ZIP || (*st_type) == VS_OT_JAR || (*st_type) == VS_OT_MSO || (*st_tEnd) == VS_OT_JAR || (*st_tEnd) == VS_OT_ZIP || tFileType == VS_OT_JAR || tFileType == VS_OT_MSO) {
                    if((lByte - i) == 2 && 0 == memcmp(ptr,"\000\000",2)) { (*st_tEnd) = (*st_type); CLEANUP(VSA_OK); }
                }
                break;
            default: break;
            }
            break;
        default:
            status = UNKNOWN;
            break;
        }
    }
cleanup:
    if(rc != VSA_OK) {
        strcpy((char *)mimetype,(const char *)"unknown/unknown");
        strcpy((char *)ext,".*");
        tObjectType = VS_OT_UNKNOWN;
        rc = VSA_E_NOT_SCANNED;
    }
    else {
        if((*st_tEnd) == VS_OT_UNKNOWN && text == TRUE) {
            if((*st_type) == VS_OT_UNKNOWN && tFileType >= VS_OT_TEXT && tFileType < VS_OT_IMAGE) {
                (*st_tEnd) = (*st_type) = tFileType;
            }
            else if((*st_type) >= VS_OT_TEXT && (*st_type) < VS_OT_IMAGE) {
                if((*st_type) != VS_OT_UNKNOWN)
                    (*st_tEnd) = (*st_type); /* in case of textual objects the extension can be overtaken */
                else
                    (*st_tEnd) = (*st_type) = tFileType;
            }
        }
        if((*st_type) != (*st_tEnd)) {
            if(text == TRUE) {
                if((*st_type) > VS_OT_UNKNOWN && (*st_type) < VS_OT_IMAGE && (*st_tEnd) > VS_OT_UNKNOWN && (*st_tEnd) < VS_OT_IMAGE)
                    (*st_type) = tFileType;
                else
                    (*st_type) = VS_OT_UNKNOWN;
            }
            else {
                if((*st_type) == VS_OT_ZIP && (*st_tEnd) == VS_OT_UNKNOWN)
                    (*st_type) = VS_OT_ZIP;
                else if((*st_type) == VS_OT_PDF && (*st_tEnd) == VS_OT_UNKNOWN)
                    (*st_type) = VS_OT_PDF;
                else if((*st_type) == VS_OT_XHTML && tFileType == VS_OT_TEXT)
                    (*st_type) = VS_OT_TEXT;
                else if((*st_type) == VS_OT_TEXT && tFileType == VS_OT_TEXT)
                    (*st_type) = VS_OT_TEXT;
                else if((*st_type) == VS_OT_XHTML && tFileType == VS_OT_HTML)
                    (*st_type) = VS_OT_HTML;
                else if((*st_type) == VS_OT_HTML && tFileType == VS_OT_HTML)
                    (*st_type) = VS_OT_HTML;
                else
                    (*st_type) = VS_OT_BINARY;
            }
        } else {
            if((*st_tEnd) == VS_OT_UNKNOWN && (*st_type) == VS_OT_UNKNOWN && tFileType == VS_OT_TEXT) {
                (*st_tEnd) = (*st_type) = tFileType;
            }
        }
        tObjectType = (*st_type);
        switch((*st_type)) {
        case VS_OT_BINARY:
            setByteType(fileName,fileExt,ext,mimetype,(PChar)".bin",(PChar)"application/octet-stream",pByte,lByte);
            break;
        case VS_OT_PDF:
            strcpy((char *)mimetype,(const char *)"application/pdf");
            strcpy((char *)ext,(const char *)".pdf");
            break;
        case VS_OT_POSTSCRIPT:
            strcpy((char *)mimetype,(const char *)"application/postscript");
            strcpy((char *)ext,(const char *)".ps");
            break;
        case VS_OT_SAR:
            strcpy((char *)mimetype,(const char *)"application/vnd.sar");
            strcpy((char *)ext,(const char *)".sar");
            break;
        case VS_OT_RAR:
            strcpy((char *)mimetype,(const char *)"application/rar");
            strcpy((char *)ext,(const char *)".rar");
            break;
        case VS_OT_ZIP:
        case VS_OT_BZIP2:
        case VS_OT_GZIP:
            strcpy((char *)mimetype,(const char *)"application/zip");
            strcpy((char *)ext,(const char *)".zip");
            break;
        case VS_OT_XHTML:
            strcpy((char *)mimetype,(const char *)"application/xhtml+xml");
            strcpy((char *)ext,(const char *)".xhtml");
            if(tFileType == VS_OT_HTML)
                tFileType = VS_OT_XHTML;
            else if(tFileType == VS_OT_UNKNOWN)
                tFileType = (*st_type);
            break;
        case VS_OT_XSL:
            strcpy((char *)mimetype,(const char *)"application/xsl");
            strcpy((char *)ext,(const char *)".xsl");
            if(tFileType == VS_OT_UNKNOWN)
                tFileType = (*st_type);
            break;
        case VS_OT_XML:
            strcpy((char *)mimetype,(const char *)"application/xml");
            strcpy((char *)ext,(const char *)".xml");
            if(tFileType == VS_OT_UNKNOWN)
                tFileType = (*st_type);
            break;
        case VS_OT_HTML:
            strcpy((char *)mimetype,(const char *)"text/html");
            strcpy((char *)ext,(const char *)".html");
            if(tFileType == VS_OT_XHTML || tFileType == VS_OT_HTML) {
                tFileType = VS_OT_HTML;
                (*st_tEnd) = VS_OT_HTML;
            } else if(tFileType == VS_OT_UNKNOWN) {
                tFileType = (*st_type);
            }
            break;
        case VS_OT_TEXT:
            strcpy((char *)mimetype,(const char *)"text/plain");
            strcpy((char *)ext,(const char *)".txt");
            break;
        case VS_OT_FLASH:
            strcpy((char *)mimetype,(const char *)"application/x-shockwave-flash");
            strcpy((char *)ext,(const char *)".swf");
            break;
        case VS_OT_FLASHVIDEO:
            strcpy((char *)mimetype,(const char *)"video/x-flv");
            strcpy((char *)ext,(const char *)".flv");
            break;
        case VS_OT_IMAGE:
            strcpy((char *)mimetype,"image/*");
            strcpy((char *)ext,".jpg");
            break;
        case VS_OT_GIF:
            strcpy((char *)mimetype,"image/gif");
            strcpy((char *)ext,".gif");
            break;
        case VS_OT_PNG:
            strcpy((char *)mimetype,(const char *)"image/png");
            strcpy((char *)ext,(const char *)".png");
            break;
        case VS_OT_JPEG:
            strcpy((char *)mimetype,(const char *)"image/jpeg");
            strcpy((char *)ext,(const char *)".jpg");
            break;
        case VS_OT_SILVERLIGHT:
            strcpy((char *)mimetype,(const char *)"application/x-silverlight");
            strcpy((char *)ext,(const char *)".xap");
            break;
        case VS_OT_JSCRIPT:
            strcpy((char *)mimetype,(const char *)"application/javascript");
            strcpy((char *)ext,(const char *)".js");
            break;
        case VS_OT_EMCASCRIPT:
            strcpy((char *)mimetype,(const char *)"application/ecmascript");
            strcpy((char *)ext,(const char *)".es");
            break;
        case VS_OT_JAR:
            strcpy((char *)mimetype,(const char *)"application/x-jar");
            strcpy((char *)ext,(const char *)".jar");
            break;
        case VS_OT_JAVA:
            strcpy((char *)mimetype,(const char *)"application/x-java-class");
            strcpy((char *)ext,(const char *)".class");
            break;
        case VS_OT_ALF:
            strcpy((char *)mimetype,(const char *)"application/x-alf");
            strcpy((char *)ext,(const char *)".alf");
            break;
        case VS_OT_OTF:
            strcpy((char *)mimetype,(const char *)"application/x-otf");
            strcpy((char *)ext,(const char *)".oft");
            break;
        case VS_OT_KEP:
            strcpy((char *)mimetype,(const char *)"application/x-kep");
            strcpy((char *)ext,(const char *)".kep");
            break;
        case VS_OT_SIM:
            strcpy((char *)mimetype,(const char *)"application/x-sim");
            strcpy((char *)ext,(const char *)".sim");
            break;
        case VS_OT_SAPSHORTCUT:
            strcpy((char *)mimetype,(const char *)"application/x-sapshortcut");
            strcpy((char *)ext,(const char *)".sap");
            break;
        case VS_OT_INI:
            strcpy((char *)mimetype,(const char *)"text/x-ini");
            strcpy((char *)ext,(const char *)".ini");
            break;
        case VS_OT_MSO:
            if(mimetype != NULL && *mimetype != 'a')
               strcpy((char *)mimetype,(const char *)"application/office");
            if(fileExt != NULL && *fileExt == '.') {
               strcpy((char *)ext,(const char *)fileExt);
            } else {
                if(ext != NULL && *ext != '.')
                   strcpy((char *)ext,(const char *)".doc");
            }
            break;
        case VS_OT_ARCHIVE:
            strcpy((char *)mimetype,(const char *)"application/x-archive");
            strcpy((char *)ext,(const char *)".arc");
            break;
        default:
            setByteType(fileName,fileExt,ext,mimetype,(PChar)".*",(PChar)"unknown/unknown",pByte,lByte);
            tObjectType = VS_OT_UNKNOWN;
            break;
        }
    }
    if(inFileType) *inFileType = tFileType;
    if(inObjectType) *inObjectType = tObjectType;
    if(ststatus) *ststatus = (int)status;
    if(intext) *intext = text;
    return rc;
} /* getByteType */

static void setByteType(PChar fileName,
                        PChar fileExt,
                        PChar ext,
                        PChar mimetype,
                        PChar defaultExt,
                        PChar defaultMimeType,
                        PByte pBuffer,
                        size_t lBuffer)
{
    if(fileExt != NULL && fileExt[0] != 0 && fileExt[1] != 0) {
        strcpy((char *)ext,(const char *)fileExt);
    } else {
        strcpy((char *)ext,(const char *)defaultExt);
    }
    if(fileName != NULL) {
        PChar pMTyp = vsaGetFileMimeType(fileName);
        if(pMTyp) {
            strcpy((char *)mimetype,(const char *)pMTyp);
            free(pMTyp);
        } else {
            PChar pBTyp = vsaGetByteMimeType((void*)pBuffer,(size_t)lBuffer);
            if(pBTyp) {
                strcpy((char *)mimetype,(const char *)pBTyp);
                free(pBTyp);
            } else {
                strcpy((char *)mimetype,(const char *)defaultMimeType);
            }
        }
    } else {
        strcpy((char *)mimetype,(const char *)defaultMimeType);
    }
} /* setByteType */

static PChar vsaGetByteMimeType(void *pBuffer, size_t lBuffer)
{
    VSA_RC rc = VSA_OK;
    PChar pMimeType = NULL;
    size_t len = 0;
#ifdef _WIN32
    return NULL;
#else
    const char *pMTyp = 0;
    if(pMagicFPtr && pMagicFPtr->bLoaded) {
       magic_t lMagic = pMagicFPtr->fp_magic_open(0x000200 | 0x000010 | 0x000400);
       pMagicFPtr->fp_magic_load(lMagic,NULL);
       pMTyp = pMagicFPtr->fp_magic_buffer(lMagic, pBuffer, lBuffer);
       if(pMTyp != 0) {
          const char *p = strrchr((const char*)pMTyp,(int)';');
          if(p == NULL) /* no extras */ {
             SETSTRING(pMimeType,pMTyp);
          } else {
             size_t magLen = (p - pMTyp);
             if(magLen > 0 && magLen < MAX_PATH_LN) {
                SETSTRINGLN(pMimeType,pMTyp,magLen);
             } else {
                SETSTRING(pMimeType,pMTyp);
             }
          }
       }
       pMagicFPtr->fp_magic_close(lMagic);
    }
    if(pMTyp == 0) return NULL;
cleanup:
    if(rc != VSA_OK) return NULL;
    return pMimeType;
#endif
}

static Bool isHTMLCharacter(int c)
{

    switch(c) {
    case '\x82':
    case '\x84':
    case '\x86':
    case '\x87':
    case '\x8b':
    case '\x91':
    case '\x92':
    case '\x94':
    case '\x95':
    case '\x96':
    case '\x97':
    case '\x99':
    case '\x9b':
    case '\xa0':
    case '\xa1':
    case '\xa6':
    case '\xa9':
    case '\xaa':
    case '\xab':
    case '\xac':
    case '\xad':
    case '\xae':
    case '\xa7':
    case '\xb0':
    case '\xb2':
    case '\xb3':
    case '\xb5':
    case '\xb6':
    case '\xb7':
    case '\xb9':
    case '\xba':
    case '\xbb':
    case '\xbf':
    case '\xc0':
    case '\xe0':
    case '\xc2':
    case '\xe2':
    case '\xc6':
    case '\xe6':
    case '\xc8':
    case '\xe8':
    case '\xc9':
    case '\xe9':
    case '\xca':
    case '\xea':
    case '\xcb':
    case '\xeb':
    case '\xce':
    case '\xcc':
    case '\xcf':
    case '\xef':
    case '\xd4':
    case '\xf4':
    case '\xd9':
    case '\xf9':
    case '\xdb':
    case '\xfb':
    case '\xdc':
    case '\xfc':
    case '\x80':
        /*case '\u20a3': */
        return TRUE;
    default: break;
    }
    return FALSE;
} /* isHTMLCharacter */

static char* memstr(char* input,const unsigned char* search,int len_input,int len_search)
{
    int i;
    for(i = 0; (memcmp(input,search,len_search)) && (i != len_input - len_search); input++,i++)
        ;
    return (i == len_input - len_search) ? 0 : input;
} /* memstr */

static void * memstr2(const char *l,size_t l_len,const char *s,size_t s_len)
{
    char *cur = 0,*last = 0;
    const char *cl = (const char *)l;
    const char *cs = (const char *)s;

    if(l_len == 0 || s_len == 0)
        return NULL;

    if(l_len < s_len)
        return NULL;

    if(s_len == 1)
        return memchr(l,(int)*cs,l_len);

    last = (char *)cl + l_len - s_len;

    for(cur = (char *)cl; cur <= last; cur++) {
        if(cur[0] == cs[0] && memcmp(cur,cs,s_len) == 0) {
            return cur;
        }
    }
    return NULL;
}
VSA_RC check4ActiveContent(
    PByte           pObject,
    size_t          lObjectSize,
    VS_OBJECTTYPE_T tObjectType)
{
    char  *p = NULL;
    char  *str = (char*)pObject;
    size_t snifflen = lObjectSize > 1024 ? 1024 : lObjectSize;

    if(pObject == NULL) return VSA_OK;

    if(tObjectType > VS_OT_UNKNOWN && tObjectType < VS_OT_IMAGE)
    {
        p = memstr2(str,lObjectSize,(const char*)"<script",7);
        if(p == NULL)
            p = memstr2(str,lObjectSize,(const char*)"<applet",7);
        if(p == NULL)
            p = memstr2(str,lObjectSize,(const char*)"<object",7);
        if(p == NULL)
            p = memstr2(str,lObjectSize,(const char*)"<embed",6);
        if(p == NULL)
            p = memstr2(str,lObjectSize,(const char*)"PHNjcmlwdD",10);
        if(p == NULL)
            p = memstr2(str,lObjectSize,(const char*)"javascript:",11);
        if(tObjectType == VS_OT_HTML || tObjectType == VS_OT_XHTML || tObjectType == VS_OT_XSL)
        {
            if(p == NULL)
                p = memstr2(str,lObjectSize,(const char*)"onclick=\"",9);
            if(p == NULL)
                p = memstr2(str,lObjectSize,(const char*)"ondblclick=\"",12);
            if(p == NULL)
                p = memstr2(str,lObjectSize,(const char*)"onkeydown=\"",11);
            if(p == NULL)
                p = memstr2(str,lObjectSize,(const char*)"onkeyup=\"",9);
            if(p == NULL)
                p = memstr2(str,lObjectSize,(const char*)"onmouseup=\"",11);
            if(p == NULL)
                p = memstr2(str,lObjectSize,(const char*)"onmouseover=\"",13);
            if(p == NULL)
                p = memstr2(str,lObjectSize,(const char*)"onmousemove=\"",13);
            if(p == NULL)
                p = memstr2(str,lObjectSize,(const char*)"onmouseout=\"",12);
            if(p == NULL)
                p = memstr2(str,lObjectSize,(const char*)"onkeypress=\"",12);
            if(p == NULL)
                p = memstr2(str,lObjectSize,(const char*)"onload=\"",8);
            if(p == NULL)
                p = memstr2(str,lObjectSize,(const char*)"onunload=\"",10);
            if(tObjectType == VS_OT_XSL)
            {
                if(p == NULL)
                    p = memstr2(str,lObjectSize,(const char*)"<xsl:attribute name=\"onload\">",29);
                if(p == NULL)
                    p = memstr2(str,lObjectSize,(const char*)"<xsl:attribute name=\"onunload\">",31);
            }
        }
    }
    else if(tObjectType == VS_OT_PDF)
    {
        p = memstr2(str,lObjectSize,(const char*)"/JS",3);
        if(p == NULL)
            p = memstr2(str,lObjectSize,(const char*)"/OpenAction",11);
    }
    else if(tObjectType == VS_OT_MSO)
    {
        p = memstr(str,(const unsigned char*)".class",(int)lObjectSize,6);
        if(p == NULL)
            p = memstr(str,(const unsigned char*)"vbaProject.bin",(int)lObjectSize,14);
    }
    else
    {
        p = memstr2(str,snifflen,(const char*)"<script",7);
        if(p == NULL)
            p = memstr2(str,snifflen,(const char*)"<applet",7);
        if(p == NULL)
            p = memstr2(str,snifflen,(const char*)"<object",7);
        if(p == NULL)
            p = memstr2(str,snifflen,(const char*)"<embed",6);
    }
    if(p != NULL)
    {
        return VSA_E_ACTIVECONTENT_FOUND;
    }
    else
    {
        return VSA_OK;
    }
} /* check4ActiveContent */

VSA_RC checkContentType(
    PChar           pExtension,
    PChar           pMimeType,
    PChar           pszScanMimeTypes,
    PChar           pszBlockMimeTypes,
    PChar           pszScanExtensions,
    PChar           pszBlockExtensions,
    PChar           errname,
    PChar           errfreename
    )
{
    char   *p = NULL;
    VSA_RC  rc = VSA_OK;
    char   *str = NULL;

    if(pszScanMimeTypes != NULL)
    {
        str = (char*)pszScanMimeTypes;
        p = strstr(str,(const char*)pMimeType);
        if(p == NULL)
        {
            sprintf((char*)errname,"MIME type %.100s is not allowed (whitelist %.850s)",pMimeType,(const char*)pszScanMimeTypes);
            errfreename = (PChar)"Check SCANMIMETYPES parameter";
            CLEANUP(VSA_E_BLOCKED_BY_POLICY);
        }
    }
    if(pszBlockMimeTypes != NULL)
    {
        str = (char*)pszBlockMimeTypes;
        p = strstr(str,(const char*)pMimeType);
        if(p != NULL)
        {
            sprintf((char*)errname,"MIME type %.100s is not allowed (blacklist %.850s)",pMimeType,(const char*)pszBlockMimeTypes);
            errfreename = (PChar)"Check BLOCKMIMETYPES parameter";
            CLEANUP(VSA_E_BLOCKED_BY_POLICY);
        }
    }
    if(pszScanExtensions != NULL)
    {
        str = (char*)pszScanExtensions;
        p = strstr(str,(const char*)pExtension);
        if(p == NULL)
        {
            sprintf((char*)errname,"File extension %.100s is not allowed (whitelist %.850s)",pExtension,(const char*)pszScanExtensions);
            errfreename = (PChar)"Check SCANEXTENSIONS parameter";
            CLEANUP(VSA_E_BLOCKED_BY_POLICY);
        }
    }
    if(pszBlockExtensions != NULL)
    {
        str = (char*)pszBlockExtensions;
        p = strstr(str,(const char*)pExtension);
        if(p != NULL)
        {
            sprintf((char*)errname,"File extension %.100s is not allowed (blacklist %.850s)",pExtension,(const char*)pszBlockExtensions);
            errfreename = (PChar)"Check BLOCKEXTENSIONS parameter";
            CLEANUP(VSA_E_BLOCKED_BY_POLICY);
        }
    }
cleanup:
    if(rc){
        rc = VSA_E_BLOCKED_BY_POLICY;
    }
    return rc;
} /* checkContentType */

PChar getCleanFilePatch(PChar orgFileName, size_t maxlen, PChar resultBuffer)
{
    PChar      pTmp;
    size_t     index = 0;
    for (pTmp = orgFileName; *pTmp && index < maxlen; ++pTmp)
    {
        if (('\\' == *pTmp) || ('/' == *pTmp)) {
            resultBuffer[index++] = '_';
        }
        else {
            resultBuffer[index++] = *pTmp;
        }
    }
    resultBuffer[index] = 0;
    return resultBuffer;
} /* getCleanFilePatch */

