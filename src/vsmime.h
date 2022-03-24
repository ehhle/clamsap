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

#ifndef VSMIME_H
#define VSMIME_H

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

#include "vsaxxtyp.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct magic_s;
typedef struct magic_s * magic_t;
typedef magic_t      (FN_MAGIC_OPEN)(int flags);
typedef void         (FN_MAGIC_CLOSE)(magic_t cookie);
typedef int          (FN_MAGIC_LOAD)(magic_t cookie,const char *magicfile);
typedef const char * (FN_MAGIC_BUFFER)(magic_t cookie,const void *buffer,size_t length);
typedef const char * (FN_MAGIC_FILE)(magic_t cookie,const char *filename);

typedef void     *DLL_MAGIC_HDL;
typedef struct {
    /* function pointers for clamav functions in libmagic library */
    FN_MAGIC_OPEN           *fp_magic_open;
    FN_MAGIC_CLOSE          *fp_magic_close;
    FN_MAGIC_LOAD           *fp_magic_load;
    FN_MAGIC_BUFFER         *fp_magic_buffer;
    FN_MAGIC_FILE           *fp_magic_file;
    /* handle */
    char                     bLoaded;
    DLL_MAGIC_HDL            dll_hdl;
} magic_function_pointers;

struct magic_function_s {
    const char *  function_name;
    int           function_index;
};

typedef int (APIENTRY DLL_MAGIC_CALL)(void);
typedef DLL_MAGIC_CALL *DLL_MAGIC_ADR;

#define DLL_MAGIC_DEFINE(x)       {  # x, DLL_FPTR_MAGIC_OFFSET(x) }
#define MAGIC_FIRST_FUNC          fp_magic_open
#define DLL_FPTR_MAGIC_OFFSET(x)  ((offsetof(magic_function_pointers,fp_ ## x) - offsetof(magic_function_pointers,MAGIC_FIRST_FUNC)) / sizeof(DLL_MAGIC_CALL *))
#define EXT_LN                  10
#define MIME_LN                 255

/*--------------------------------------------------------------------*/
/* helper defines                                                     */
/*--------------------------------------------------------------------*/
#define SETERRORSTRING( buf, txt )                                      \
{   if (txt != NULL && (len=strlen((const char*)txt)) > (size_t)0)      \
    {   buf = (PChar)malloc(len+1);                                     \
    if (buf == NULL)                                                    \
        CLEANUP(VSA_E_NO_SPACE);                                        \
    /* CCQ_OFF */ memcpy(buf,txt,len); /*CCQ_ON */                      \
    buf[len] = 0; } /* ensure zero termination */                       \
        else                                                            \
        buf = NULL;                                                     \
}

#define SETSTRING( buf, txt )                                           \
{   if (txt != NULL && (len=strlen((const char*)txt)) > (size_t)0)      \
    {   buf = (PChar)malloc(len+1);                                     \
    if (buf == NULL)                                                    \
        CLEANUP(VSA_E_NO_SPACE);                                        \
    /* CCQ_OFF */ memcpy(buf,txt,len); /*CCQ_ON */                      \
    buf[len] = 0; } /* ensure zero termination */                       \
        else                                                            \
        buf = NULL;                                                     \
}

#define SETSTRINGLN( buf, txt , len)                                    \
{   if (txt != NULL && (len) > (size_t)0)                               \
    {   buf = (PChar)malloc(len+1);                                     \
    if (buf == NULL)                                                    \
        CLEANUP(VSA_E_NO_SPACE);                                        \
    /* CCQ_OFF */ memcpy(buf,txt,len); /*CCQ_ON */                      \
    buf[len] = 0; } /* ensure zero termination */                       \
        else                                                            \
        buf = NULL;                                                     \
}

#define FCLOSE_SAFE( __FP )                                             \
    if (__FP != NULL)                                                   \
    {                                                                   \
        fclose(__FP);                                                   \
        __FP = NULL;                                                    \
    }
/*--------------------------------------------------------------------*/
/* helper functions                                                   */
/*--------------------------------------------------------------------*/
int vsaLoadMagicLibrary(PPChar ppszErrorText);
void vsaCloseMagicLibrary(void);
PChar vsaGetFileMimeType(PChar pszFileName);
VSA_RC getFileType(PChar,PChar,PChar,
                   VS_OBJECTTYPE_T *);
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
                   VS_OBJECTTYPE_T *inObjectType);

VSA_RC check4ActiveContent(
    PByte           pObject,
    size_t          lObjectSize,
    VS_OBJECTTYPE_T tObjectType,
    Bool            bPdfAllowOpenAction);

VSA_RC checkContentType(
    PChar           pExtension,
    PChar           pMimeType,
    PChar           pszScanMimeTypes,
    PChar           pszBlockMimeTypes,
    PChar           pszScanExtensions,
    PChar           pszBlockExtensions,
    PChar           errname,
    PChar           errfreename
    );

VSA_RC addContentInfo(UInt              uiJobID,
    PChar             pszObjectName,
    size_t            lObjectSize,
    VS_OBJECTTYPE_T   tContentType,
    PChar             pszExtension,
    PChar             pszContentType,
    PChar             pszCharSet,
    UInt              lContent,
    PPVSA_CONTENTINFO pp_content);

VSA_RC addScanError(UInt            uiJobID,
    PChar           pszObjectName,
    size_t          lObjectSize,
    Int             iErrorRC,
    PChar           pszErrorText,
    UInt            lError,
    PPVSA_SCANERROR pp_scanerror);

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
    PPVSA_VIRUSINFO pp_virusinfo);

PChar getCleanFilePatch(PChar orgFileName, size_t maxlen, PChar resultBuffer);
#ifdef __cplusplus
}
#endif

#endif /* VSMIME_H */
