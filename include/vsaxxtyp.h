/*****************************************************************************/
/*
 *  (C) Copyright SAP AG, Walldorf 2015, All Rights reserved
 *
 * SAP AG DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL SAP AG BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 */

/*include----------------------------------------------------------------------
 * @doc   EXTERNAL   VSA
 *
 * vsaxxtyp.h:  vsa = Virus Scan Adapter
 * ==========   xx  = OS-independent code
 *              typ = Type declarations for the adapter
 *
 *
 *  Author:    Markus Strehle  (SAP AG) (mailto:markus.strehle@sap.com)
 *  Reviewer:  SAP Security Response Team (mailto:secure@sap.com)
 *  Version:   2.03
 *
 *  Description:
 * 
 *    @module  Virus Scan Adapter |
 *    This module contains the type declarations for an adapter to
 *    an external scan engine. The adapter - known as the virus scan
 *    adapter (VSA) - is designed as shared library.
 *    The data types described here are defined to have a common interface
 *    to allow this module to be used outside of SAP.
 *
 *    The SAP virus scan interface (VSI) should provide a vendor-
 *    independent interface outside of SAP and a common interface
 *    inside of SAP for internal use. 
 *    An external virus scan adapter must at least provide the filling of 
 *    the structure <t VSA_CONFIG>. The parameters can then be set by
 *    calling the functions "<f VsaInit>" and "<f VsaScan>".
 *
 *    Version:   2.03
 *
 *    Version information in source control:<nl> 
 *    $Id: //bas/CGK/src/include/vsaxxtyp.h#19 $ $Date: 2015/03/03 $
 *
 *    @group
 *    Functions for the Virus Scan Adapter 
 *    @flag <f VsaStartup> |
 *          This function will be called first after loading the shared library.
 *          All global initialization should be done here, such as
 *          WSAStartup(), CoInitialize(), ThreadLibraryinitialization()
 *    @flag <f VsaGetConfig> |
 *          The VSA has to fill the VSA_CONFIG structure with all
 *          provided features, parameters and flags.
 *          A vendor of the VSA can also set default values for each
 *          initial and option parameter.
 *    @flag <f VsaInit> |
 *          Depending which thread model the adapter provides
 *          (STA or MTA), this function will be called once or several 
 *          times for each scan instance.
 *          The VSA initializes itself (or the connected scan engine)
 *          and reads all status information (version,date) about 
 *          the anti-virus engine and the drivers (of the AV engine).
 *    @flag <f VsaScan> |
 *          Performs the scan and clean job! 
 *          <nl>-> If the engine wants to notify the caller, the adapter
 *             can pass this information and send it to the callback
 *             function. Here the user can handle these messages like
 *             events (event handling). 
 *          <nl>-> If the caller wants to provide all I/O operations, then
 *             an extra callback can be installed and the scan action 
 *             'CLIENTIO' must be set.
 *    @flag <f VsaReleaseScan> |
 *          Releases the reserved data structure <t VSA_SCANINFO>.
 *          This function only has to be called if the scan
 *          function <f VsaScan> should return that information.
 *    @flag <f VsaEnd> |
 *          Depending which thread model the adapter provides
 *          (STA or MTA), this function will be called once or more for
 *          each instance.
 *          Releases all used resources and shuts the engine down
 *    @flag <f VsaCleanup> |
 *          Called as last function before unloading the adapter 
 *          Cleanup all your global reserved data here, such as
 *          WSACleanup, CoUninitialize, ExitThread 
 *          Shuts the adapter down!
 *      
 *    @end
 *  Modified:
 *    July 2004
 *          <nl>Redesigned the data types to be compatible with JAVA primitive
 *          types.
 *          <nl>Provide an external I/O interface to enable stream scanning.
 *
 *    June 2006
 *          <nl>Defined _USE_32BIT_TIME_T for NT based 32-bit build to use
 *          always time_t as 32-bit type even on Visual Studio 2005 builds.
 *
 *    Aug 2007
 *          <nl>Updated <t VS_ADAPTER_T>. Run test to ensure compatibility
 *          to SAP VSILIB version 1.70.
 *
 *    Oct 2011
 *          <nl>Enhancement for content filtering in combination with AV scan.
 *
 *    June 2012
 *          <nl>New parameters for update.
 *
 *    Dec 2012
 *          <nl>Definition for NW-VSI 2.00
 *
 *  Remarks:
 *    The adapter interface has to use UTF8 (unsigned char) charset as "Char"! 
 *    Please remark this note and provide all necessary conversions   
 *    to other character set standards (ASCII,UTF16,UC-2,etc.) inside 
 *    your VSA implementation, if your product does not recognize UTF8!    
 *    This is the first release of VSI. For problems or questions     
 *    about functions or types, contact either the author or 
 *    mailto:secure@sap.com
 *
 *  Prerequisites:
 *    This header file and a SAP supported platform (plus compiler).
 *
 ----------------------------------------------------------------------------*/

#ifndef VSAXXTYP_H
#define VSAXXTYP_H

/* Microsoft Visual Studio 2005 changes 
 * time_t to 64-bit type on all platforms even on x86 (32-bit).
 * Therefore we use this define to switch back
 * to the standard, on 32-bit platforms time_t is
 * 4 byte and on 64-bit it is 8 byte.
 */
#if !defined(_WIN64) && defined(_MSC_VER) && _MSC_VER >= 1400
# ifndef _USE_32BIT_TIME_T
#  error "You have to define _USE_32BIT_TIME_T for a 32 bit time_t"
# endif
#endif
/* Standard headers                                                   */
#include <time.h>        /* used for UTC time/date support            */
#include <limits.h>      /* need _MAX values to define numeric types: */

#ifndef APIENTRY
#  if   (_WIN32) && defined(_M_IX86) || defined(_STDCALL_SUPPORTED)
#    define WIN32_MEAN_AND_LEAN
#    define WINAPI         __stdcall
#    define APIENTRY       WINAPI
#  else
#    define APIENTRY
#  endif
#endif

#ifdef SAPDECLSPEC_H /* Within SAP     */
#define VSA_API            SAP_DECLSPEC_EXPORT
#else                /* Outside of SAP */
#ifndef VSA_API
#  if (_WIN32) && defined(_M_IX86) || defined(_STDCALL_SUPPORTED)
#    define VSA_API        __declspec( dllexport ) WINAPI
#  elif defined(SAPonLIN) && defined(__GNUC__) && !defined(GCC_NO_HIDDEN_VISIBILITY) && !defined(SAPccQ)
#    define VSA_API        __attribute__((visibility("default")))
#  else
#    define VSA_API
#  endif
#endif
#endif

/* declaration for implementations outside of SAP */
#ifndef DLL_EXPORT
#define DLL_EXPORT          VSA_API
#endif

#ifndef CALLBACK
#  if defined (_WIN32) && defined(_M_IX86) || defined(_STDCALL_SUPPORTED)
#    define CALLBACK       __stdcall
#  else
#    define CALLBACK
#  endif
#endif

/*--------------------------------------------------------------------*/
/*    defines                                                         */
/*--------------------------------------------------------------------*/
#ifndef PATH_MAX                    /*-PATH_MAX <limits.h> not present*/
# ifndef MAX_PATH_LN
    #define MAX_PATH_LN     1024
# endif
# ifndef SAP_SYS_NMLN
    #define SAP_SYS_NMLN    256
# endif
#else
# ifndef MAX_PATH_LN
    #define MAX_PATH_LN     PATH_MAX+1/* <sys/limits.h> no terminating 0*/
# endif 
# ifndef SAP_SYS_NMLN
    #define SAP_SYS_NMLN    256
# endif
#endif

/*--------------------------------------------------------------------*/
/* basic defines                                                      */
/*--------------------------------------------------------------------*/

#ifndef TRUE
#define TRUE    1
#endif

#ifndef FALSE
#define FALSE   0
#endif

#ifndef NULL
#define NULL    0L
#endif

/*--------------------------------------------------------------------*/
/* project related defines                                            */
/*--------------------------------------------------------------------*/
/* symbol defines
 */
#ifndef LSTOK                       /* @type LSTOK | List/Token delimiter 
                                                     symbol ';' (semicolon). */
# define LSTOK           ";"        /* Used for all PChar list values        */
# define LSTOK_CHAR      ';'        /* VS_IP_SERVERS,VS_IP_DRIVERNAMES       */
#endif                              /* VS_OP_SCANEXTENSIONS, and so on       */
#ifndef EXTSIGN                     /* @type EXTSIGN | Extension replace sign
                                       '?' (question mark), such as C??,EX?  */
# define EXTSIGN         "?"        /* Indicates that the current            */
# define EXTSIGN_CHAR    '?'        /* character is either zero or any       */
#endif                              /* non-zero sign                         */
#ifndef EXTCHAR                     /* @type EXTCHAR | Extension replacement 
                                       sign '*' (asterisk), such as C*,EX*,D */
# define EXTCHAR         "*"        /* The asterisk behaves here in the same way */
# define EXTCHAR_CHAR    '*'        /* as in a reg. expression, either this or   */
#endif                              /* following signs can be (non)/zero         */

/*--------------------------------------------------------------------*/
/*    public typedefs                                                 */
/*--------------------------------------------------------------------*/
/* type definition                                                    */
/*
 * SAP internal:
 * we don't need to declare these types
 */
# ifndef VSI_INTERNAL
/* Short */
#if SHRT_MAX == 0x7FFF /* -32767 - 32767 */
  typedef short SAP_SHORT;
#else
  #error "We need a short type with 2 bytes"
#endif

/* UShort */
#if USHRT_MAX == 0xFFFFu /* 0 - 65535 */
  typedef unsigned short SAP_USHORT;
#else
  #error "We need a unsigned short type with 2 bytes"
#endif

/* Int */
#if INT_MAX == 0x7FFFFFFF /* -2147483647 - 2147483647 */
    typedef int SAP_INT;
#elif LONG_MAX == 0x7FFFFFFF
    typedef long SAP_INT;
#else
    #error "We need an int type with 4 bytes"
#endif

/* UInt */
#if UINT_MAX == 0xFFFFFFFFu /* 0 - 4294967295 */
    typedef unsigned int SAP_UINT;
#elif ULONG_MAX == 0xFFFFFFFFu
    typedef unsigned long SAP_UINT;
#else
    #error "We need an unsigned int type with 4 bytes"
#endif

/* Long */
#if defined(WIN32) || defined(WIN64)
    typedef __int64 SAP_LLONG; /* -+ 9223372036854775807 */
    typedef unsigned __int64 SAP_ULLONG;
#else
# if ( defined(__ia64__)  || defined(__s390x__) || defined(__x86_64__) || \
       defined(__PPC64__) || defined(__sparcv9) || defined(__LP64__) )
    typedef          long SAP_LLONG;   /* this requires the LP64 data model */
    typedef unsigned long SAP_ULLONG;
# else
    typedef     long long SAP_LLONG;
    typedef unsigned long long SAP_ULLONG;
# endif
#endif
    
/* 
 * SAP_UTF8
 * UTF-8 is from type unsigned char
 */
  typedef   unsigned char SAP_UTF8;                       /*UTF8 chars*/
  typedef   unsigned char SAP_BOOL;
  typedef   unsigned char SAP_RAW;
  typedef   unsigned char SAP_BYTE;
# endif 

/* basic typedefs                                                     */

#ifndef _basictypedefs
#define _basictypedefs 
/*   base type   ||           VSA type             || parameter prefix*/
/* @type Void | Data type <t void>. Pointer declarations are 
                *PVoid, **PPVoid. Platform specific size !            */
  typedef void        Void,    *PVoid,    **PPVoid;       /* v        */
/* @type Char | Defined as UTF-8 string "unsigned char" which means 
                the adapter has to use UTF-8 for character operations */
  typedef SAP_UTF8    Char,    *PChar,    **PPChar;       /* sz       */
/* @type Byte | 8-bit \<=\> 1 byte. Defined as "unsigned char"        */
  typedef SAP_RAW     Byte,    *PByte,    **PPByte;       /* b        */
/* @type Short | 2 byte value with the range -32767 to 32767          */
  typedef SAP_SHORT   Short,   *PShort,   **PPShort;      /* s        */
/* @type UShort | 2 byte value with the range 0 to 65535              */
  typedef SAP_USHORT  UShort,  *PUShort,  **PPUShort;     /* us       */
/* @type Int | 4 byte value with the range -2147483647 to 2147483647  */
  typedef SAP_INT     Int,     *PInt,     **PPInt;        /* i        */
/* @type UInt | 4 byte value with the range 0 to 4294967295           */
  typedef SAP_UINT    UInt,    *PUInt,    **PPUInt;       /* ui       */
/* @type Long | 8 byte value with the range -+ 9223372036854775807    */
  typedef SAP_LLONG   Long,    *PLong,    **PPLong;       /* l        */
/* @type ULong | 8 byte value with the range 0 - 18446744073709551615 */
  typedef SAP_ULLONG  ULong,   *PULong,   **PPULong;      /* ul       */
/* @type Bool |  Means unsigned 8-bit unsigned character: Byte.       */
  typedef SAP_BOOL    Bool,    *PBool,    **PPBool;       /* b        */
/* @type Double | 8 byte value                                        */
  typedef double      Double,  *PDouble,  **PPDouble;     /* d        */
/* @type Float | 4 byte floating point value                          */
  typedef float       Float,   *PFloat,   **PPFloat;      /* f        */
/* @type time_t | Platform-specific data type time_t. Contains the time 
                  in sec.                                             */
/* @type size_t | Platform-specific data type size_t. Contains the byte
                  length of an object                                 */
#endif   /* _basictypedefs */

/*--------------------------------------------------------------------*/
/*    project related typedefs                                        */
/*--------------------------------------------------------------------*/
#ifndef __vsatypedefs
#define __vsatypedefs
/* @type VSA_ENGINE | Handle to an external AV product. 
                      Data type is *<t Void>*/
  typedef PVoid VSA_ENGINE;
/* @type VSA_USRDATA | Contain pointer to user-defined data structure. 
                       Data type is *<t Void>*/
  typedef PVoid VSA_USRDATA;
/* VSA_IODATA | Contain pointer to user-defined I/O data. 
                       Data type is *<t Void>*/
  typedef PVoid VSA_IODATA;
/* @type VSA_PARAMVALUE | Contain pointer to a parameter value. 
                          Data type is *<t Void>*/
  typedef PVoid VSA_PARAMVALUE;
/* @type VSA_PARAM | Pointer to the value returned by callback. The
                     real information in the pointer might be 
                     dereferenced. Data type is *<t Void>*/
  typedef PVoid VSA_PARAM;
#endif   /* __vsatypedefs */


#ifndef _vs_typedefs
#define _vs_typedefs
/*--------------------------------------------------------------------*/
/*    parameter enumerator                                            */
/*--------------------------------------------------------------------*/
/* @enum VS_INITPARAM_T |
 *   Initial parameter list of VSA. These parameters must be set with 
 *   the function <f VsaInit>.
 *   @xref When providing a "list" the token <t LSTOK> separates the values.
 *         The number of entries in the list has to be checked by the adapter.
 *         <nl><t VS_OPTPARAM_T>
 */
typedef enum __vs_initparameter_enum {
    /*---VS initialization parameters---*/
    VS_IP_INITDRIVERS              =   0,  /* @emem Standard driver(list) which should be loaded on <f VsaInit>  */
    VS_IP_INITEXTRADRIVERS         =   1,  /* @emem Extra or additional driver(list) in a separate location.     */
    VS_IP_INITDRIVERDIRECTORY      =   2,  /* @emem Default directory in which the required drivers can be found.*/
    VS_IP_INITEXTRADRIVERDIRECTORY =   3,  /* @emem Extra or additional directory in which drivers can be found. */
    VS_IP_INITSERVERS              =   4,  /* @emem Server(list) to be connected if VSA is a scan daemon. Syntax: "server[:port];server[:port]" */
    VS_IP_INITTIMEOUT              =   5,  /* @emem Timeout in sec (<t time_t>) for the connection to the VSA.   */
    VS_IP_INITRECONNECTTIME        =   6,  /* @emem Time in sec (<t time_t>) after which a VSA should reattempt connection if a TIMEOUT occures. */
    VS_IP_INITCONTENTPATTERN       =   7,  /* @emem POSIX regular pattern the engine should search on content scan*/
    VS_IP_INITREPLACEPATTERN       =   8,  /* @emem POSIX reg. pattern for replace actions                       */
    VS_IP_INITREGEXFLAGS           =   9,  /* @emem POSIX reg. flags for the regex engine                        */
    VS_IP_INITTEMP_PATH            =  10,  /* @emem Temporary directory path where the engine may create files.  */
    VS_IP_INITDIRECTORY            =  11,  /* @emem Base directory                                               */
    VS_IP_INITENGINES              =  12,  /* @emem Threat engine(s) to be used for malware protection, content filtering, etc.  */
    VS_IP_INITENGINEDIRECTORY      =  13,  /* @emem Default directory in which the threat engine(s) can be found */
    VS_IP_INITUPDATE_URI           =  14,  /* @emem URI (URL or local path) to an update service                 */
    VS_IP_INITLICENSE_PATH         =  15   /* @emem Path where the external product can find a valid license file*/

} VS_INITPARAM_T, *PVS_INITPARAM_T, **PPVS_INITPARAM_T;

/* @enum VS_OPTPARAM_T |
 *   Initial parameter list of VSA. These parameters must be set with 
 *   the function <f VsaScan>.
 *   @xref When providing a "list" the token <t LSTOK> separates the values.
 *         The number of entries in the list has to be checked by the adapter.
 *         <nl><t VS_INITPARAM_T>
 */
typedef enum __vs_optionparameter_enum {
    /*---VS optional scan parameters---*/
    VS_OP_SCANBESTEFFORT           = 100,  /* @emem Set all flags known to the VSA to provide a scan on the "best effort" basis, such as SCANALLFILES*/
    VS_OP_SCANALLFILES             = 101,  /* @emem Scan for all files, regardless of their extension. Means ??? or *                             */
    VS_OP_SCANALLMACROS            = 102,  /* @emem Scan for all macro types regardless of their file type. If SCANALLFILES, then this has no effect*/
    VS_OP_SCANALLEMBEDDED          = 103,  /* @emem Scan in embedded objects: uu-/hex-/xx-/binhex-encoded files, objects in PDF etc.                                     */
    VS_OP_SCANEXTENSIONS           = 104,  /* @emem Scan only for these extensions. Wildcards can also be used here, such as exe;com;b?t;h??;.
                                            *       See <t EXTSIGN> and <t EXTCHAR>. */
    VS_OP_SCANHEURISTICLEVEL       = 105,  /* @emem Activate heuristic searching at level X. 0 means deactivated                                    */
    VS_OP_SCANONLYHEURISTIC        = 106,  /* @emem Use only heuristic mechanisms.                                                             */
    VS_OP_SCANLIMIT                = 107,  /* @emem Restricts scan/repair of an object to a number. In this way you can search, for example, only 
                                                    for one virus.                                                                                  */
    VS_OP_SCANEXTRACT              = 108,  /* @emem Archives or compressed objects should be unpacked                                               */
    VS_OP_SCANEXTRACT_PATH         = 109,  /* @emem Unpack directory, such as temporary scan directory                                              */
    VS_OP_SCANEXTRACT_SIZE         = 110,  /* @emem Maximum unpack size in <t size_t>                                                               */
    VS_OP_SCANEXTRACT_TIME         = 111,  /* @emem Maximum unpack time                                                                             */
    VS_OP_SCANEXTRACT_DEPTH        = 112,  /* @emem Maximum depth to which an object should be unpacked.                                            */
    VS_OP_SCANEXTRACT_RATIO        = 113,  /* @emem Maximum ratio of compressed/uncompressed of an object                                           */
    VS_OP_SCANLOGPATH              = 114,  /* @emem Path for log or trace file of the VSA.                                                          */
    VS_OP_SCANDIREXCLUDELIST       = 115,  /* @emem List of directories to be excluded when scanning subdirectories.                                */
    VS_OP_SCANSUBDIRLEVEL          = 116,  /* @emem Scans subdirectories to a level of X. 0 means that subdirectories are not scanned.              */
    VS_OP_SCANACCESSFILELOCAL      = 117,  /* @emem Object can be accessed locally by the VSA or engine. Informs scan daemons that the object does not
                                            *       need to be sent using sockets.                                                                  */
    VS_OP_SCANMIMETYPES            = 118,  /* @emem Scan and allow MIME types. Define more than one in a list or by wildcards, such as text*   */
    VS_OP_SCANEXCLUDEMIMETYPES     = 119,  /* @emem Depreciated, do not use anymore, but support BLOCK parameters */
    VS_OP_SCANREGEXFLAGS           = 120,  /* @emem POSIX reg. flags for the regex engine                                                           */
       /*---reserved---*/    
    VS_OP_CLEANRENAME              = 200,  /* @emem An infected object should be renamed if it is cleaned. The rules for this depend on the VSA.    */
    VS_OP_CLEANDELETE              = 201,  /* @emem An infected object should be deleted either directly or if not reparable, depending on the VSA.*/
    VS_OP_CLEANQUARANTINE          = 202,  /* @emem Directory for infected objects. VSA should move the infected objects there.                     */
    VS_OP_CLEANNODELETEINARCHIVE   = 203,  /* @emem If an infection is found in an archive file, this subobject should not be deleted.              */
    VS_OP_CLEANNODELETEINEMBEDDED  = 204,  /* @emem If an infection is found in an embedded object (including macros), this subobject should not be 
                                            *       deleted. For example, for Microsoft Word documents with embedded macro viruses.                 */
    VS_OP_CLEANNODELETEJOKES       = 205,  /* @emem Infected objects should not be deleted if the VSA determines that they are not real viruses,
                                            *       but rather hoaxes or joke viruses.                                                              */
       /*---reserved---*/

    VS_OP_BLOCKMIMETYPES           = 300,  /* @emem Block MIME types       */
    VS_OP_BLOCKEXTENSIONS          = 301   /* @emem Block files extensions */

} VS_OPTPARAM_T, *PVS_OPTPARAM_T, **PPVS_OPTPARAM_T;

/* @type VS_PARAMETER_T |
 *   Union of parameter types.
 *   @xref The number of entries in the list has to be checked by the adapter.
 *         <nl><t VS_INITPARAM_T>
 *         <nl><t VS_OPTPARAM_T>
 */
typedef union __vs_parameter_union {
    VS_INITPARAM_T tInitCode;
    VS_OPTPARAM_T  tOptCode;
} VS_PARAMETER_T, *PVS_PARAMETER_T, **PPVS_PARAMETER_T;

/*--------------------------------------------------------------------*/
/*    vendor enumerator for the adapter information                   */
/*--------------------------------------------------------------------*/
/* @enum VS_ADAPTER_T |
 * This enumerator identifies which certified adapter the
 * partner provides. For new vendors or products, add your new ID here.
 * You could also define an extra ID here for different versions of an
 * engine to provide extra mechanisms.
 */
typedef enum __vs_adapter_enum {
    VS_AD_SAP              =  0,   /* @emem Example ID for a SAP VSA.                  */
    VS_AD_HBV,                     /* Avira (H+BEDV) AntiVir interface                 */
    VS_AD_SAV,                     /* Sophos SAVI interface                            */
    VS_AD_NAI,                     /* McAfee engine                                    */
    VS_AD_SYM,                     /* Symantec Scan Engine API                         */
    VS_AD_BBS,                     /* BowBridge Software Company with AntiVirus Bridge */
    VS_AD_FSC,                     /* F-Secure engine interface                        */
    VS_AD_CLAM,                    /* OpenSource ClamAV adapter ClamSAP                */
    VS_AD_TDM,                     /* Trend Micro Virus Scan Engine adapter            */
    VS_AD_DAEMON,                  /* Generic ID for a daemon adapter (sockets,ICAP,Proxy,etc.)*/
    VS_AD_COMMAND                  /* Generic ID for a command line wrapper            */

} VS_ADAPTER_T, *PVS_ADAPTER_T, **PPVS_ADAPTER_T;
/*  @enum VS_THREADMODEL_T |
 *  Type of thread model the VSA supports. These types are
 *  corresponding to the COM/COM+ ThreadingModel identifiers.
 */
typedef enum __vs_threadingmodel_enum {
    /*---VSA threading model---*/
    VS_THREAD_APARTMENT    =   0,   /* @emem Single-thread apartment (STA). The VSA
                                     *  supports only single threaded instances.       */
    VS_THREAD_BOTH,                 /* @emem STA and MTA provided.                     */
    VS_THREAD_FREE                  /* @emem Multi-thread apartment (MTA). The VSA instances
                                     *  are valid for different threads.               */

} VS_THREADMODEL_T, *PVS_THREADMODEL_T, **PPVS_THREADMODEL_T;
 
/*----------------------------------------------------------------------
 *  @enum VS_PARAMTYPE_T |
 *  Virus scan specific DATA TYPES
 *  This section defines the data types known to the VSA as generic data 
 *  types to those known on the upper level
 *----------------------------------------------------------------------*/
typedef enum VS_PARAMTYPE_T {
    VS_TYPE_BOOL        = 0,       /* @emem boolean, 1 byte <t Bool>    */
    VS_TYPE_BYTE,                  /* @emem byte, 1 byte <t Byte>       */
    VS_TYPE_SHORT,                 /* @emem short, 2 byte <t Short>     */
    VS_TYPE_INT,                   /* @emem int, 4 byte <t Int>         */
    VS_TYPE_LONG,                  /* @emem long, 8 byte <t Long>       */
    VS_TYPE_FLOAT,                 /* @emem float, 4 byte <t Float>     */
    VS_TYPE_DOUBLE,                /* @emem double, 8 byte <t Double>   */
    VS_TYPE_CHAR,                  /* @emem UTF8, unsigned char <t Char>*/
    VS_TYPE_TIME_T,                /* @emem platform depend. <t time_t> */
    VS_TYPE_SIZE_T,                /* @emem platform depend. <t size_t> */
    VS_TYPE_OBJECT                 /* @emem <t void>                    */

} VS_PARAMTYPE_T, *PVS_PARAMTYPE_T, **PPVS_PARAMTYPE_T;

/* @enum VS_DETECTTYPE_T |
 * Type of detection for found object.
 */
typedef enum __vs_detecttype_enum {
    VS_DT_NOVIRUS    = 0,                      /* @emem No virus \<=\> <e VS_VIRUSTYPE_T.VS_VT_NOVIRUS>*/
    VS_DT_KNOWNVIRUS,                          /* @emem Known virus. Provide additional information.   */
    VS_DT_VARIANTVIRUS,                        /* @emem New but similar to a known virus               */
    VS_DT_NEWVIRUS,                            /* @emem Not a known virus                              */
    VS_DT_ACTIVECONTENT,                       /* @emem Not a virus but found active content           */
    VS_DT_MIMEVALIDATION,                      /* @emem Not a virus but found invalid MIME content     */
    VS_DT_PATTERNMATCH,                        /* @emem Not a virus but pattern matched                */
    VS_DT_ERROR                                /* @emem An error occurred                              */

} VS_DETECTTYPE_T, *PVS_DETECTTYPE_T, **PPVS_DETECTTYPE_T;

/* @enum VS_VIRUSTYPE_T |
 * Classification of the found virus infection.
 */
typedef enum __vs_virustype_enum {
    VS_VT_NOVIRUS   = 0,                       /* @emem Not a virus \<=\>  <e VS_DETECTTYPE_T.VS_DT_NOVIRUS>    */
    VS_VT_VIRUS,                               /* @emem Known virus, normal for us.                           */
    VS_VT_TROJAN,                              /* @emem Trojan                                                  */
    VS_VT_JOKE,                                /* @emem A bad joke, not a virus                                 */
    VS_VT_HOAX,                                /* @emem Wannabe virus; harmless.                                */
    VS_VT_POLYMORPH,                           /* @emem A polymorphic virus                                     */
    VS_VT_ENCRYPTED,                           /* @emem An encrypted object that looks like a virus             */
    VS_VT_COMPRESSED,                          /* @emem A compressed object that looks like a virus             */
    VS_VT_APPLICATION,                         /* @emem Application that behaves like a virus, such as a dialer */
    VS_VT_WORM,                                /* @emem A worm virus  (such as an e-mail worm)                  */
    VS_VT_CORRUPTED,                           /* @emem A corrupted object or an object that cannot be analyzed */
    VS_VT_TEST,                                /* @emem A test virus, such as EICAR                             */
    VS_VT_BACKDOOR,                            /* @emem A back door                                             */
    VS_VT_EXPLOIT,                             /* @emem An exploit                                              */
    VS_VT_FLOODER,                             /* @emem A flooder (such as ICQ bombs, lead to denial of service)*/
    VS_VT_SPAM,                                /* @emem A Spam mail                                             */
    VS_VT_PUA,                                 /* @emem (P)otential (u)nwanted (a)pplication                    */
    VS_VT_CHAMELEON                            /* @emem Chameleon file, found during MIME check                 */

} VS_VIRUSTYPE_T, *PVS_VIRUSTYPE_T, **PPVS_VIRUSTYPE_T;

/* @enum VS_OBJECTTYPE_T |
 * Type of the object which was found. This enumeration is designed to store IDs of the
 * MIME types (see RFC 2045 to 2049). The definition of MIME types are in canonical form, 
 * which means that the media types here are with a major integer and their subtypes with 
 * a "minor integer". The ranges of the media types are:
 * <nl>
 * <nl>text             <tab><tab>  ...   000...199
 * <nl>image                 <tab>  ...   200...299
 * <nl>video                 <tab>  ...   300...399
 * <nl>audio                 <tab>  ...   400...499
 * <nl>application           <tab>  ...   500...599
 * <nl>application/archive   <tab>  ...   600...699
 * <nl>multipart             <tab>  ...   700...799
 * <nl>message               <tab>  ...   800...899
 * <nl>model                 <tab>  ...   900...999
 */
typedef enum __vs_objecttype_enum {
    /* unknown / non-identifiable object */
    VS_OT_UNKNOWN         =  -1,               /* @emem Set unknown/unknown or application/unknown                      */
    /* text */
    VS_OT_TEXT            =   0,               /* @emem Plain text, means text/plain                                    */
    VS_OT_HTML            =   1,               /* @emem HTML object, means text/html                                    */
    VS_OT_XHTML           =   2,               /* @emem XHTML object application/xhtml+xml                              */
    VS_OT_XML             =   3,               /* @emem XML object, text/xml, application/xml                           */
    VS_OT_XSL             =   4,               /* @emem XML style sheet object, text/xsl, application/xslt+xml          */
    VS_OT_DTD             =   5,               /* @emem SGML Document Definition File                                   */
    VS_OT_JSCRIPT         =   6,               /* @emem JavaScript Code, application/javascript (application/javascript)*/
    VS_OT_EMCASCRIPT      =  12,               /* @emem Ecmascript, application/ecmascript                              */
    VS_OT_VBSCRIPT        =   7,               /* @emem Visual Basic for Applications Script                            */
    VS_OT_RTF             =   8,               /* @emem Microsoft RTF file (application/rtf)                            */
    VS_OT_RICHTEXT        =   9,               /* @emem Rich text file                                                  */
    VS_OT_CSS             =  10,               /* @emem CSS style sheet file                                            */
    VS_OT_SGML            =  11,               /* @emem SGML file                                                       */
    VS_OT_ALF             =  13,               /* @emem Archive Link Format (application/x-alf)                         */
    VS_OT_OTF             =  14,               /* @emem Open Type Font (application/x-otf)                              */
    VS_OT_SAPSHORTCUT     =  15,               /* @emem SAP Short File with extension *.sap (application/x-sapshortcut) */
    VS_OT_INI             =  16,               /* @emem Textual configuration files with extension ini (text/x-ini)     */
    VS_OT_JSON            =  17,               /* @emem Textual structured data in JSON format (text/json)              */
    /* image */
    VS_OT_IMAGE           = 200,               /* @emem Image object, means image/X (any)                               */
    VS_OT_GIF             = 201,               /* @emem GIF image file (application/gif)                                */
    VS_OT_JPEG            = 202,               /* @emem JPEG image file (application/jpg)                               */
    VS_OT_BMP             = 203,               /* @emem Bitmap image file                                               */
    VS_OT_RIFF            = 204,               /* @emem RIFF image file                                                 */
    VS_OT_TIFF            = 205,               /* @emem TIFF image file                                                 */
    VS_OT_PNG             = 206,               /* @emem PNG image file  (application/png)                               */
    VS_OT_ICO             = 207,               /* @emem ICO (icon image) file (application/ico)                         */
    VS_OT_SVG             = 208,               /* @emem SVG (vector graphic) (image/svg+xml)                            */
    VS_OT_LWF             = 209,               /* @emem Wavelet (extension lwf) (image/x-wavelet)                       */
    /* video */
    VS_OT_VIDEO           = 300,               /* @emem Video object                                                    */
    VS_OT_MPEG            = 301,               /* @emem MPEG-1/2 video stream                                           */
    VS_OT_QUICKTIME       = 302,               /* @emem Quick time file                                                 */
    VS_OT_AVI             = 303,               /* @emem Audio Video Interleave (AVI) File                               */
    /* audio */
    VS_OT_AUDIO           = 400,               /* @emem Audio object                                                    */
    VS_OT_WAV             = 401,               /* @emem Waveform Audio                                                  */
    VS_OT_MP3             = 402,               /* @emem MPEG Audio Stream, Layer III                                    */
    VS_OT_XMPEG           = 403,               /* @emem MPEG (mp2) file                                                 */
    VS_OT_MIDI            = 404,               /* @emem MIDI file                                                       */
    VS_OT_REALAUDIO       = 405,               /* @emem RealAudio file                                                  */
    VS_OT_FLASHVIDEO      = 406,               /* @emem Flash Video (video/x-flv)                                       */
    /* application */
    VS_OT_BINARY          = 500,               /* @emem Binary object (application/octet-stream)                        */
    VS_OT_MSO             = 501,               /* @emem Microsoft Office document                                       */
    VS_OT_VBAMACRO        = 502,               /* @emem VBA macro                                                       */
    VS_OT_COMPRESSED      = 503,               /* @emem Compressed object                                               */
    VS_OT_SELFEXTRACT     = 504,               /* @emem Compressed object with self-extracting                          */
    VS_OT_PDF             = 505,               /* @emem Adobe PDF file (application/pdf)                                */
    VS_OT_POSTSCRIPT      = 506,               /* @emem Adobe Postscript file (application/postscript)                  */
    VS_OT_EXEC            = 507,               /* @emem Dos/Windows executable                                          */
    VS_OT_ELF             = 508,               /* @emem Unix executable                                                 */
    VS_OT_MACHO           = 509,               /* @emem Mac executable                                                  */
    VS_OT_JAVA            = 510,               /* @emem JAVA byte code (application/x-java-class)                       */
    VS_OT_ODF             = 511,               /* @emem Open Document Formats (application/vnd.oasis.opendocument*)     */
    VS_OT_OFFICE          = 512,               /* @emem Generic Office Formats, in case of no MSOffice and ODF          */
    VS_OT_COM             = 513,               /* @emem MS-DOS COM (command) executable                                 */
    /* application/archive */
    VS_OT_ARCHIVE         = 600,               /* @emem Archive object                                                  */
    VS_OT_SAR             = 601,               /* @emem SAP archive format CAR/SAR (application/sar)                    */
    VS_OT_ZIP             = 602,               /* @emem ZIP archive (application/zip)                                   */
    VS_OT_TAR             = 603,               /* @emem TAR archive                                                     */
    VS_OT_GZIP            = 604,               /* @emem GZip archive (application/zip)                                  */
    VS_OT_ARJ             = 605,               /* @emem ARJ archive                                                     */
    VS_OT_RAR             = 606,               /* @emem RAR archive  (application/rar)                                  */
    VS_OT_UUE             = 607,               /* @emem UUE archive                                                     */
    VS_OT_CMZ             = 608,               /* @emem CMZ archive                                                     */
    VS_OT_CAB             = 609,               /* @emem Microsoft Cabinet archive                                       */
    VS_OT_TNEF            = 610,               /* @emem TNEF archive                                                    */
    VS_OT_LHA             = 611,               /* @emem LHA archive                                                     */
    VS_OT_BZIP2           = 612,               /* @emem BZip2 archive                                                   */
    VS_OT_ICAB            = 613,               /* @emem Install Shield Cabinet archive                                  */
    VS_OT_SFX             = 614,               /* @emem Self-extracting archive                                         */
    VS_OT_ARC             = 615,               /* @emem LH ARC old version                                              */
    VS_OT_ACE             = 616,               /* @emem WinAce Compressed File                                          */
    VS_OT_JAR             = 617,               /* @emem JAR archive, (application/x-jar)                                */
    VS_OT_FLASH           = 618,               /* @emem Flash File (application/x-shockwave-flash)                      */
    VS_OT_SILVERLIGHT     = 619,               /* @emem Silverlight (application/x-silverlight)                         */
    VS_OT_SIM             = 620,               /* @emem SAP Tutor file (application/x-sim)                              */
    VS_OT_KEP             = 621,               /* @emem SAP Show file (outdated in NetWeaver) (application/x-kep)       */
    /* multipart */
    VS_OT_MULTIPART       = 700,               /* @emem Multipart object                                                */
    VS_OT_EMBEDDED        = 701,               /* @emem Embedded object                                                 */
    VS_OT_ENCRYPTED       = 702,               /* @emem Encrypted object                                                */
    VS_OT_OLE2            = 703,               /* @emem Embedded document in OLE2 file                                  */
    VS_OT_FORM_DATA       = 704,               /* @emem Multipart data from HTML forms                                  */
    /* message */
    VS_OT_MESSAGE         = 800,               /* @emem Message RFC822 object                                           */
    VS_OT_RFC822          = 801,               /* @emem RFC 1822 based messages                                         */
    VS_OT_NEWS            = 802,               /* @emem Newsgroup message                                               */
    VS_OT_PARTIAL         = 803,               /* @emem Message with partial content                                    */
    VS_OT_HTTP            = 804,               /* @emem HTTP header message                                             */
    VS_OT_EXTERNALBODY    = 805,               /* @emem Message with external content                                   */
    /* model */
    VS_OT_MODEL           = 900,               /* @emem Vector model objects                                            */
    VS_OT_VRML            = 901,               /* @emem VRML file                                                       */
    VS_OT_3DMF            = 902                /* @emem 3DMF file                                                       */
    
} VS_OBJECTTYPE_T, *PVS_OBJECTTYPE_T, *PPVS_OBJECTTYPE_T;

/* @enum VS_ACTIONTYPE_T |
 * The action the was done with the object.
 */
typedef enum __vs_actiontype_enum {
    VS_AT_NOACTION        = 0,                 /* @emem No action                                 */
    VS_AT_ACTIONFAILED,                        /* @emem The action failed; error                  */
    VS_AT_CLEANED,                             /* @emem Object was repaired                       */
    VS_AT_RENAMED,                             /* @emem Object was renamed                        */
    VS_AT_DELETED,                             /* @emem Object was deleted                        */
    VS_AT_MOVED,                               /* @emem Objects was moved to quarantine directory */
    VS_AT_BLOCKED,                             /* @emem Object was blocked                        */
    VS_AT_ENCRYPTED                            /* @emem Object was encrypted                      */

} VS_ACTIONTYPE_T, *PVS_ACTIONTYPE_T, *PPVS_ACTIONTYPE_T;

/*--------------------------------------------------------------------*/
/*    message enumerator for event CALLBACK mechanism                 */
/*--------------------------------------------------------------------*/
/* @enum VS_MESSAGE_T |
 * This message enumerator is used with simple bit flags. These should 
 * provide user-defined notification mechanism. After <f VsaGetConfig> the 
 * adapter should return notification messages. The user can obtain for which events
 * the VSA should send notifications. Such as: FLAG = VS_M_VIRUS \| VS_M_CLEAN;
 * @xref <t VSA_CALLBACK>. 
 */
typedef enum __vs_message_enum {
    /* activate all known/supported messages, regardless of which the VSA supports */
    VS_M_ALL               = ((0L)-1),     /* @emem Should help the user to set all, regardless of the VSA */
    /* send error string on VSA internal errors, such as bad, unknown parameter, invalid handle...              */
    VS_M_ERROR             = 0x01000000L,  /* @emem Error occurred. Send VSA error text                         */
    /* the query messages must return <> 0 for YES and 0 for proceeding the action                              */
    VS_M_ABORTSCAN         = 0x02000000L,  /* @emem Abort current scan action?    =\> Send JOBID                */
       /*---reserved---*/
    /* higher message ids */
    VS_M_VIRUS             = 0x00010000L,  /* @emem Virus found !                 =\> Send <t VSA_VIRUSINFO>    */
    VS_M_CLEAN             = 0x00020000L,  /* @emem No virus found                =\> Send JOBID                */
    VS_M_NOTSCANNED        = 0x00040000L,  /* @emem The object was not scanned    =\> Send <t VSA_SCANERROR>    */
    VS_M_REPAIRED          = 0x00080000L,  /* @emem The object was repaired       =\> Send <t VSA_VIRUSINFO>    */
    VS_M_NOTREPAIRED       = 0x00100000L,  /* @emem The object was not repaired   =\> Send <t VSA_SCANERROR>    */
    VS_M_OBJECTFOUND       = 0x00200000L,  /* @emem Object found such as OnFileFound =\> Send OBJECTNAME        */
    /* for macro actions   */
    VS_M_MACROSCLEANED     = 0x00400000L,  /* @emem All macros in object cleaned  =\> Send JOBID                */
    VS_M_CONTAINMACROS     = 0x00800000L,  /* @emem Object contains macros        =\> Send JOBID                */
    /* update notification */
    VS_M_EXPIRED           = 0x00000010L,  /* @emem Signature patterns were updated, instance needs to be reloaded   */
    /* lower message ids */
    VS_M_SCANACTIONS       = 0x00000001L,  /* @emem Send number of re-scans if <e VS_OPTPARAM_T.VS_OP_SCANLIMIT> \> 0*/
    VS_M_SCANPROGRESS      = 0x00000002L,  /* @emem Called in short distances     =\> Send progress in percentage*/
    VS_M_MATCHPATTERN      = 0x00000004L,  /* @emem The content matches a specified expression. =\> Send <t VSA_CONTENTINFO>*/
    VS_M_REPLACEDPATTERN   = 0x00000008L   /* @emem The matched pattern was replaced. =\> Send <t VSA_CONTENTINFO>*/
    /*---reserved---*/

} VS_MESSAGE_T, *PVS_MESSAGE_T, **PPVS_MESSAGE_T;


/*--------------------------------------------------------------------*/
/*    request enumerator for client I/O CALLBACK mechanism            */
/*--------------------------------------------------------------------*/
/* @enum VS_IOREQUEST_T |
 * This I/O request enumerator is used with simple bit flags. These should 
 * provide client input/output requests for bytes to be scanned. After <f VsaGetConfig> the 
 * adapter should return the I/O request messages. 
 * @xref <t VSA_CALLBACK>.
 */
typedef enum __vs_iorequest_enum {

    VS_IO_OPENREAD          = 0x00000010L,  /* @emem Open the stream for read                                 */
    VS_IO_OPENWRITE         = 0x00000020L,  /* @emem Open the stream for write                                */
    VS_IO_CLOSEREAD         = 0x00000040L,  /* @emem Close the input stream                                   */
    VS_IO_CLOSEWRITE        = 0x00000080L,  /* @emem Close the output stream                                  */
    VS_IO_READ              = 0x00000100L,  /* @emem Read bytes from the stream                               */
    VS_IO_WRITE             = 0x00000200L   /* @emem Write bytes to the stream                                */

} VS_IOREQUEST_T, *PVS_IOREQUEST_T, **PPVS_IOREQUEST_T;


/* @enum VS_CALLRC |
 *   CALLBACK return codes
 */
typedef enum __vs_callback_rc_enum {
    VS_CB_EOF               =  -1,   /* @emem Client I/O error or end-of-file return value*/
    VS_CB_OK                =   0,   /* @emem Callback OK, continue the action            */
    VS_CB_NEXT              =   1,   /* @emem Abort the current action, go to next object */
    VS_CB_TERMINATE         =   2    /* @emem Terminate the complete callback action.     */

} VS_CALLRC, PVS_CALLRC, **PPVS_CALLRC;
#endif  /* _vs_typedefs */

#ifndef _vsa_typedefs
#define _vsa_typedefs
/*--------------------------------------------------------------------*/
/* adapter intern data enumerations and structures                    */
/*--------------------------------------------------------------------*/
/* @enum VSA_SCANPARAM_T |
 *       Scanable object list of an adapter.
 */
typedef enum __vsa_scanparameter_enum {
    /*---VSA scan parameters. Only one of these params can be set for one call                          */
    VSA_SP_CLIENTIO                = 0x00000001L,  /* @emem Perform client I/O such as external streams */
    VSA_SP_BYTES                   = 0x00000002L,  /* @emem Byte array: an area in memory of
                                                    *  a defined number of bytes in length.             */
    VSA_SP_FILE                    = 0x00000004L,  /* @emem A single file in the local file system.     */
    VSA_SP_DIRECTORY               = 0x00000008L,  /* @emem A complete directory in the file system 
                                                    *  (with subdirectories, if specified).             */
    VSA_SP_PARTITION               = 0x00000010L,  /* @emem A complete local partition.                 */
    VSA_SP_BOOTSECTOR              = 0x00000020L,  /* @emem MBR partition boot block of local hard disk */
    VSA_SP_MEMORY                  = 0x00000040L,  /* @emem The entire local main memory. Might not be
                                                    *  possible for SAP platforms, but included for completeness*/
    VSA_SP_HTTP_HEADER             = 0x00000100L,  /* @emem HTTP header                                 */
    VSA_SP_HTTP_BODY               = 0x00000200L,  /* @emem HTTP body                                   */
    VSA_SP_HTTP_URI                = 0x00000400L,  /* @emem Uniform Ressource Locator (URI)             */
    VSA_SP_HTTP_MESSAGE            = 0x00000800L,  /* @emem Raw HTTP message                            */
    VSA_SP_MAIL_MESSAGE            = 0x00001000L,  /* @emem Raw mail message                            */

    VSA_SP_STREAM_OPEN             = 0x00010000L,  /* @emem Open a Stream                               */
    VSA_SP_STREAM_CLOSE            = 0x00020000L,  /* @emem Close a Stream                              */
    VSA_SP_STREAM_WRITE            = 0x00040000L,  /* @emem Write to a Stream                           */
    VSA_SP_STREAM_READ             = 0x00080000L   /* @emem Read from a Stream                          */

} VSA_SCANPARAM_T, *PVSA_SCANPARAM_T, **PPVSA_SCANPARAM_T;

/* @enum VSA_ACTIONPARAM_T |
 *       List of provided scan actions of the VSA.
 */
typedef enum __vsa_actionparameter_enum {
    /*---VSA action parameter for VsaScan, one or more flags are allowed use bitflag                                    */
    VSA_AP_CHECKMIMETYPE           = 0x00000001L,  /* @emem Check whether it is worthwhile to scan the object and whether it is scanable by VSA*/
    VSA_AP_SCAN                    = 0x00000002L,  /* @emem Scan only                                                   */
    VSA_AP_CHECKREPAIR             = 0x00000004L,  /* @emem Scan and if infected check if reparable, but do not clean  */
    VSA_AP_CLEAN                   = 0x00000008L,  /* @emem Scan and clean infected object                              */
    VSA_AP_BLOCKACTIVECONTENT      = 0x00000010L,  /* @emem Scan and regard all macros as virus send VS_M_CONTAINMACROS */
    VSA_AP_REMOVEACTIVECONTENT     = 0x00000020L,  /* @emem Scan and remove ***ALL*** embedded macros in objects        */
    VSA_AP_SCANCONTENT             = 0x00000040L,  /* @emem Scan the content and return content information structure   */
    VSA_AP_REPLACECONTENT          = 0x00000080L   /* @emem Scan and replace the content with specified content         */

} VSA_ACTIONPARAM_T, *PVSA_ACTIONPARAM_T, **PPVSA_ACTIONPARAM_T;

/*--------------------------------------------------------------------*/
/*    VSA return code enumerator                                      */
/*--------------------------------------------------------------------*/
/* @enum VSA_RC |
 * Returncodes of VSA implementations
 */
typedef enum __vsa_error_returncodes_enum {
    /* virus errors    */
    VSA_E_BLOCKED_BY_POLICY  =  -6,  /* @emem Content was blocked because of VSA_AP_CHECKCONTENT policy */
    VSA_E_CLEAN_FAILED       =  -5,  /* @emem Repair/clean of object failed                             */
    VSA_E_PATTERN_FOUND      =  -4,  /* @emem Found pattern on content scan, only if VSA_AP_SCANCONTENT */
    VSA_E_ACTIVECONTENT_FOUND=  -3,  /* @emem Found macro during scan, only if VSA_AP_BLOCKACTIVECONTENT*/
    VSA_E_VIRUS_FOUND        =  -2,  /* @emem Found virus during scan                                   */
    /* no infection, but former virus error  */
    VSA_E_CLEAN_OK           =  -1,  /* @emem Repair/clean of object was OK, Virus/Macros cleaned       */
    /* no error        */
    VSA_OK                   =   0,  /* @emem No error, no virus                                        */
    /* common program errors                                                                      */
    VSA_E_NO_SPACE           =   1,  /* @emem Resource problem: no memory,disk space,handle,etc. avail. */
    VSA_E_NULL_PARAM         =   2,  /* @emem NULL parameter was supplied to function, where not allowed*/
    VSA_E_INVALID_PARAM      =   3,  /* @emem At least one parameter is invalid                         */
    VSA_E_INVALID_HANDLE     =   4,  /* @emem Handle to adapter invalid                                 */
    VSA_E_NOT_INITIALISED    =   5,  /* @emem If <f VsaStartup>() was not successfully called           */
    /* scan engine warning/error                                                                  */
    VSA_E_EXPIRED            =   6,  /* @emem Engine or driver(s) out of date - need update             */
    VSA_E_LOAD_FAILED        =   7,  /* @emem Loading engine or another library failed                  */
    VSA_E_BAD_EXPRESSION     =   8,  /* @emem The passed regular expression contains a bad expression   */
    VSA_E_DRIVER_FAILED      =   9,  /* @emem Loading the driver(s) failed or invalid driver            */
    /* errors, occurred due to user failure                                                             */
    VSA_E_NOT_SUPPORTED      =  10,  /* @emem Action call or parameter is not supported on this VSA     */
    VSA_E_INVALID_SCANOBJECT =  11,  /* @emem Not correct object, such as "c:\" for VSA_SP_FILE         */
    /* common error for VsaScan,if any error occurred during scan, the engine were not able to scan*/
    VSA_E_CIO_FAILED         =  12,  /* @emem Client I/O callback failed. Scan could not be performed.  */
    VSA_E_SCAN_FAILED        =  13,  /* @emem See VSA_SCANERROR, any scan problem during action occurred*/
    /* not an error in scan, only information, that VSA has not touched this object               */
    VSA_E_NOT_SCANNED        =  14,  /* @emem Not an error, but a warning for the caller                */
    /* any internal error while closing/terminating the VSA                                       */
    VSA_E_END_FAILED         =  15,  /* @emem Termination/unload of VSA (engine) failed                 */
    VSA_E_IN_PROGRESS        =  16,  /* @emem VsaCleanup was not possible, a thread is still running    */
    /* additinal returncodes for  callback                                                        */
    VSA_E_CBC_TERMINATED     =  17   /* @emem Callback action was terminated by user                    */
       /*---reserved---*/

} VSA_RC, *PVSA_RC, **PPVSA_RC;

/*--------------------------------------------------------------------*/
/*    callback mechanism                                              */
/*--------------------------------------------------------------------*/
/* @cb VS_CALLRC CALLBACK | VSA_EVENTCBFP | 
 * This callback is for interactive event handling. it is not
 * mandatory for the user or the VSA vendor! Each message must be returned with <e VSA_RC.VS_CB_OK> to 
 * proceed with the action, otherwise action will (must) be 
 * terminated with <e VSA_RC.VSA_E_CBC_TERMINATED>
 *
 * @rdesc Return value must be one of <t VS_CALLRC>, otherwise the action will be terminated.
 */
/* ----------------------------------- event callback --------------------------------------------*/
typedef VS_CALLRC (CALLBACK *VSA_EVENTCBFP) (
                                             VSA_ENGINE     pVsaEngine, /* @parm Handle to AV engine <t VSA_ENGINE>   */
                                             VS_MESSAGE_T   tMessage,   /* @parm Message ID. typeof <t VS_MESSAGE_T>  */
                                             VSA_PARAM      pParameter, /* @parm Data passed by callback.             */
                                             VSA_USRDATA    pUsrData    /* @parm Pointer to user-defined data.        */
                                             );
/* ----------------------------------- event callback --------------------------------------------*/
/* @cb VS_CALLRC CALLBACK | VSA_CIOCBFP |
 * This callback is for client I/O requests. The call should be
 * used as follows: 1. VSA_SP_CLIENTIO is specified. 2. Callback 
 * function pointer is set in VSA_CALLBACK with the flags.
 * Flags means the types of callback requests the client will be 
 * provide, such as for a stream interface means. READ / WRITE / LENGTH
 */
/* ----------------------------------- client I/O callback ---------------------------------------*/
typedef VS_CALLRC (CALLBACK *VSA_CIOCBFP) (
                                            VSA_ENGINE     pVsaEngine,  /* @parm Handle to AV engine <t VSA_ENGINE>   */
                                            VS_IOREQUEST_T tRequest,    /* @parm Request ID. typeof <t VS_IOREQUEST_T>*/
                                            PVoid          pvBuffer,    /* @parm Buffer provided by engine            */
                                            size_t         lBufferSize, /* @parm Size of the provided buffer          */
                                            size_t        *lCopiedBytes /* @parm Size of the copied bytes             */
                                            );

/* ----------------------------------- client I/O callback ---------------------------------------*/
#endif  /* _vsa_typedefs */


/*--------------------------------------------------------------------
 *    structures to pass information to/from engines
 *--------------------------------------------------------------------*/
/*  @struct VSA_ADAPTERINFO |
 *  Virus scan adapter information structure to know which features 
 *  and configuration the current adapter has.
 *  @xref <t size_t>, <t VSA_CONFIG>, <t UInt>, 
 *        <t VS_ADAPTER_T>, <t VS_THREADMODEL_T>, <t Bool>.
 */
#ifndef __vsa_adapterinfo_s
typedef struct __vsa_adapterinfo_s {
    size_t              struct_size;                    /* @field Size of structure                                     */

    VS_ADAPTER_T        tAdapterID;                     /* @field <t VS_ADAPTER_T> ID of the certified vendor           */
    VS_THREADMODEL_T    tThreadingModel;                /* @field <t VS_THREADMODEL_T> Threading models: STA, both, MTA */
    UShort              usVsiVersion;                   /* @field Supported VSI version.                                */
    /* vendor specific data */                          /* if we have later another version                             */
    UShort              usVsaMajVersion;                /* @field VSA major version                                     */
    UShort              usVsaMinVersion;                /* @field VSA minor version                                     */
    PChar               pszVendorInfo;                  /* @field Version string of the vendor                          */
    PChar               pszAdapterName;                 /* @field VSA product name                                      */
    Bool                bReserved1;                     /* @field Reserved for later usage                              */
    void               *pvReserved2;                    /* @field Reserved for later usage                              */

} VSA_ADAPTERINFO, *PVSA_ADAPTERINFO, **PPVSA_ADAPTERINFO;
#define __vsa_adapterinfo_s
#endif  /* __vsa_adapterinfo_s */

/*  @struct VSA_CALLBACK |
 *  Callback structure.
 *  @xref <t size_t>, <t UInt>, 
 *        <t Bool>.
 */
#ifndef __vsa_callback_s
typedef struct __vsa_callback_s {
    size_t              struct_size;         /* @field Size of structure                                    */
    VSA_EVENTCBFP       pEventCBFP;          /* @field Callback function pointer of type <cbc VSA_EVENTCBFP>*/
    UInt                uiEventMsgFlags;     /* @field Bit combination of <t VS_MESSAGE_T> for callback     */
    VSA_USRDATA         pvUsrData;           /* @field Void* to pass own data through callback              */
    PVoid               pClientIOCBFP;       /* @field Pointer of client callback <cbc VSA_CIOCBFP>         */
    UInt                uiCIOMsgFlags;       /* @field Bit combination of <t VS_IOREQUEST_T> for callback   */
    VSA_IODATA          pvIOData;            /* @field Pointer to pass request data for I/O messages        */

} VSA_CALLBACK, *PVSA_CALLBACK, **PPVSA_CALLBACK;
#define __vsa_callback_s
#endif  /* __vsa_callback_s */

/*  @struct VSA_INITPARAM |
 *  Initial parameter structure of the adapter.
 *  @xref <t size_t>, <t VSA_CONFIG>, <t UInt>, <t VSA_INITPARAMS>,
 *        <t Bool>, <t Void>.
 */
#ifndef __vsa_initparameters_s
typedef struct __vsa_initparameter_s {       /* single parameter                              */
    size_t              struct_size;         /* @field Size of structure                      */

    VS_INITPARAM_T      tCode;               /* @field Parameter code from enum <t VS_INITPARAM_T>  */
    VS_PARAMTYPE_T      tType;               /* @field Type of pvValue <t VS_PARAMTYPE_T>           */
    size_t              lLength;             /* @field Size of pvValue                              */
    VSA_PARAMVALUE      pvValue;             /* @field Content of value  pvValue. Typeof: *<t Void> */
} VSA_INITPARAM, *PVSA_INITPARAM, **PPVSA_INITPARAM;

/*  @struct VSA_INITPARAMS |
 *  Initial parameter array structure.
 *  @xref <t size_t>, <t VSA_CONFIG>, <t UInt>, <t VSA_INITPARAM>,
 *        <t Bool>, <t Void>.
 */
typedef struct __vsa_initparameters_s {
   UShort               usInitParams;        /* @field Number of parameters in array                */
   PVSA_INITPARAM       pInitParam;          /* @field Pointer to the parameters <t VSA_INITPARAM>  */
} VSA_INITPARAMS, *PVSA_INITPARAMS, **PPVSA_INITPARAMS;
#define __vsa_initparameters_s
#endif /* __vsa_initparameters_s */

/*  @struct VSA_OPTPARAM |
 *  Optional parameter structure of the adapter.
 *  @xref <t size_t>, <t VSA_CONFIG>, <t UInt>, <t VSA_OPTPARAMS>,
 *        <t Bool>, <t Void>.
 */
#ifndef __vsa_optparameters_s
typedef struct __vsa_optparameter_s {        /* single parameter                             */
    size_t              struct_size;         /* @field Size of structure                     */

    VS_OPTPARAM_T       tCode;               /* @field Parameter code from enum <t VS_OPTPARAM_T>   */
    VS_PARAMTYPE_T      tType;               /* @field Type of pvValue <t VS_PARAMTYPE_T>           */
    size_t              lLength;             /* @field Size of pvValue                              */
    VSA_PARAMVALUE      pvValue;             /* @field Content of value  pvValue. Typeof: *<t Void> */
} VSA_OPTPARAM, *PVSA_OPTPARAM, **PPVSA_OPTPARAM;

/*  @struct VSA_OPTPARAMS |
 *  Optional parameter array structure.
 *  @xref <t size_t>, <t VSA_CONFIG>, <t UInt>, <t VSA_OPTPARAM>,
 *        <t Bool>, <t Void>.
 */
typedef struct __vsa_optparameters_s {
   UShort               usOptParams;         /* @field Number of parameters in array                */
   PVSA_OPTPARAM        pOptParam;           /* @field Pointer to the parameters <t VSA_OPTPARAM>   */
} VSA_OPTPARAMS, *PVSA_OPTPARAMS, **PPVSA_OPTPARAMS;
#define __vsa_optparameters_s
#endif /* __vsa_optparameters_s */

/*  @struct VSA_SCANPARAM |
 *  Scan structure for <f VsaScan>. Contains all information for the function.
 *  @xref <t size_t>, <f VsaScan>, <t UInt>, <t VSA_OPTPARAM>,
 *        <t VSA_OPTPARAMS>, <t Bool>, <t Void>.
 */
#ifndef __vsa_scanparameter_s
typedef struct __vsa_scanparameter_s {       /* single parameter                             */
    size_t              struct_size;         /* @field Size of structure                     */

    VSA_SCANPARAM_T     tScanCode;           /* @field Scan code,which object type should be scanned*/
    UInt                tActionCode;         /* @field Action type to be performed, such as SCAN \| CLEAN*/
    PChar               pszObjectName;       /* @field Path, file, or only name if bytes are scanned*/
    PByte               pbByte;              /* @field Ptr to bytes of length. lLength to be scanned*/
    size_t              lLength;             /* @field Size of bytes to be scanned in pointer pbByte*/
    UInt                uiJobID;             /* @field JobID should only be passed back to caller   */

} VSA_SCANPARAM, *PVSA_SCANPARAM, **PPVSA_SCANPARAM;
#define __vsa_scanparameter_s
#endif  /* __vsa_scanparameter_s */

#ifndef __vsa_config_s
/*  @struct VSA_CONFIG |
 *  Configuration structure of the adapter contains features and settings of it.
 *  These settings are requested after the adapter is started and are responsible for the other
 *  function calls.
 *  @xref <t size_t>, <t VSA_ADAPTERINFO>, <t UInt>, <t VSA_INITPARAMS>,
 *        <t VSA_OPTPARAMS>, <t Bool>, <t Void>.
 */
typedef struct __vsa_config_s {
    size_t              struct_size;        /* @field Size of structure                                      */

    PVSA_ADAPTERINFO    pAdapterInfo;       /* @field Info about adapter to be used. Pointer to <t VSA_ADAPTERINFO>*/
    UInt                uiVsaScanFlags;     /* @field OR linked value from <t VSA_SCANPARAM_T>.
                                             *        Which scan parameters are known.                          */
    UInt                uiVsaActionFlags;   /* @field Bit combination of <t VSA_ACTIONPARAM_T> which are known  */
    UInt                uiVsaEvtMsgFlags;   /* @field Bit combination of <t VS_MESSAGE_T> which are known       */
    UInt                uiVsaCIOMsgFlags;   /* @field Bit combination of <t VS_IOREQUEST_T> which are known     */
                                             
    PVSA_INITPARAMS     pInitParams;        /* @field Pointer to initial parameters array <t VSA_INITPARAMS>    */
    PVSA_OPTPARAMS      pOptParams;         /* @field Pointer to optional parameters array <t VSA_OPTPARAMS>    */
    Bool                bReserved1;         /* @field Reserved: for possible later usage                        */
    PVoid               pvReserved2;        /* @field Reserved: for possible later usage                        */

} VSA_CONFIG, *PVSA_CONFIG, **PPVSA_CONFIG;
#define __vsa_config_s
#endif /* __vsa_config_s */

/*  @struct VSA_DRIVERINFO |
 *  Information structure about the loaded drivers.
 *  @xref <t size_t>, <f VsaInit>, <t UInt>, <t VSA_INIT>,
 *        <t time_t>, <t Bool>, <t Void>.
 */
#ifndef __vsa_driverinfo_s                  /* driver means here definition files !                 */
typedef struct __vsa_driverinfo_s {         /* an scan engine can use more than one definition file */
    size_t              struct_size;        /* @field Size of structure                             */

    PChar               pszName;            /* @field Name of driver.                                      */
    UShort              usDrvMajVersion;    /* @field Major version of the driver                          */
    UShort              usDrvMinVersion;    /* @field Minor version of the driver                          */
    time_t              utcDate;            /* @field Driver date saved in UTC                             */
    UInt                uiViruses;          /* @field Number of viruses detected by this driver            */
    UInt                uiVariants;         /* @field Number of variants detected by this driver           */
    Int                 iDriverRC;          /* @field Error return code of driver on load <nl>
                                             * define: <nl>
                                             * iDriverRC  =   0 -\> OK <nl>                                
                                             * iDriverRC \<\> 0 -\> error/warning in driver, vendor intern.
                                             * Therefore set also ulErrorRC and fill pszErrorText in <t VSA_INIT>*/
} VSA_DRIVERINFO, *PVSA_DRIVERINFO, **PPVSA_DRIVERINFO;
#define __vsa_driverinfo_s
#endif  /* __vsa_driverstatus_s */

/*  @struct VSA_INIT |
 *  Single instance structure of VSA. The handle to the external product (engine, scan daemon) is stored
 *  here as a pointer (void). The other parameters are for information purposes. The caller has to check if
 *  a parameter is NULL.
 *  @xref <t size_t>, <f VsaInit>, <t UInt>, <t VSA_DRIVERINFO>,
 *        <t time_t>, <t Bool>, <t Void>.
 */
#ifndef __vsa_init_s
typedef struct __vsa_init_s {
    size_t              struct_size;        /* @field Size of structure                                    */
    /* Engine specific values               */
    VSA_ENGINE          hEngine;            /* @field Handle to external AV engine <t VSA_ENGINE>          */
    UInt                uiViruses;          /* @field Number of viruses known by engine                    */
    UInt                uiExtensions;       /* @field Numbers of extensions which can be scanned           */
    UInt                uiIntRevNum;        /* @field Internal revision number from engine                 */
    UInt                uiSignature;        /* @field Vendor-specific engine signature                     */
    /* Handle to used pattern files, drivers, virus definition files, ...                                  */
    UShort              usDrivers;          /* @field Number of drivers, which currently used              */
    PVSA_DRIVERINFO     pDriver;            /* @field Pointer to driver structure <t VSA_DRIVERINFO>       */
    /* Engine information values            */
    UShort              usEngineMajVersion; /* @field Major engine version number                          */
    UShort              usEngineMinVersion; /* @field Minor engine version number                          */
    PChar               pszEngineVersionText;/*@field Printable version string of engine                   */
    /* date of engine                       */
    time_t              utcDate;            /* @field Engine date saved in UTC                             */
    /* error handling                       */
    Int                 iErrorRC;           /* @field Vendor dep. error code either from driver or engine  */
    PChar               pszErrorText;       /* @field Vendor dep. error text occurred in driver or engine  */


} VSA_INIT, *PVSA_INIT, **PPVSA_INIT;
#define __vsa_init_s
#endif  /* __vsa_init_s */

/*  @struct VSA_CONTENTINFO |
 *  Information structure of the content to be scanned.
 *  @xref <t size_t>, <f VsaScan>, <t UInt>, <t VSA_SCANINFO>,
 *        <t VS_OBJECTTYPE_T>, <t time_t>, <t Bool>, <t Void>.
 */
#ifndef __vsa_contentinfo_s
typedef struct __vsa_contentinfo_s {
    size_t              struct_size;        /* @field Size of structure                                    */
    /* info flags about infection           */
    VS_OBJECTTYPE_T     tObjectType;        /* @field One of enumeration <t VS_OBJECTTYPE_T>               */
    PChar               pszExtension;       /* @field Extension of the content, such as .doc, .xls         */
    PChar               pszContentType;     /* @field MIME type of content, see RFCs 2045/2046/2077        */
    PChar               pszCharSet;         /* @field Charset of content                                   */
    /* object specific values               */
    UInt                uiJobID;            /* @field JobID, passed back to caller                         */
    PChar               pszObjectName;      /* @field Name of object, such as filename                     */
    size_t              lObjectSize;        /* @field Size of the object, such as byte length, file size.  */
    /* match specific values                */
    size_t              match_so;           /* @field Byte offset from string's start to substring's start.*/
    size_t              match_eo;           /* @field Byte offset from string's start to substring's end.  */

} VSA_CONTENTINFO, *PVSA_CONTENTINFO, **PPVSA_CONTENTINFO;
#define __vsa_contentinfo_s
#endif  /* __vsa_contentinfo_s */


/*  @struct VSA_VIRUSINFO |
 *  Information structure of a virus infection.
 *  @xref <t size_t>, <f VsaScan>, <t UInt>, <t VSA_SCANINFO>,
 *        <t VSA_SCANERROR>, <t time_t>, <t Bool>, <t Void>.
 */
#ifndef __vsa_virusinfo_s
typedef struct __vsa_virusinfo_s {
    size_t              struct_size;        /* @field Size of structure                              */
    /* info flags about infection           */
    Bool                bRepairable;        /* @field Flag to determine if the virus can be removed. */
    VS_DETECTTYPE_T     tDetectType;        /* @field One of enumeration <t VS_DETECTTYPE_T>         */
    VS_VIRUSTYPE_T      tVirusType;         /* @field One of enumeration <t VS_VIRUSTYPE_T>          */
    VS_OBJECTTYPE_T     tObjectType;        /* @field One of enumeration <t VS_OBJECTTYPE_T>         */
    VS_ACTIONTYPE_T     tActionType;        /* @field One of enumeration <t VS_ACTIONTYPE_T>         */
    /* virus specific values                */
    UInt                uiVirusID;          /* @field Virus identifier, may be different for another VSA*/
    PChar               pszVirusName;       /* @field Virus name                                     */
    /* object specific values               */
    UInt                uiJobID;            /* @field JobID, passed back to caller                   */
    PChar               pszObjectName;      /* @field Name of object, such as file name              */
    size_t              lObjectSize;        /* @field Size of the object, such as byte length, file size.*/
    /* reserved for free info               */
    PChar               pszFreeTextInfo;    /* @field Free text field, if engine has more information 
                                             *        about infection                                */


} VSA_VIRUSINFO, *PVSA_VIRUSINFO, **PPVSA_VIRUSINFO;
#define __vsa_virusinfo_s
#endif  /* __vsa_virusinfo_s */

/*  @struct VSA_SCANERROR |
 *  Information structure of a scan error that has occurred.
 *  @xref <t size_t>, <f VsaScan>, <t UInt>, <t VSA_SCANINFO>,
 *        <t VSA_VIRUSINFO>, <t time_t>, <t Bool>, <t Void>.
 */
#ifndef __vsa_scanerror_s
typedef struct __vsa_scanerror_s {
    size_t              struct_size;        /* @field Size of structure                   */
    /* object specific values               */
    UInt                uiJobID;            /* @field JobID, passed back to caller        */
    PChar               pszObjectName;      /* @field Name of object, such as filename    */
    size_t              lObjectSize;        /* @field Size of the object, such as byte length, file size.  */
    /* error handling                       */
    Int                 iErrorRC;           /* @field Vendor-dep. error code either from driver or engine  */
    PChar               pszErrorText;       /* @field Vendor-dep. error text occurred in driver or engine  */

} VSA_SCANERROR, *PVSA_SCANERROR, **PPVSA_SCANERROR;
#define __vsa_scanerror_s
#endif  /* __vsa_errorinfo_s */


/*  @struct VSA_SCANINFO |
 *  Information structure of a scan result.
 *  @xref <t size_t>, <f VsaScan>, <t UInt>, <t VSA_SCANERROR>,
 *        <t VSA_VIRUSINFO>, <t time_t>, <t Bool>, <t Void>.
 */
#ifndef __vsa_scaninfo_s
typedef struct __vsa_scaninfo_s {
    size_t              struct_size;        /* @field Size of structure              */
    /* objectID here again for result overview of scan action                        */
    UInt                uiJobID;            /* @field JobID, passed back to caller   */
    UInt                uiScanned;          /* @field Number of scanned objects, also counter for pContentInfo ()  */
    UInt                uiNotScanned;       /* @field Number of objects not scanned  */
    UInt                uiClean;            /* @field Number of clean objects        */

    UInt                uiInfections;       /* @field Number of infections, also counter for pVirusInfo ()         */
    UInt                uiScanErrors;       /* @field Number of errors during scan, also counter for pScanError () */

    PVSA_CONTENTINFO    pContentInfo;       /* @field Structure array (size = uiScanned)
                                             * with <t VSA_CONTENTINFO> to query information
                                             * about the content.                                                  */
    PVSA_VIRUSINFO      pVirusInfo;         /* @field Structure array (size = uiInfections)
                                             * with <t VSA_VIRUSINFO> to query infections      
                                             * without a callback function after a scan                            */
    PVSA_SCANERROR      pScanError;         /* @field Structure array (size = uiScanErrors)
                                               with <t VSA_SCANERROR> to query scan problems                       */
    PByte               pbBytesCleaned;     /* @field Filtered or changed/cleaned bytes. Correspond to <t VSA_SCANPARAM>
                                               field pbByte, but allocated by VSA. The VSA has to release/free it  */
    size_t              lBytesCleaned;      /* @field The size of the byte pbBytesCleaned
                                                                                                                   */
    /*  reserved here another parameter, currently not in use                        */
    PVoid               pvReserved1;        /* @field Reserved, not in use           */

} VSA_SCANINFO, *PVSA_SCANINFO, **PPVSA_SCANINFO;
#define __vsa_scaninfo_s
#endif  /* __vsa_scaninfo_s */

/*--------------------------------------------------------------------*/
/*    several NULL value defines allowed as defaults                  */
/*--------------------------------------------------------------------*/
#define VSA_NO_INITPARAMS       ((PVSA_INITPARAMS) 0)
#define VSA_NO_OPTPARAMS        ((PVSA_OPTPARAMS)  0)
#define VSA_NO_SCANINFO         ((PPVSA_SCANINFO)  0)
#define VSA_NO_CALLBACK         ((PVSA_CALLBACK)   0)
/* alternative defines for C freaks */
#define VSA_NULL_INITPARAMS     VSA_NO_INITPARAMS
#define VSA_NULL_OPTPARAMS      VSA_NO_OPTPARAMS
#define VSA_NULL_SCANINFO       VSA_NO_SCANINFO
#define VSA_NULL_CALLBACK       VSA_NO_CALLBACK

/*--------------------------------------------------------------------*/
/*    Constants for content scan                                      */
/*--------------------------------------------------------------------*/
#define VSA_E_NOT_KNOWN         VSA_E_NOT_SCANNED

/*--------------------------------------------------------------------*/
/*    Defines for legacy reasons                                      */
/*--------------------------------------------------------------------*/
#define VSA_E_MACRO_FOUND       VSA_E_ACTIVECONTENT_FOUND
#define VSA_AP_CHECKSCAN        VSA_AP_CHECKMIMETYPE
#define VSA_AP_FINDALLMACROS    VSA_AP_BLOCKACTIVECONTENT
#define VSA_AP_REMOVEALLMACROS  VSA_AP_REMOVEACTIVECONTENT

#ifdef __cplusplus
extern "C"
{
#endif

/*--------------------------------------------------------------------*/
/*    VSA interface                                                   */
/*--------------------------------------------------------------------*/
/**********************************************************************
 *  VsaStartup()
 *
 *  Description:
 *  @func
 *     Global initialization of the adapter. This function will be called
 *     once after loading the VSA.
 *  @end
 *
 *  @rdesc Returncodes: one of <t VSA_RC>
 *  @flag   VSA_OK                   |      Success
 *  @flag   VSA_E_NOT_INITIALISED    |      Global initialization not successful
 *  @flag   VSA_E_NO_SPACE           |      Any resource allocation failed 
 *
 **********************************************************************/
VSA_RC VSA_API VsaStartup( void );


/**********************************************************************
 *  VsaGetConfig() 
 *
 *  Description:
 *  @func
 *     This call allows the SAP system to know which type of VSA was loaded and
 *     which parameters and other features it has. An AV vendor of a VSA
 *     can also define a default profile of initial and optional 
 *     parameters here. <nl>
 *     "REQ" (required) parameters are mandatory. <nl>
 *     "OPT" (optional) parameters are not mandatory.
 *  @end
 *
 *  @rdesc Returncodes: one of <t VSA_RC>
 *  @flag   VSA_OK                |         Success
 *  @flag   VSA_E_NOT_INITIALISED |         Global initialization not successful
 *  @flag   VSA_E_NO_SPACE        |         Any resource allocation failed 
 *  @flag   VSA_E_NULL_PARAMETER  |         NULL pointer provided
 *
 **********************************************************************/
VSA_RC VSA_API VsaGetConfig(
                            PPVSA_CONFIG   ppVsaConfig /* @parm REQ[out] Address of handle <t VSA_CONFIG> */
                           );


/**********************************************************************
 *  VsaInit()
 *
 *  Description:
 *  @func
 *     Initializes or creates a new scan engine instance.
 *     Then assigns all the vendor specific data structures from
 *     actual AV product to VSA data structure.<nl>
 *     "REQ" (required) parameters are mandatory. <nl>
 *     "OPT" (optional) parameters are not mandatory.
 *  @end
 *
 *  @rdesc Returncodes: one of <t VSA_RC>
 *  @flag   VSA_OK                   |      Success
 *  @flag   VSA_E_EXPIRED            |      Engine or driver expired
 *  @flag   VSA_E_NO_SPACE           |      Any resource allocation failed 
 *  @flag   VSA_E_LOAD_FAILED        |      Load failed (such as external process)
 *  @flag   VSA_E_BAD_EXPRESSION     |      Regular expression syntax is invalid
 *  @flag   VSA_E_NULL_PARAM         |      NULL pointer provided
 *  @flag   VSA_E_INVALID_PARAM      |      At least one parameter is invalid
 *  @flag   VSA_E_DRIVER_FAILED      |      At least one driver failed
 *  @flag   VSA_E_NOT_SUPPORTED      |      At least one parameter or object is not supported
 *  @flag   VSA_E_CIO_FAILED         |      Client I/O request action failed.
 *  @flag   VSA_E_NOT_INITIALISED    |      Global initialization not successful
 *  @flag   VSA_E_CBC_TERMINATED     |      Action was terminated during callback
 *
 **********************************************************************/
VSA_RC VSA_API VsaInit(
                       const PVSA_CALLBACK   pVsaCallback,  /* @parm OPT[in ] Handle to <t VSA_CALLBACK>      */
                       const PVSA_INITPARAMS pVsaInitParams,/* @parm OPT[in ] Handle to <t VSA_INITPARAMS>    */
                             PPVSA_INIT      ppVsaInit      /* @parm REQ[out] Address of handle <t VSA_INIT>  */
                       );


/**********************************************************************
 *  VsaScan()
 *
 *  Description:
 *  @func
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
 *  @end
 *
 *  @rdesc Returncodes: one of <t VSA_RC> 
 *  @group Virus error codes (negative values):
 *  @flag    VSA_E_CLEAN_FAILED         |    Removing/replacing infection failed
 *  @flag    VSA_E_PATTERN_FOUND        |    Pattern was found
 *  @flag    VSA_E_MACRO_FOUND          |    Macro was found
 *  @flag    VSA_E_VIRUS_FOUND          |    Virus was found
 *  @flag    VSA_E_CLEAN_OK             |    The clean action was successful
 *  @group No error, no virus:
 *  @flag    VSA_OK                     |    Success
 *  @group Program error codes (positive values):
 *  @flag    VSA_E_NO_SPACE             |    Any resource allocation failed 
 *  @flag    VSA_E_NULL_PARAM           |    NULL pointer provided
 *  @flag    VSA_E_INVALID_PARAM        |    At least one parameter is invalid
 *  @flag    VSA_E_INVALID_HANDLE       |    The provided handle is invalid
 *  @flag    VSA_E_NOT_INITIALISED      |    The adapter was not successfully initialized
 *  @flag    VSA_E_NOT_SUPPORTED        |    At least one parameter or object is not supported
 *  @flag    VSA_E_INVALID_SCANOBJECT   |    See VSA_SCANPARAM, object is invalid
 *  @flag    VSA_E_CIO_FAILED           |    Client I/O failed. Scan could not be performed.
 *  @flag    VSA_E_SCAN_FAILED          |    The scan action failed
 *  @flag    VSA_E_NOT_SCANNED          |    At least one object was not scanned
 *  @flag    VSA_E_CBC_TERMINATED       |    Action was terminated during callback
 *
 **********************************************************************/
VSA_RC VSA_API VsaScan(
                       const PVSA_INIT      pVsaInit,     /* @parm REQ[in ]  Handle to <t VSA_INIT>             */
                       const PVSA_CALLBACK  pVsaCallback, /* @parm OPT[in ]  Handle to <t VSA_CALLBACK>         */
                       const PVSA_SCANPARAM pVsaScanParam,/* @parm REQ[in ]  Handle to <t VSA_SCANPARAM>        */
                       const PVSA_OPTPARAMS pVsaOptParams,/* @parm OPT[in ]  Handle to <t VSA_OPTPARAMS>        */
                             PPVSA_SCANINFO ppVsaScanInfo /* @parm OPT[out]  Address of handle <t VSA_SCANINFO> */
                       );


/**********************************************************************
 *  VsaReleaseScan()
 *
 *  Description:
 *  @func
 *     Release the dynamically allocated structure VSA_SCANINFO. The address of the
 *     of the handle is required but the handle can also point to NULL. <nl>
 *     "REQ" (required) parameters are mandatory. <nl>
 *     "OPT" (optional) parameters are not mandatory.
 *  @end
 *  
 *  @rdesc Returncodes: one of <t VSA_RC>
 *  @flag    VSA_OK                   |      Success
 *  @flag    VSA_E_NOT_INITIALISED    |      Global initialization not successful
 *  @flag    VSA_E_NULL_PARAM         |      NULL pointer provided
 *
 **********************************************************************/
VSA_RC VSA_API VsaReleaseScan(
                              PPVSA_SCANINFO  ppVsaScanInfo /* @parm REQ[in] Address of handle <t VSA_SCANINFO> */
                              );


/**********************************************************************
 *  VsaEnd()
 *
 *  Description:
 *  @func
 *     Closes the engine instance. Releases also VSA_CONFIG allocated
 *     by VsaGetConfig - assumes that the actual job is done there. <nl>
 *     "REQ" (required) parameters are mandatory. <nl>
 *     "OPT" (optional) parameters are not mandatory.
 *  @end
 *
 *  @rdesc Returncodes: one of <t VSA_RC>
 *  @flag   VSA_OK                     |    Success
 *  @flag   VSA_E_NULL_PARAM           |    NULL pointer provided
 *  @flag   VSA_E_NOT_INITIALISED      |    Global initialization not successful
 *  @flag   VSA_E_END_FAILED           |    The AV engine could not be closed
 *  @flag   VSA_E_IN_PROGRESS          |    Any thread is still running
 *
 **********************************************************************/
VSA_RC VSA_API VsaEnd(
                      PPVSA_INIT   ppVsaInit,  /* @parm REQ[in]  Address of handle <t VSA_INIT>   */
                      PPVSA_CONFIG ppVsaConfig /* @parm REQ[in]  Address of handle <t VSA_CONFIG> */
                      );


/**********************************************************************
 *  VsaCleanup()
 *
 *  Description:
 *  @func
 *     Global cleanup for the adapter. This function will be called at last
 *     before unloading the VSA.
 *  @end
 *
 *  @rdesc Returncodes: one of <t VSA_RC>
 *  @flag   VSA_OK                     |    Success
 *  @flag   VSA_E_NOT_INITIALISED      |    Global initialization not successful
 *  @flag   VSA_E_IN_PROGRESS          |    Any thread is still running
 *
 **********************************************************************/
VSA_RC VSA_API VsaCleanup( void );

#ifdef __cplusplus
}
#endif

#endif /* VSAXXTYP_H */
