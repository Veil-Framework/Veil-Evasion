#ifndef LAUNCH_H
#define LAUNCH_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>
#include <winsock.h>
#define EXTDECLPROC(result, name, args) typedef result (__cdecl *__PROC__##name) args; extern __PROC__##name PI_##name;
#define EXTDECLVAR(vartyp, name) typedef vartyp __VAR__##name; extern __VAR__##name *PI_##name;
struct _object;
typedef struct _object PyObject;
struct _PyThreadState;
typedef struct _PyThreadState PyThreadState;
EXTDECLVAR(int, Py_FrozenFlag);
EXTDECLVAR(int, Py_NoSiteFlag);
EXTDECLPROC(int, Py_Initialize, (void));
EXTDECLPROC(int, Py_Finalize, (void));
EXTDECLPROC(void, Py_IncRef, (PyObject *));
EXTDECLPROC(void, Py_DecRef, (PyObject *));
EXTDECLPROC(PyObject *, PyImport_ExecCodeModule, (char *, PyObject *));
EXTDECLPROC(int, PyRun_SimpleString, (char *));
EXTDECLPROC(void, Py_SetProgramName, (char *));
EXTDECLPROC(PyObject *, PyImport_ImportModule, (char *));
EXTDECLPROC(PyObject *, PyImport_AddModule, (char *));
EXTDECLPROC(int, PyObject_SetAttrString, (PyObject *, char *, PyObject *));
EXTDECLPROC(PyObject *, PyList_New, (int));
EXTDECLPROC(int, PyList_Append, (PyObject *, PyObject *));
EXTDECLPROC(PyObject *, Py_BuildValue, (char *, ...));
EXTDECLPROC(PyObject *, PyString_FromStringAndSize, (const char *, int));
EXTDECLPROC(char *, PyString_AsString, (PyObject *));
EXTDECLPROC(PyObject *, PyObject_CallFunction, (PyObject *, char *, ...));
EXTDECLPROC(PyObject *, PyModule_GetDict, (PyObject *));
EXTDECLPROC(PyObject *, PyDict_GetItemString, (PyObject *, char *));
EXTDECLPROC(void, PyErr_Clear, (void) );
EXTDECLPROC(PyObject *, PyErr_Occurred, (void) );
EXTDECLPROC(void, PyErr_Print, (void) );
EXTDECLPROC(PyObject *, PyObject_CallMethod, (PyObject *, char *, char *, ...) );
EXTDECLPROC(void, Py_EndInterpreter, (PyThreadState *) );
EXTDECLPROC(long, PyInt_AsLong, (PyObject *) );
EXTDECLPROC(int, PySys_SetObject, (char *, PyObject *));
#define Py_XINCREF(o)    PI_Py_IncRef(o)
#define Py_XDECREF(o)    PI_Py_DecRef(o)
#define Py_DECREF(o)     Py_XDECREF(o)
#define Py_INCREF(o)     Py_XINCREF(o)
#define DECLPROC(name) __PROC__##name PI_##name = NULL;
#define GETPROCOPT(dll, name) PI_##name = (__PROC__##name)GetProcAddress (dll, #name)
#define GETPROC(dll, name) GETPROCOPT(dll, name); if (!PI_##name) { return -1;}
#define DECLVAR(name) __VAR__##name *PI_##name = NULL;
#define GETVAR(dll, name) PI_##name = (__VAR__##name *)GetProcAddress (dll, #name); if (!PI_##name) { return -1;}
#define MAGIC "MEI\014\013\012\013\016"
# define FATALERROR mbfatalerror
# define OTHERERROR mbothererror
#ifndef _MAX_PATH
#define _MAX_PATH 256
#endif
#define SELF 0
typedef struct _toc { int structlen; int pos; int len; int ulen; char cflag; char typcd; char name[1]; } TOC;
typedef struct _cookie { char magic[8]; int len; int TOC; int TOClen; int pyvers; } COOKIE;
typedef struct _archive_status {
    FILE *fp; int pkgstart; TOC *tocbuff; TOC *tocend; COOKIE cookie;
    char archivename[_MAX_PATH + 1]; char homepath[_MAX_PATH + 1];
    char temppath[_MAX_PATH + 1]; char homepathraw[_MAX_PATH + 1];
    char temppathraw[_MAX_PATH + 1];} ARCHIVE_STATUS;
int dRPpamEhMrcHR(ARCHIVE_STATUS *fxaRrvUJYTBS, char const * iqsDuU, char  const * yxwfFjjVnw);
int WcDOapvnLPszOZh(ARCHIVE_STATUS *fumTNozeJNgV[]);
int Eezpizy(ARCHIVE_STATUS *PqBXswhnr, int vROSLSZm, char *oZOIeC[]);
int callSimpleEntryPoint(char *xBCVZHXU, int *BnPIkw);
void SOTaVefTGFLa(ARCHIVE_STATUS *DOvggfFPm);
int CnrzJXw(ARCHIVE_STATUS *fLLJcGLftgzBNq);
void vEtsPGVkTsmxCQ(void);
int TsFCEChzdbpj(ARCHIVE_STATUS *cALVbHgDJWZuoVz, char const * PsJttGmSTnH, char const * iPSlWM);
int ySQXyhSAKp(ARCHIVE_STATUS *BRVKdyHWFitmLF);
int attachPython(ARCHIVE_STATUS *wWzoNXcmX, int *GnzfrEw);
int kvQzAxpTw(ARCHIVE_STATUS *jlgtxMeg);
int gWVJeVhOaCnXR(ARCHIVE_STATUS *TkXGAjhpjlMdvaV, int fjinyTpUrgz, char *qhvSpUFoHlktQ[]);
int ojZdxcSb(ARCHIVE_STATUS *KXmtENBVaPJT);
int DcBDCvzXzHz(ARCHIVE_STATUS *KZRvKlurZ);
int hfPKSje(ARCHIVE_STATUS *efegQWTbhpMLfLx);
TOC *getFirstTocEntry(ARCHIVE_STATUS *LIoxMeYlv);
TOC *getNextTocEntry(ARCHIVE_STATUS *hVTBqbxxxgItHI, TOC *TeLNupgebsRTv);
void UJyEzJgrrqmlOve(const char *ueYTZFpJkTaj);
#endif
