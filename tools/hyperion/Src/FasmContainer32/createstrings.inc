macro createStringBruteforcing location
{
	 mov [location+0],'B'
	 mov [location+1],'r'
	 mov [location+2],'u'
	 mov [location+3],'t'
	 mov [location+4],'e'
	 mov [location+5],'f'
	 mov [location+6],'o'
	 mov [location+7],'r'
	 mov [location+8],'c'
	 mov [location+9],'i'
	 mov [location+10],'n'
	 mov [location+11],'g'
	 mov [location+12],' '
	 mov [location+13],'K'
	 mov [location+14],'e'
	 mov [location+15],'y'
	 mov [location+16],0
}

macro createStringSettingPermissions location
{
	 mov [location+0],'S'
	 mov [location+1],'e'
	 mov [location+2],'t'
	 mov [location+3],'t'
	 mov [location+4],'i'
	 mov [location+5],'n'
	 mov [location+6],'g'
	 mov [location+7],' '
	 mov [location+8],'S'
	 mov [location+9],'e'
	 mov [location+10],'c'
	 mov [location+11],'t'
	 mov [location+12],'i'
	 mov [location+13],'o'
	 mov [location+14],'n'
	 mov [location+15],' '
	 mov [location+16],'P'
	 mov [location+17],'e'
	 mov [location+18],'r'
	 mov [location+19],'m'
	 mov [location+20],'i'
	 mov [location+21],'s'
	 mov [location+22],'s'
	 mov [location+23],'i'
	 mov [location+24],'o'
	 mov [location+25],'n'
	 mov [location+26],'s'
	 mov [location+27],0
}

macro createStringOrdinal location
{
	 mov [location+0],'O'
	 mov [location+1],'r'
	 mov [location+2],'d'
	 mov [location+3],'i'
	 mov [location+4],'n'
	 mov [location+5],'a'
	 mov [location+6],'l'
	 mov [location+7],':'
	 mov [location+8],' '
	 mov [location+9],0
}

macro createStringName location
{
	 mov [location+0],'N'
	 mov [location+1],'a'
	 mov [location+2],'m'
	 mov [location+3],'e'
	 mov [location+4],':'
	 mov [location+5],' '
	 mov [location+6],0
}

macro createStringProcessImportDirectory location
{
	 mov [location+0],'P'
	 mov [location+1],'r'
	 mov [location+2],'o'
	 mov [location+3],'c'
	 mov [location+4],'e'
	 mov [location+5],'s'
	 mov [location+6],'s'
	 mov [location+7],'i'
	 mov [location+8],'n'
	 mov [location+9],'g'
	 mov [location+10],' '
	 mov [location+11],'I'
	 mov [location+12],'m'
	 mov [location+13],'p'
	 mov [location+14],'o'
	 mov [location+15],'r'
	 mov [location+16],'t'
	 mov [location+17],' '
	 mov [location+18],'D'
	 mov [location+19],'i'
	 mov [location+20],'r'
	 mov [location+21],'e'
	 mov [location+22],'c'
	 mov [location+23],'t'
	 mov [location+24],'o'
	 mov [location+25],'r'
	 mov [location+26],'y'
	 mov [location+27],':'
	 mov [location+28],0
}

macro createStringFoundImportTable location
{
	 mov [location+0],'I'
	 mov [location+1],'m'
	 mov [location+2],'p'
	 mov [location+3],'o'
	 mov [location+4],'r'
	 mov [location+5],'t'
	 mov [location+6],' '
	 mov [location+7],'T'
	 mov [location+8],'a'
	 mov [location+9],'b'
	 mov [location+10],'l'
	 mov [location+11],'e'
	 mov [location+12],':'
	 mov [location+13],0
}

macro createStringLoadingFilesAPIs location
{
	 mov [location+0],'L'
	 mov [location+1],'o'
	 mov [location+2],'a'
	 mov [location+3],'d'
	 mov [location+4],'i'
	 mov [location+5],'n'
	 mov [location+6],'g'
	 mov [location+7],' '
	 mov [location+8],'A'
	 mov [location+9],'P'
	 mov [location+10],'I'
	 mov [location+11],'s'
	 mov [location+12],0
}

macro createStringMappingFileInMemory location
{
	 mov [location+0],'M'
	 mov [location+1],'a'
	 mov [location+2],'p'
	 mov [location+3],'p'
	 mov [location+4],'i'
	 mov [location+5],'n'
	 mov [location+6],'g'
	 mov [location+7],' '
	 mov [location+8],'F'
	 mov [location+9],'i'
	 mov [location+10],'l'
	 mov [location+11],'e'
	 mov [location+12],' '
	 mov [location+13],'i'
	 mov [location+14],'n'
	 mov [location+15],'t'
	 mov [location+16],'o'
	 mov [location+17],' '
	 mov [location+18],'M'
	 mov [location+19],'e'
	 mov [location+20],'m'
	 mov [location+21],'o'
	 mov [location+22],'r'
	 mov [location+23],'y'
	 mov [location+24],0
}

macro createStringLoaded location
{
	 mov [location+0],'L'
	 mov [location+1],'o'
	 mov [location+2],'a'
	 mov [location+3],'d'
	 mov [location+4],'e'
	 mov [location+5],'d'
	 mov [location+6],' '
	 mov [location+7],0
}

macro createStringLoadedPEHeader location
{
	 mov [location+0],'S'
	 mov [location+1],'e'
	 mov [location+2],'t'
	 mov [location+3],' '
	 mov [location+4],'I'
	 mov [location+5],'m'
	 mov [location+6],'a'
	 mov [location+7],'g'
	 mov [location+8],'e'
	 mov [location+9],' '
	 mov [location+10],'w'
	 mov [location+11],'r'
	 mov [location+12],'i'
	 mov [location+13],'t'
	 mov [location+14],'a'
	 mov [location+15],'b'
	 mov [location+16],'l'
	 mov [location+17],'e'
	 mov [location+18],':'
	 mov [location+19],0
}

macro createStringVerifyPE location
{
	 mov [location+0],'V'
	 mov [location+1],'e'
	 mov [location+2],'r'
	 mov [location+3],'i'
	 mov [location+4],'f'
	 mov [location+5],'y'
	 mov [location+6],'i'
	 mov [location+7],'n'
	 mov [location+8],'g'
	 mov [location+9],' '
	 mov [location+10],'P'
	 mov [location+11],'E'
	 mov [location+12],0
}

macro createStringVerifyChecksum location
{
	 mov [location+0],'V'
	 mov [location+1],'e'
	 mov [location+2],'r'
	 mov [location+3],'i'
	 mov [location+4],'f'
	 mov [location+5],'y'
	 mov [location+6],'i'
	 mov [location+7],'n'
	 mov [location+8],'g'
	 mov [location+9],' '
	 mov [location+10],'C'
	 mov [location+11],'h'
	 mov [location+12],'e'
	 mov [location+13],'c'
	 mov [location+14],'k'
	 mov [location+15],'s'
	 mov [location+16],'u'
	 mov [location+17],'m'
	 mov [location+18],0
}

macro createStringDone location
{
	 mov [location+0],'D'
	 mov [location+1],'o'
	 mov [location+2],'n'
	 mov [location+3],'e'
	 mov [location+4],0
}

macro createStringLoading location
{
	 mov [location+0],'L'
	 mov [location+1],'o'
	 mov [location+2],'a'
	 mov [location+3],'d'
	 mov [location+4],'i'
	 mov [location+5],'n'
	 mov [location+6],'g'
	 mov [location+7],' '
	 mov [location+8],'A'
	 mov [location+9],'P'
	 mov [location+10],'I'
	 mov [location+11],'s'
	 mov [location+12],':'
	 mov [location+13],0
}

macro createStringError location
{
	 mov [location+0],'E'
	 mov [location+1],'r'
	 mov [location+2],'r'
	 mov [location+3],'o'
	 mov [location+4],'r'
	 mov [location+5],0
}

macro createStringStartingHyperion location
{
	 mov [location+00],'H'
	 mov [location+01],'y'
	 mov [location+02],'p'
	 mov [location+03],'e'
	 mov [location+04],'r'
	 mov [location+05],'i'
	 mov [location+06],'o'
	 mov [location+07],'n'
	 mov [location+08],' '
	 mov [location+09],'L'
	 mov [location+10],'o'
	 mov [location+11],'g'
	 mov [location+12],'f'
	 mov [location+13],'i'
	 mov [location+14],'l'
	 mov [location+15],'e'
	 mov [location+16],13
	 mov [location+17],10
	 mov [location+18],0
}

macro createStringStartingHyperionLines location
{
	 mov [location+00],'-'
	 mov [location+01],'-'
	 mov [location+02],'-'
	 mov [location+03],'-'
	 mov [location+04],'-'
	 mov [location+05],'-'
	 mov [location+06],'-'
	 mov [location+07],'-'
	 mov [location+08],'-'
	 mov [location+09],'-'
	 mov [location+10],'-'
	 mov [location+11],'-'
	 mov [location+12],'-'
	 mov [location+13],'-'
	 mov [location+14],'-'
	 mov [location+15],'-'
	 mov [location+16],13
	 mov [location+17],10
	 mov [location+18],0
}

macro createStringLogTxt location
{
	 mov [location+0],'l'
	 mov [location+1],'o'
	 mov [location+2],'g'
	 mov [location+3],'.'
	 mov [location+4],'t'
	 mov [location+5],'x'
	 mov [location+6],'t'
	 mov [location+7],0
}

macro createStringKernel32 location
{
	 mov [location+00],'k'
	 mov [location+01],'e'
	 mov [location+02],'r'
	 mov [location+03],'n'
	 mov [location+04],'e'
	 mov [location+05],'l'
	 mov [location+06],'3'
	 mov [location+07],'2'
	 mov [location+08],'.'
	 mov [location+09],'d'
	 mov [location+10],'l'
	 mov [location+11],'l'
	 mov [location+12],0
}

macro  createStringCreateFileMapping location
{
	 mov [location+00],'C'
	 mov [location+01],'r'
	 mov [location+02],'e'
	 mov [location+03],'a'
	 mov [location+04],'t'
	 mov [location+05],'e'
	 mov [location+06],'F'
	 mov [location+07],'i'
	 mov [location+08],'l'
	 mov [location+09],'e'
	 mov [location+10],'M'
	 mov [location+11],'a'
	 mov [location+12],'p'
	 mov [location+13],'p'
	 mov [location+14],'i'
	 mov [location+15],'n'
	 mov [location+16],'g'
	 mov [location+17],'A'
	 mov [location+18],0
}

macro createStringMapViewOfFile location
{
	 mov [location+00],'M'
	 mov [location+01],'a'
	 mov [location+02],'p'
	 mov [location+03],'V'
	 mov [location+04],'i'
	 mov [location+05],'e'
	 mov [location+06],'w'
	 mov [location+07],'O'
	 mov [location+08],'f'
	 mov [location+09],'F'
	 mov [location+10],'i'
	 mov [location+11],'l'
	 mov [location+12],'e'
	 mov [location+13],0
}

macro createStringUnmapViewOfFile location
{
	 mov [location+00],'U'
	 mov [location+01],'n'
	 mov [location+02],'m'
	 mov [location+03],'a'
	 mov [location+04],'p'
	 mov [location+05],'V'
	 mov [location+06],'i'
	 mov [location+07],'e'
	 mov [location+08],'w'
	 mov [location+09],'O'
	 mov [location+10],'f'
	 mov [location+11],'F'
	 mov [location+12],'i'
	 mov [location+13],'l'
	 mov [location+14],'e'
	 mov [location+15],0
}

macro createStringCreateFile location
{
	 mov [location+00],'C'
	 mov [location+01],'r'
	 mov [location+02],'e'
	 mov [location+03],'a'
	 mov [location+04],'t'
	 mov [location+05],'e'
	 mov [location+06],'F'
	 mov [location+07],'i'
	 mov [location+08],'l'
	 mov [location+09],'e'
	 mov [location+10],'A'
	 mov [location+11],0
}

macro createStringCloseHandle location
{
	 mov [location+00],'C'
	 mov [location+01],'l'
	 mov [location+02],'o'
	 mov [location+03],'s'
	 mov [location+04],'e'
	 mov [location+05],'H'
	 mov [location+06],'a'
	 mov [location+07],'n'
	 mov [location+08],'d'
	 mov [location+09],'l'
	 mov [location+10],'e'
	 mov [location+11],0
}

macro createStringGetFileSize location
{
	 mov [location+00],'G'
	 mov [location+01],'e'
	 mov [location+02],'t'
	 mov [location+03],'F'
	 mov [location+04],'i'
	 mov [location+05],'l'
	 mov [location+06],'e'
	 mov [location+07],'S'
	 mov [location+08],'i'
	 mov [location+09],'z'
	 mov [location+10],'e'
	 mov [location+11],0
}

macro createStringDeleteFile location
{
	 mov [location+00],'D'
	 mov [location+01],'e'
	 mov [location+02],'l'
	 mov [location+03],'e'
	 mov [location+04],'t'
	 mov [location+05],'e'
	 mov [location+06],'F'
	 mov [location+07],'i'
	 mov [location+08],'l'
	 mov [location+09],'e'
	 mov [location+10],'A'
	 mov [location+11],0
}

macro createStringGetModuleHandle location
{
	 mov [location+00],'G'
	 mov [location+01],'e'
	 mov [location+02],'t'
	 mov [location+03],'M'
	 mov [location+04],'o'
	 mov [location+05],'d'
	 mov [location+06],'u'
	 mov [location+07],'l'
	 mov [location+08],'e'
	 mov [location+09],'H'
	 mov [location+10],'a'
	 mov [location+11],'n'
	 mov [location+12],'d'
	 mov [location+13],'l'
	 mov [location+14],'e'
	 mov [location+15],'A'
	 mov [location+16],0
}

macro createStringVirtualAlloc location
{
	 mov [location+00],'V'
	 mov [location+01],'i'
	 mov [location+02],'r'
	 mov [location+03],'t'
	 mov [location+04],'u'
	 mov [location+05],'a'
	 mov [location+06],'l'
	 mov [location+07],'A'
	 mov [location+08],'l'
	 mov [location+09],'l'
	 mov [location+10],'o'
	 mov [location+11],'c'
	 mov [location+12],0
}

macro createStringVirtualProtect location
{
	 mov [location+00],'V'
	 mov [location+01],'i'
	 mov [location+02],'r'
	 mov [location+03],'t'
	 mov [location+04],'u'
	 mov [location+05],'a'
	 mov [location+06],'l'
	 mov [location+07],'P'
	 mov [location+08],'r'
	 mov [location+09],'o'
	 mov [location+10],'t'
	 mov [location+11],'e'
	 mov [location+12],'c'
	 mov [location+13],'t'
	 mov [location+14],0
}

macro createStringVirtualFree location
{
	 mov [location+00],'V'
	 mov [location+01],'i'
	 mov [location+02],'r'
	 mov [location+03],'t'
	 mov [location+04],'u'
	 mov [location+05],'a'
	 mov [location+06],'l'
	 mov [location+07],'F'
	 mov [location+08],'r'
	 mov [location+09],'e'
	 mov [location+10],'e'
	 mov [location+11],0
}
