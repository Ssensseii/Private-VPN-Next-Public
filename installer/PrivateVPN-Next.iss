#define MyAppName "PrivateVPN Next"
#define MyAppVersion GetEnv("APP_VERSION")
#define MyAppPublisher "PrivateVPN Next"

[Setup]
AppId={{A21E7B83-7A3A-4C21-9F24-61EAC9B9E62D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\PrivateVPN Next
DefaultGroupName=PrivateVPN Next
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
OutputDir=..\release
OutputBaseFilename=PrivateVPN-Next-Setup
SetupIconFile=..\dist\app.ico
UninstallDisplayIcon={app}\PrivateVPN-Next.exe
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
CloseApplications=force
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Дополнительные ярлыки:"

[Files]
Source: "..\dist\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\PrivateVPN Next"; Filename: "{app}\PrivateVPN-Next.exe"; IconFilename: "{app}\app.ico"; WorkingDir: "{app}"
Name: "{autodesktop}\PrivateVPN Next"; Filename: "{app}\PrivateVPN-Next.exe"; IconFilename: "{app}\app.ico"; Tasks: desktopicon; WorkingDir: "{app}"

[Code]
function GetTickCount: LongWord;
  external 'GetTickCount@kernel32.dll stdcall';

var
  InstallStartedAt: LongWord;

function FormatDuration(Milliseconds: LongWord): String;
var
  TotalSeconds: LongWord;
begin
  TotalSeconds := Milliseconds div 1000;
  Result := Format('%d мин %d сек', [TotalSeconds div 60, TotalSeconds mod 60]);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    InstallStartedAt := GetTickCount;
end;

procedure CurInstallProgressChanged(CurProgress, MaxProgress: Integer);
var
  Elapsed, Remaining: LongWord;
begin
  if (InstallStartedAt = 0) or (MaxProgress <= 0) or (CurProgress <= 0) then
    exit;
  Elapsed := GetTickCount - InstallStartedAt;
  Remaining := (Elapsed * LongWord(MaxProgress - CurProgress)) div LongWord(CurProgress);
  WizardForm.StatusLabel.Caption :=
    'Установка: ' + IntToStr(CurProgress * 100 div MaxProgress) +
    '% · прошло ' + FormatDuration(Elapsed) +
    ' · осталось примерно ' + FormatDuration(Remaining);
end;
