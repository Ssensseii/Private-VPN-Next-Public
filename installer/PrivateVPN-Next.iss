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
