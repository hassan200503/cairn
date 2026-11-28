; Inno Setup script for the Cairn flashing workbench.
;
; The installer ships the PyInstaller onefile console build (dist\cairn.exe).
; It installs per-user (no admin), adds the install directory to the user PATH,
; and creates a "Cairn Workbench" shortcut that opens the local dashboard.

#define CairnName "Cairn"
; The onefile exe carries no Windows version resource; the build script passes
; /DCairnVersion=<version from pyproject> explicitly.
#ifndef CairnVersion
#define CairnVersion "0.0.0-dev"
#endif
#define CairnPublisher "Cairn contributors"
#define CairnExe "cairn.exe"

[Setup]
AppId={{B7E3C2D1-4A58-4F0E-9C6B-1A2B3C4D5E6F}
AppName={#CairnName}
AppVersion={#CairnVersion}
AppPublisher={#CairnPublisher}
DefaultDirName={localappdata}\Programs\Cairn
DefaultGroupName={#CairnName}
DisableProgramGroupPage=yes
OutputBaseFilename=CairnSetup-{#CairnVersion}
OutputDir=installer
Compression=lzma2/max
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
UninstallDisplayIcon={app}\{#CairnExe}
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "addpath"; Description: "Add Cairn to the user PATH (recommended)"; \
    Flags: checkedonce

[Files]
Source: "dist\cairn.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Cairn Workbench"; Filename: "{app}\{#CairnExe}"; \
    Parameters: "ui"; Comment: "Open the Cairn local workbench dashboard"
Name: "{group}\Uninstall Cairn"; Filename: "{uninstallexe}"

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; \
    ValueData: "{olddata};{app}"; Tasks: addpath; \
    Check: NeedsAddPath('{app}')

[Run]
Filename: "{app}\{#CairnExe}"; Parameters: "version"; \
    Description: "Print the installed Cairn version"; \
    Flags: postinstall skipifsilent runasoriginaluser
Filename: "{app}\{#CairnExe}"; Parameters: "ui"; \
    Description: "Launch the Cairn workbench dashboard"; \
    Flags: postinstall skipifsilent runasoriginaluser nowait

[UninstallDelete]
; Sessions, vaults, and journals are user data; they are deliberately kept.
; Nothing else is written outside {app}.

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
  InstallDir: string;
begin
  InstallDir := ExpandConstant(Param);
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(InstallDir) + ';',
    ';' + Uppercase(OrigPath) + ';') = 0;
end;
