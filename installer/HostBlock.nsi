; HostBlock setup wizard (NSIS 3). Build it with:  python3 installer/build.py
; build.py passes VERSION, ROOT (project folder), RUNTIME (bundled Python) and OUTFILE.
;
; Silent install for IT admins:  Hostblock.setup.exe /S [/NOPROTECT] [/NOWEEKLY] [/NODESKTOP] [/ADMINONLY]
;   /ADMINONLY = turning protection on/off keeps requiring an administrator (e.g. parental control)
;   exit code 0 = OK, 10 = installed but protection could not be turned on,
;             11 = installed but the weekly update could not be set up
; Silent uninstall:              "C:\Program Files\HostBlock\Uninstall.exe" /S
; Running setup again updates HostBlock and keeps the current settings (the options page is skipped).

Unicode true
Target amd64-unicode
ManifestDPIAware true
SetCompressor /SOLID lzma
RequestExecutionLevel admin

!ifndef VERSION | ROOT | RUNTIME | OUTFILE
  !error "Build this installer with installer/build.py"
!endif

!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\HostBlock"
!define ASSETS "${ROOT}/installer/assets"
; Runs hostblock.py with the bundled Python. -I ignores PYTHON* variables and user site-packages.
!define CLI '"$INSTDIR\runtime\python.exe" -I -X utf8 "$INSTDIR\hostblock.py"'
; Setup's own runs log next to the weekly task's log, in the admin-only install folder.
!define LOG '--log "$INSTDIR\hostblock.log"'

Name "HostBlock"
Caption "HostBlock ${VERSION} Setup"
OutFile "${OUTFILE}"
; Fixed, admin-only location: the weekly task runs these files with SYSTEM rights,
; so they must not live anywhere a normal account could change them.
InstallDir "$PROGRAMFILES64\HostBlock"
BrandingText "HostBlock ${VERSION}"
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "HostBlock"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "HostBlock Setup"
VIAddVersionKey "LegalCopyright" "HostBlock contributors"

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinVer.nsh"
!include "FileFunc.nsh"

Var Dialog
Var ChkProtect
Var ChkFakenews
Var ChkGambling
Var ChkPorn
Var ChkSocial
Var ChkWeekly
Var ChkDesktop
Var OptProtect
Var OptFakenews
Var OptGambling
Var OptPorn
Var OptSocial
Var OptWeekly
Var OptDesktop
Var ChkQuick
Var OptQuick
Var FinishText
Var FinishTitle
Var WelcomeText
Var Upgrade
Var ExitCode

; ---------------------------------------------------------------- look & pages
!define MUI_ICON "${ASSETS}/hostblock.ico"
!define MUI_UNICON "${ASSETS}/hostblock.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "${ASSETS}/wizard.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "${ASSETS}/wizard.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
!define MUI_HEADERIMAGE_BITMAP "${ASSETS}/header.bmp"
!define MUI_HEADERIMAGE_UNBITMAP "${ASSETS}/header.bmp"
!define MUI_ABORTWARNING

!define MUI_WELCOMEPAGE_TITLE "Welcome to HostBlock"
!define MUI_WELCOMEPAGE_TEXT "$WelcomeText"
!insertmacro MUI_PAGE_WELCOME

Page custom OptionsPage OptionsPageLeave

!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_TITLE "$FinishTitle"
!define MUI_FINISHPAGE_TEXT "$FinishText"
!define MUI_FINISHPAGE_TEXT_LARGE
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Open HostBlock now"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchApp
!insertmacro MUI_PAGE_FINISH

!define MUI_UNCONFIRMPAGE_TEXT_TOP "HostBlock will be removed from this computer. Your hosts file will be put back exactly as it was before HostBlock, and the weekly update will be removed."
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ---------------------------------------------------------------- start-up checks
Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "HostBlock needs 64-bit Windows." /SD IDOK
    Abort
  ${EndIf}
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_ICONSTOP "HostBlock needs Windows 10 or newer." /SD IDOK
    Abort
  ${EndIf}
  SetRegView 64
  ; Always the admin-only folder, even if /D= was given: the weekly task runs these files as SYSTEM.
  StrCpy $INSTDIR "$PROGRAMFILES64\HostBlock"

  StrCpy $Upgrade 0
  StrCpy $FinishTitle "HostBlock is installed"
  StrCpy $WelcomeText "HostBlock blocks ads, trackers and harmful websites on this computer, in every browser and app.$\r$\n$\r$\nIt adds a well-known list of ad and tracking sites (StevenBlack's hosts list) to your computer's hosts file. Your original file is backed up first, and you can undo everything at any time.$\r$\n$\r$\nClick Next to continue."
  ${If} ${FileExists} "$INSTDIR\hostblock.py"
    StrCpy $Upgrade 1
    StrCpy $FinishTitle "HostBlock is updated"
    StrCpy $WelcomeText "HostBlock is already installed on this computer. Setup will update it to version ${VERSION} and keep your current settings.$\r$\n$\r$\nTo change settings afterwards, use the HostBlock window.$\r$\n$\r$\nClick Next to continue."
  ${EndIf}

  StrCpy $OptProtect ${BST_CHECKED}
  StrCpy $OptWeekly ${BST_CHECKED}
  StrCpy $OptDesktop ${BST_CHECKED}
  StrCpy $OptQuick ${BST_CHECKED}
  StrCpy $OptFakenews ${BST_UNCHECKED}
  StrCpy $OptGambling ${BST_UNCHECKED}
  StrCpy $OptPorn ${BST_UNCHECKED}
  StrCpy $OptSocial ${BST_UNCHECKED}

  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/NOPROTECT" $R1
  ${IfNot} ${Errors}
    StrCpy $OptProtect ${BST_UNCHECKED}
  ${EndIf}
  ClearErrors
  ${GetOptions} $R0 "/NOWEEKLY" $R1
  ${IfNot} ${Errors}
    StrCpy $OptWeekly ${BST_UNCHECKED}
  ${EndIf}
  ClearErrors
  ${GetOptions} $R0 "/NODESKTOP" $R1
  ${IfNot} ${Errors}
    StrCpy $OptDesktop ${BST_UNCHECKED}
  ${EndIf}
  ClearErrors
  ${GetOptions} $R0 "/ADMINONLY" $R1
  ${IfNot} ${Errors}
    StrCpy $OptQuick ${BST_UNCHECKED}
  ${EndIf}
FunctionEnd

; The HostBlock window must be closed while its files are replaced or removed.
Function CheckAppRunning
  retry:
  FindWindow $0 "TkTopLevel" "HostBlock"
  ${If} $0 <> 0
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "Please close the HostBlock window, then click Retry." /SD IDCANCEL IDRETRY retry
    Abort
  ${EndIf}
FunctionEnd

Function un.CheckAppRunning
  retry:
  FindWindow $0 "TkTopLevel" "HostBlock"
  ${If} $0 <> 0
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "Please close the HostBlock window, then click Retry." /SD IDCANCEL IDRETRY retry
    Abort
  ${EndIf}
FunctionEnd

; ---------------------------------------------------------------- "Choose your protection" page
Function OptionsPage
  ${If} $Upgrade == 1
    Abort  ; updating: keep the current settings, change them in the HostBlock window
  ${EndIf}
  !insertmacro MUI_HEADER_TEXT "Choose your protection" "You can change all of this later in the HostBlock window."
  nsDialogs::Create 1018
  Pop $Dialog
  ${If} $Dialog == error
    Abort
  ${EndIf}

  ${NSD_CreateCheckbox} 0 0 100% 12u "&Turn on protection when setup finishes (downloads the latest list)"
  Pop $ChkProtect
  ${NSD_SetState} $ChkProtect $OptProtect
  ${NSD_OnClick} $ChkProtect OnProtectClick

  ${NSD_CreateGroupBox} 0 15u 100% 45u "Also block"
  Pop $0
  ${NSD_CreateCheckbox} 10u 27u 44% 12u "&Fake news sites"
  Pop $ChkFakenews
  ${NSD_SetState} $ChkFakenews $OptFakenews
  ${NSD_CreateCheckbox} 54% 27u 42% 12u "&Gambling sites"
  Pop $ChkGambling
  ${NSD_SetState} $ChkGambling $OptGambling
  ${NSD_CreateCheckbox} 10u 42u 44% 12u "&Adult content"
  Pop $ChkPorn
  ${NSD_SetState} $ChkPorn $OptPorn
  ${NSD_CreateCheckbox} 54% 42u 42% 12u "&Social media"
  Pop $ChkSocial
  ${NSD_SetState} $ChkSocial $OptSocial

  ${NSD_CreateCheckbox} 0 65u 100% 12u "&Keep the list up to date automatically (every Sunday)"
  Pop $ChkWeekly
  ${NSD_SetState} $ChkWeekly $OptWeekly
  ${NSD_CreateCheckbox} 0 79u 100% 20u "&Let anyone using this PC turn protection on or off without an administrator password (untick this for parental control)"
  Pop $ChkQuick
  ${NSD_SetState} $ChkQuick $OptQuick
  ${NSD_CreateCheckbox} 0 101u 100% 12u "Create a &desktop shortcut"
  Pop $ChkDesktop
  ${NSD_SetState} $ChkDesktop $OptDesktop

  ${NSD_CreateLabel} 0 120u 100% 12u "Your current hosts file is backed up before anything changes."
  Pop $0

  Call UpdateCategoryState
  ${NSD_OnBack} OptionsPageLeave       ; keep the choices when the user goes Back
  nsDialogs::Show
FunctionEnd

Function OnProtectClick
  Pop $0
  Call UpdateCategoryState
FunctionEnd

Function UpdateCategoryState
  ${NSD_GetState} $ChkProtect $0
  ${If} $0 == ${BST_CHECKED}
    StrCpy $1 1
  ${Else}
    StrCpy $1 0
  ${EndIf}
  EnableWindow $ChkFakenews $1
  EnableWindow $ChkGambling $1
  EnableWindow $ChkPorn $1
  EnableWindow $ChkSocial $1
FunctionEnd

Function OptionsPageLeave
  ${NSD_GetState} $ChkProtect $OptProtect
  ${NSD_GetState} $ChkFakenews $OptFakenews
  ${NSD_GetState} $ChkGambling $OptGambling
  ${NSD_GetState} $ChkPorn $OptPorn
  ${NSD_GetState} $ChkSocial $OptSocial
  ${NSD_GetState} $ChkWeekly $OptWeekly
  ${NSD_GetState} $ChkDesktop $OptDesktop
  ${NSD_GetState} $ChkQuick $OptQuick
FunctionEnd

; Background tasks that let any signed-in user turn protection on/off (see hostblock.py install-tasks).
Function ApplyQuickToggle   ; $OptQuick = BST_CHECKED to allow, otherwise remove
  ${If} $OptQuick == ${BST_CHECKED}
    DetailPrint "Letting everyone on this PC turn protection on or off..."
    nsExec::ExecToLog '${CLI} install-tasks ${LOG}'
    Pop $0
    ${If} $0 != 0
      DetailPrint "The on/off tasks could not be set up (exit code $0)."
      MessageBox MB_ICONEXCLAMATION "HostBlock couldn't set up turning protection on or off without an administrator password, so the HostBlock window will ask for one." /SD IDOK
    ${EndIf}
    WriteRegDWORD HKLM "${UNINST_KEY}" "QuickToggle" 1
  ${Else}
    nsExec::ExecToLog '${CLI} remove-tasks ${LOG}'
    Pop $0
    WriteRegDWORD HKLM "${UNINST_KEY}" "QuickToggle" 0
  ${EndIf}
FunctionEnd

Function LaunchApp
  Exec '"$INSTDIR\runtime\pythonw.exe" -I "$INSTDIR\HostBlock.pyw"'
FunctionEnd

; ---------------------------------------------------------------- install
Section "HostBlock" SecMain
  SetShellVarContext all
  SetRegView 64
  Call CheckAppRunning

  SetOutPath "$INSTDIR"
  File "${ROOT}/hostblock.py"
  File "${ROOT}/HostBlock.pyw"
  File "${ROOT}/README.md"
  File "${ROOT}/LICENSE"
  File "${ROOT}/THIRD-PARTY-NOTICES.md"
  File "${ASSETS}/hostblock.ico"
  RMDir /r "$INSTDIR\__pycache__"
  DetailPrint "Installing HostBlock's private copy of Python..."
  SetDetailsPrint textonly             ; don't list ~900 individual files
  RMDir /r "$INSTDIR\runtime"          ; fresh runtime on upgrade
  SetOutPath "$INSTDIR\runtime"
  File /r "${RUNTIME}/*"
  SetOutPath "$INSTDIR"
  SetDetailsPrint both

  WriteUninstaller "$INSTDIR\Uninstall.exe"

  CreateShortCut "$SMPROGRAMS\HostBlock.lnk" "$INSTDIR\runtime\pythonw.exe" '-I "$INSTDIR\HostBlock.pyw"' \
      "$INSTDIR\hostblock.ico" 0 SW_SHOWNORMAL "" "Turn ad and tracker blocking on or off"
  ${If} $Upgrade == 1
    ${If} ${FileExists} "$DESKTOP\HostBlock.lnk"
      StrCpy $OptDesktop ${BST_CHECKED}  ; refresh the existing one
    ${Else}
      StrCpy $OptDesktop ${BST_UNCHECKED}
    ${EndIf}
  ${EndIf}
  ${If} $OptDesktop == ${BST_CHECKED}
    CreateShortCut "$DESKTOP\HostBlock.lnk" "$INSTDIR\runtime\pythonw.exe" '-I "$INSTDIR\HostBlock.pyw"' \
        "$INSTDIR\hostblock.ico" 0 SW_SHOWNORMAL "" "Turn ad and tracker blocking on or off"
  ${EndIf}

  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "HostBlock"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "HostBlock"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\hostblock.ico"
  WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
  SetDetailsPrint none                 ; GetSize logs its progress otherwise
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  SetDetailsPrint both
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize" "$0"

  ${If} $Upgrade == 1
    ; Keep the user's settings: 'update' re-applies the stored list and options (and does
    ; nothing while protection is off); an existing weekly task already points at these files.
    DetailPrint "Refreshing the blocklist with your current settings..."
    nsExec::ExecToLog '${CLI} update ${LOG}'
    Pop $0
    StrCpy $FinishText "HostBlock has been updated to version ${VERSION}. Your settings were kept."
    ${If} $0 != 0
      StrCpy $FinishText "$FinishText$\r$\n$\r$\nThe blocklist could not be refreshed right now (no internet connection?). Use 'Update now' in HostBlock later."
    ${EndIf}
    ; Keep the earlier on/off choice; versions before 1.3.0 had none, so they get the default (allowed).
    ClearErrors
    ReadRegDWORD $2 HKLM "${UNINST_KEY}" "QuickToggle"
    ${If} ${Errors}
    ${OrIf} $2 == 1
      StrCpy $OptQuick ${BST_CHECKED}
    ${Else}
      StrCpy $OptQuick ${BST_UNCHECKED}
    ${EndIf}
    Call ApplyQuickToggle
    Return
  ${EndIf}

  ; First install: apply the choices from the "Choose your protection" page.
  StrCpy $ExitCode 0
  StrCpy $FinishText "HostBlock is installed. Open it from the Start menu to turn protection on or off."
  ${If} $OptProtect == ${BST_CHECKED}
    StrCpy $1 ""
    ${If} $OptFakenews == ${BST_CHECKED}
      StrCpy $1 "$1 fakenews"
    ${EndIf}
    ${If} $OptGambling == ${BST_CHECKED}
      StrCpy $1 "$1 gambling"
    ${EndIf}
    ${If} $OptPorn == ${BST_CHECKED}
      StrCpy $1 "$1 porn"
    ${EndIf}
    ${If} $OptSocial == ${BST_CHECKED}
      StrCpy $1 "$1 social"
    ${EndIf}
    ${If} $1 != ""
      StrCpy $1 " --extensions$1"
    ${EndIf}
    DetailPrint "Downloading the latest blocklist and turning on protection..."
    nsExec::ExecToLog '${CLI} block --compact$1 ${LOG}'
    Pop $0
    ${If} $0 == 0
      StrCpy $FinishText "Protection is ON: ads and trackers are now blocked on this computer.$\r$\n$\r$\nTo change settings or turn it off, open HostBlock from the Start menu."
    ${Else}
      DetailPrint "Protection could not be turned on (exit code $0)."
      StrCpy $FinishText "HostBlock is installed, but protection could not be turned on right now (usually there is no internet connection).$\r$\n$\r$\nOpen HostBlock and click 'Turn protection ON' to try again."
      StrCpy $ExitCode 10
    ${EndIf}
  ${EndIf}
  ${If} $OptWeekly == ${BST_CHECKED}
    DetailPrint "Setting up the weekly update..."
    nsExec::ExecToLog '${CLI} schedule ${LOG}'
    Pop $0
    ${If} $0 != 0
      DetailPrint "The weekly update could not be set up (exit code $0)."
      MessageBox MB_ICONEXCLAMATION "The weekly update could not be set up. You can turn it on later in the HostBlock window." /SD IDOK
      ${If} $ExitCode == 0
        StrCpy $ExitCode 11
      ${EndIf}
    ${EndIf}
  ${EndIf}
  Call ApplyQuickToggle
  ${If} $ExitCode != 0
    SetErrorLevel $ExitCode   ; lets silent deployments see that setup was incomplete
  ${EndIf}
SectionEnd

; ---------------------------------------------------------------- uninstall
Section "Uninstall"
  SetShellVarContext all
  SetRegView 64
  Call un.CheckAppRunning

  DetailPrint "Putting the hosts file back the way it was before HostBlock..."
  nsExec::ExecToLog '${CLI} restore'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_YESNO|MB_ICONEXCLAMATION "HostBlock could not undo its changes to the hosts file automatically (see the details list).$\r$\n$\r$\nRemove HostBlock anyway?" /SD IDYES IDYES +2
    Abort
  ${EndIf}
  nsExec::ExecToLog '${CLI} unschedule'
  Pop $0
  nsExec::ExecToLog '${CLI} remove-tasks'
  Pop $0
  Delete "$SYSDIR\drivers\etc\hosts.hostblock-lock"

  Delete "$SMPROGRAMS\HostBlock.lnk"
  Delete "$DESKTOP\HostBlock.lnk"
  DetailPrint "Removing HostBlock's files..."
  SetDetailsPrint textonly
  RMDir /r "$INSTDIR\runtime"
  SetDetailsPrint both
  RMDir /r "$INSTDIR\__pycache__"
  Delete "$INSTDIR\hostblock.py"
  Delete "$INSTDIR\HostBlock.pyw"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\THIRD-PARTY-NOTICES.md"
  Delete "$INSTDIR\hostblock.ico"
  Delete "$INSTDIR\schedule.txt"
  Delete "$INSTDIR\task.xml"
  Delete "$INSTDIR\hostblock.log"
  Delete "$INSTDIR\hostblock.log.old"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINST_KEY}"
SectionEnd
