#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <ctime>

using namespace std;

// TDM-GCC Fixes for missing security macro definitions
#ifndef SECURITY_BUILTIN_DOMAIN_RELATIVE_ID
#define SECURITY_BUILTIN_DOMAIN_RELATIVE_ID (0x00000020L)
#endif
#ifndef DOMAIN_ALIAS_RA_ADMIN
#define DOMAIN_ALIAS_RA_ADMIN (0x00000220L)
#endif

// UI Component Resource Identifiers (13 Action Buttons Total!)
#define IDC_COMBO_DRIVES  101
#define IDC_BTN_REFRESH   102
#define IDC_EDIT_INPUT    103
#define IDC_EDIT_LOG      104

// Core Operations
#define IDC_BTN_WRITE     105
#define IDC_BTN_READ      106
#define IDC_BTN_FORMAT    107
#define IDC_BTN_OPENDIR   108
#define IDC_BTN_CLEARLOG  109

// Data Generator Controls
#define IDC_BTN_ZEROOUT   110
#define IDC_BTN_FILL255   111
#define IDC_BTN_RANDOM    112
#define IDC_BTN_INVERT    113

// Clipboard & File I/O
#define IDC_BTN_COPYHEX   114
#define IDC_BTN_PASTEHEX  115
#define IDC_BTN_SAVEFILE  116
#define IDC_BTN_LOADFILE  117

// Hardware Utilities
#define IDC_BTN_DRIVEINFO 118
#define IDC_BTN_VERIFY    119

// Global Interface Handles
HWND hComboDrives, hBtnRefresh, hEditInput, hEditLog;
HWND hBtnWrite, hBtnRead, hBtnFormat, hBtnOpenDir, hBtnClearLog;
HWND hBtnZeroOut, hBtnFill255, hBtnRandom, hBtnInvert;
HWND hBtnCopyHex, hBtnPasteHex, hBtnSaveFile, hBtnLoadFile;
HWND hBtnDriveInfo, hBtnVerify;
HWND hStatic1, hStatic2, hStatic3; 

vector<char> activeDrives;
BYTE lastReadBuffer[32] = {0}; // Tracks the last byte stream read from device

// Verifies if the process possesses Administrator clearance token
bool IsRunAsAdmin() {
    BOOL fIsAdmin = FALSE;
    PSID AdministratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RELATIVE_ID,
        DOMAIN_ALIAS_RA_ADMIN, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &fIsAdmin);
        FreeSid(AdministratorsGroup);
    }
    return fIsAdmin != FALSE;
}

// Restarts application instance triggering the native Windows UAC escalation
void ElevateToAdmin() {
    char szPath[MAX_PATH];
    if (GetModuleFileNameA(NULL, szPath, MAX_PATH)) {
        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.cbSize = sizeof(sei);
        sei.lpVerb = "runas"; 
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;
        if (ShellExecuteExA(&sei)) {
            ExitProcess(0); 
        }
    }
}

// Appends message streams to the multi-line edit terminal console
void AppendLog(const string& text) {
    int length = GetWindowTextLengthA(hEditLog);
    SendMessageA(hEditLog, EM_SETSEL, length, length);
    SendMessageA(hEditLog, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
}

// Scans storage pathways filtering solely external/removable storage keys
vector<char> GetExternalDrives() {
    vector<char> externalDrives;
    char buffer[256];
    DWORD size = GetLogicalDriveStringsA(sizeof(buffer), buffer);

    if (size == 0 || size > sizeof(buffer)) return externalDrives;

    char* drive = buffer;
    while (*drive) {
        UINT driveType = GetDriveTypeA(drive);
        if (driveType == DRIVE_REMOVABLE) {
            externalDrives.push_back(drive[0]); 
        }
        drive += strlen(drive) + 1;
    }
    return externalDrives;
}
// Re-scans and populates dropdown items dynamically
void RefreshDriveList() {
    SendMessage(hComboDrives, CB_RESETCONTENT, 0, 0);
    activeDrives = GetExternalDrives();

    if (activeDrives.empty()) {
        SendMessageA(hComboDrives, CB_ADDSTRING, 0, (LPARAM)"No USB drives detected");
        SendMessage(hComboDrives, CB_SETCURSEL, 0, 0);
        EnableWindow(hBtnWrite, FALSE);
        EnableWindow(hBtnRead, FALSE);
        EnableWindow(hBtnFormat, FALSE);
        EnableWindow(hBtnOpenDir, FALSE);
        EnableWindow(hBtnDriveInfo, FALSE);
        EnableWindow(hBtnVerify, FALSE);
        return;
    }

    for (char letter : activeDrives) {
        string driveStr = "Drive ";
        driveStr += letter;
        driveStr += ":";
        SendMessageA(hComboDrives, CB_ADDSTRING, 0, (LPARAM)driveStr.c_str());
    }
    SendMessage(hComboDrives, CB_SETCURSEL, 0, 0);
    EnableWindow(hBtnWrite, TRUE);
    EnableWindow(hBtnRead, TRUE);
    EnableWindow(hBtnFormat, TRUE);
    EnableWindow(hBtnOpenDir, TRUE);
    EnableWindow(hBtnDriveInfo, TRUE);
    EnableWindow(hBtnVerify, TRUE);
}

// Generates a path to a hidden system file on the target USB drive
string GetShadowFilePath(char driveLetter) {
    string path = "";
    path += driveLetter;
    path += ":\\.shadow_bytes.dat";
    return path;
}

// GUI Window Procedure (Message Processing & Auto-Scaling Layout Grid)
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wp, LPARAM lp) {
    switch (uMsg) {
        case WM_CREATE: {
            srand(static_cast<unsigned int>(time(NULL)));
            HFONT hFont = CreateFontA(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");

            // Create window labels
            hStatic1 = CreateWindowA("STATIC", "Select USB Drive:", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, NULL, NULL, NULL);
            hStatic2 = CreateWindowA("STATIC", "Enter exactly 32 bytes (0-255 separated by space):", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, NULL, NULL, NULL);
            hStatic3 = CreateWindowA("STATIC", "Output Dashboard Terminal / Operations Log:", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, NULL, NULL, NULL);

            // Interactive ComboBox & text lines
            hComboDrives = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST, 0, 0, 0, 0, hwnd, (HMENU)IDC_COMBO_DRIVES, NULL, NULL);
            hEditInput = CreateWindowA("EDIT", "72 69 76 76 79 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, (HMENU)IDC_EDIT_INPUT, NULL, NULL);
            hEditLog = CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 0, 0, 0, 0, hwnd, (HMENU)IDC_EDIT_LOG, NULL, NULL);

            // Row 1 Buttons: Core Operations
            hBtnWrite = CreateWindowA("BUTTON", "WRITE TO USB", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_WRITE, NULL, NULL);
            hBtnRead = CreateWindowA("BUTTON", "READ FROM USB", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_READ, NULL, NULL);
            hBtnFormat = CreateWindowA("BUTTON", "FORMAT USB", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_FORMAT, NULL, NULL);
            hBtnOpenDir = CreateWindowA("BUTTON", "OPEN USB FOLDER", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_OPENDIR, NULL, NULL);
            hBtnClearLog = CreateWindowA("BUTTON", "CLEAR LOGS", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_CLEARLOG, NULL, NULL);

            // Row 2 Buttons: Data Generator Tools
            hBtnZeroOut = CreateWindowA("BUTTON", "ZERO OUT (0)", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_ZEROOUT, NULL, NULL);
            hBtnFill255 = CreateWindowA("BUTTON", "FILL MAX (255)", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_FILL255, NULL, NULL);
            hBtnRandom = CreateWindowA("BUTTON", "GEN RANDOM", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_RANDOM, NULL, NULL);
            hBtnInvert = CreateWindowA("BUTTON", "INVERT BITS", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_INVERT, NULL, NULL);

            // Row 3 Buttons: Clipboard & Files
            hBtnCopyHex = CreateWindowA("BUTTON", "COPY HEX", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_COPYHEX, NULL, NULL);
            hBtnPasteHex = CreateWindowA("BUTTON", "PASTE HEX", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_PASTEHEX, NULL, NULL);
            hBtnSaveFile = CreateWindowA("BUTTON", "EXPORT FILE", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_SAVEFILE, NULL, NULL);
            hBtnLoadFile = CreateWindowA("BUTTON", "IMPORT FILE", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_LOADFILE, NULL, NULL);

            // Row 4 Buttons: Hardware Tools
            hBtnDriveInfo = CreateWindowA("BUTTON", "DRIVE HEALTH INFO", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_DRIVEINFO, NULL, NULL);
            hBtnVerify = CreateWindowA("BUTTON", "VERIFY INTEGRITY", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_VERIFY, NULL, NULL);
            hBtnRefresh = CreateWindowA("BUTTON", "REFRESH DISKS", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_REFRESH, NULL, NULL);

            // Apply font variables cleanly
            EnumChildWindows(hwnd, [](HWND child, LPARAM font) -> BOOL {
                SendMessage(child, WM_SETFONT, font, TRUE);
                return TRUE;
            }, (LPARAM)hFont);

            RefreshDriveList();
            AppendLog("Ultimate Super-Tool Dashboard Started. Matrix unrolled.\r\n");
            break;
        }

        case WM_SIZE: {
            // Adaptive Grid Scaling Calculations
            int width = LOWORD(lp);
            int height = HIWORD(lp);
            int padding = 15;
            int usableWidth = width - (padding * 2);

            // Top Configuration Bars
            MoveWindow(hStatic1, padding, 15, 150, 20, TRUE);
            MoveWindow(hComboDrives, padding, 35, usableWidth, 200, TRUE);

            MoveWindow(hStatic2, padding, 70, usableWidth, 200, TRUE);
            MoveWindow(hEditInput, padding, 90, usableWidth, 25, TRUE);

            // Compute Button Row Layout positions dynamically
            int btnH = 30;
            int r1Y = 125, r2Y = 160, r3Y = 195, r4Y = 230;

            // Row 1 split (5 buttons)
            int w5 = usableWidth / 5;
            MoveWindow(hBtnWrite,     padding + (w5 * 0), r1Y, w5 - 5, btnH, TRUE);
            MoveWindow(hBtnRead,      padding + (w5 * 1), r1Y, w5 - 5, btnH, TRUE);
            MoveWindow(hBtnFormat,    padding + (w5 * 2), r1Y, w5 - 5, btnH, TRUE);
            MoveWindow(hBtnOpenDir,   padding + (w5 * 3), r1Y, w5 - 5, btnH, TRUE);
            MoveWindow(hBtnClearLog,  padding + (w5 * 4), r1Y, w5,     btnH, TRUE);

            // Row 2 split (4 buttons)
            int w4 = usableWidth / 4;
            MoveWindow(hBtnZeroOut,   padding + (w4 * 0), r2Y, w4 - 5, btnH, TRUE);
            MoveWindow(hBtnFill255,   padding + (w4 * 1), r2Y, w4 - 5, btnH, TRUE);
            MoveWindow(hBtnRandom,    padding + (w4 * 2), r2Y, w4 - 5, btnH, TRUE);
            MoveWindow(hBtnInvert,    padding + (w4 * 3), r2Y, w4,     btnH, TRUE);

            // Row 3 split (4 buttons)
            MoveWindow(hBtnCopyHex,   padding + (w4 * 0), r3Y, w4 - 5, btnH, TRUE);
            MoveWindow(hBtnPasteHex,  padding + (w4 * 1), r3Y, w4 - 5, btnH, TRUE);
            MoveWindow(hBtnSaveFile,  padding + (w4 * 2), r3Y, w4 - 5, btnH, TRUE);
            MoveWindow(hBtnLoadFile,  padding + (w4 * 3), r3Y, w4,     btnH, TRUE);

            // Row 4 split (3 buttons)
            int w3 = usableWidth / 3;
            MoveWindow(hBtnDriveInfo, padding + (w3 * 0), r4Y, w3 - 5, btnH, TRUE);
            MoveWindow(hBtnVerify,    padding + (w3 * 1), r4Y, w3 - 5, btnH, TRUE);
            MoveWindow(hBtnRefresh,   padding + (w3 * 2), r4Y, w3,     btnH, TRUE);

            // Bottom Log console stretches to match window adjustments
            int logY = 285;
            MoveWindow(hStatic3, padding, logY - 20, usableWidth, 20, TRUE);
            MoveWindow(hEditLog, padding, logY, usableWidth, height - logY - padding, TRUE);
            break;
        }
        case WM_COMMAND: {
            int wmId = LOWORD(wp);
            
            // Core Operational Logic
            if (wmId == IDC_BTN_REFRESH) {
                RefreshDriveList();
                AppendLog("Drive list refreshed.\r\n");
            } 
            else if (wmId == IDC_BTN_WRITE) {
                int index = SendMessage(hComboDrives, CB_GETCURSEL, 0, 0);
                if (index == CB_ERR || activeDrives.empty()) return 0;
                char targetDrive = activeDrives[index];

                char inputBuf[1024] = {0};
                GetWindowTextA(hEditInput, inputBuf, sizeof(inputBuf) - 1);
                
                stringstream ss(inputBuf);
                vector<BYTE> userBytes;
                int tempByte;
                while (ss >> tempByte) {
                    if (tempByte >= 0 && tempByte <= 255) userBytes.push_back(static_cast<BYTE>(tempByte));
                }

                if (userBytes.size() != 32) {
                    MessageBoxA(hwnd, "Error: You must type exactly 32 bytes!", "Invalid Sequence", MB_ICONERROR);
                    return 0;
                }

                string filePath = GetShadowFilePath(targetDrive);
                SetFileAttributesA(filePath.c_str(), FILE_ATTRIBUTE_NORMAL);

                HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD written;
                    WriteFile(hFile, userBytes.data(), 32, &written, NULL);
                    CloseHandle(hFile);
                    SetFileAttributesA(filePath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                    AppendLog("SUCCESS: 32 bytes committed to Drive " + string(1, targetDrive) + ":\r\n");
                }
            } 
            else if (wmId == IDC_BTN_READ) {
                int index = SendMessage(hComboDrives, CB_GETCURSEL, 0, 0);
                if (index == CB_ERR || activeDrives.empty()) return 0;
                char targetDrive = activeDrives[index];

                string filePath = GetShadowFilePath(targetDrive);
                memset(lastReadBuffer, 0, 32);

                HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD read;
                    ReadFile(hFile, lastReadBuffer, 32, &read, NULL);
                    CloseHandle(hFile);
                }

                AppendLog("\r\n--- READ DATA FROM DRIVE " + string(1, targetDrive) + ": ---\r\n");
                stringstream ssDec, ssHex;
                ssDec << "Decimal: "; ssHex << "Hex:     ";
                for (int i = 0; i < 32; i++) {
                    ssDec << (int)lastReadBuffer[i] << " ";
                    ssHex << hex << setw(2) << setfill('0') << (int)lastReadBuffer[i] << " ";
                }
                AppendLog(ssDec.str() + "\r\n" + ssHex.str() + "\r\n");
            }
            else if (wmId == IDC_BTN_FORMAT) {
                int index = SendMessage(hComboDrives, CB_GETCURSEL, 0, 0);
                if (index == CB_ERR || activeDrives.empty()) return 0;
                char targetDrive = activeDrives[index];

                if (MessageBoxA(hwnd, "Confirm format wipe command?", "Wipe Notification", MB_YESNO | MB_ICONWARNING) == IDYES) {
                    AppendLog("Formatting storage target... Please wait...\r\n");
                    UpdateWindow(hwnd);
                    string cmd = "C:\\Windows\\System32\\cmd.exe /c format " + string(1, targetDrive) + ": /fs:fat32 /q /y";
                    STARTUPINFOA si = { sizeof(si) }; PROCESS_INFORMATION pi;
                    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
                    vector<char> cmdBuf(cmd.begin(), cmd.end()); cmdBuf.push_back('\0');

                    if (CreateProcessA(NULL, cmdBuf.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                        WaitForSingleObject(pi.hProcess, INFINITE);
                        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                        AppendLog("SUCCESS: Storage device reset via structural FAT32 clear block.\r\n");
                    }
                }
            }
            else if (wmId == IDC_BTN_OPENDIR) {
                int index = SendMessage(hComboDrives, CB_GETCURSEL, 0, 0);
                if (index == CB_ERR || activeDrives.empty()) return 0;
                string dPath = string(1, activeDrives[index]) + ":\\";
                ShellExecuteA(hwnd, "open", dPath.c_str(), NULL, NULL, SW_SHOW);
                AppendLog("Opened Explorer root frame targeting " + dPath + "\r\n");
            }
            else if (wmId == IDC_BTN_CLEARLOG) {
                SetWindowTextA(hEditLog, "");
            }
            
            // Data Generator Controls Block
            else if (wmId == IDC_BTN_ZEROOUT) {
                SetWindowTextA(hEditInput, "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0");
                AppendLog("Input field initialized to a zero matrix (0x00).\r\n");
            }
            else if (wmId == IDC_BTN_FILL255) {
                SetWindowTextA(hEditInput, "255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255");
                AppendLog("Input field initialized to a high saturation block (0xFF).\r\n");
            }
            else if (wmId == IDC_BTN_RANDOM) {
                stringstream ss;
                for(int i=0; i<32; i++) ss << (rand() % 256) << (i < 31 ? " " : "");
                SetWindowTextA(hEditInput, ss.str().c_str());
                AppendLog("Generated random white-noise entropy stream into text buffer.\r\n");
            }
            else if (wmId == IDC_BTN_INVERT) {
                char inputBuf[1024] = {0}; GetWindowTextA(hEditInput, inputBuf, 1023);
                stringstream ssIn(inputBuf), ssOut; int val; vector<int> vals;
                while(ssIn >> val) { if(val>=0 && val<=255) vals.push_back(255 - val); }
                for(size_t i=0; i<vals.size(); i++) ssOut << vals[i] << (i < vals.size()-1 ? " " : "");
                SetWindowTextA(hEditInput, ssOut.str().c_str());
                AppendLog("Performed XOR inversion operation against current values.\r\n");
            }

            // Clipboard and File System Actions
            else if (wmId == IDC_BTN_COPYHEX) {
                stringstream ss;
                for(int i=0; i<32; i++) ss << hex << setw(2) << setfill('0') << (int)lastReadBuffer[i];
                string hStr = ss.str();
                if(OpenClipboard(hwnd)) {
                    EmptyClipboard();
                    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, hStr.size() + 1);
                    if(hg) {
                        memcpy(GlobalLock(hg), hStr.c_str(), hStr.size() + 1);
                        GlobalUnlock(hg); SetClipboardData(CF_TEXT, hg);
                    }
                    CloseClipboard(); AppendLog("Copied Hex buffer stream onto the clipboard stack.\r\n");
                }
            }
            else if (wmId == IDC_BTN_PASTEHEX) {
                if(OpenClipboard(hwnd)) {
                    HANDLE hData = GetClipboardData(CF_TEXT);
                    if(hData) {
                        char* pText = static_cast<char*>(GlobalLock(hData));
                        if(pText) {
                            string s(pText); stringstream ss; size_t count = 0;
                            for(size_t i=0; i<s.length() && count < 32; i+=2) {
                                if(i+1 < s.length()) {
                                    int b; stringstream hexConvert(s.substr(i, 2));
                                    if(hexConvert >> hex >> b) { ss << b << " "; count++; }
                                }
                            }
                            while(count < 32) { ss << "0 "; count++; }
                            SetWindowTextA(hEditInput, ss.str().c_str());
                            AppendLog("Parsed Hex streams directly out of system clipboard elements.\r\n");
                        }
                        GlobalUnlock(hData);
                    }
                    CloseClipboard();
                }
            }
            else if (wmId == IDC_BTN_SAVEFILE) {
                int index = SendMessage(hComboDrives, CB_GETCURSEL, 0, 0);
                if (index == CB_ERR || activeDrives.empty()) return 0;
                string expPath = string(1, activeDrives[index]) + ":\\exported_bytes.txt";
                HANDLE hFile = CreateFileA(expPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if(hFile != INVALID_HANDLE_VALUE) {
                    char buf[1024] = {0}; GetWindowTextA(hEditInput, buf, 1023);
                    DWORD wr; WriteFile(hFile, buf, (DWORD)strlen(buf), &wr, NULL); CloseHandle(hFile);
                    AppendLog("Dump file committed cleanly to " + expPath + "\r\n");
                }
            }
            else if (wmId == IDC_BTN_LOADFILE) {
                int index = SendMessage(hComboDrives, CB_GETCURSEL, 0, 0);
                if (index == CB_ERR || activeDrives.empty()) return 0;
                string impPath = string(1, activeDrives[index]) + ":\\exported_bytes.txt";
                HANDLE hFile = CreateFileA(impPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if(hFile != INVALID_HANDLE_VALUE) {
                    char buf[1024] = {0}; DWORD rd; ReadFile(hFile, buf, 1023, &rd, NULL); CloseHandle(hFile);
                    SetWindowTextA(hEditInput, buf); AppendLog("Imported data mapping layout from " + impPath + "\r\n");
                } else { 
                    AppendLog("Error: Exported configuration file missing on USB root.\r\n"); 
                }
            }
            // Hardware Structural Utilities
            else if (wmId == IDC_BTN_DRIVEINFO) {
                int index = SendMessage(hComboDrives, CB_GETCURSEL, 0, 0);
                if (index == CB_ERR || activeDrives.empty()) return 0;
                char dLetter = activeDrives[index];
                
                // Fixed trailing slash escape sequence bug
                string root = string(1, dLetter) + ":\\";
                char name[MAX_PATH] = {0}, fs[MAX_PATH] = {0}; 
                DWORD serial = 0, maxLen = 0, flags = 0;
                ULARGE_INTEGER freeB, totalB, totalFreeB;
                
                GetVolumeInformationA(root.c_str(), name, MAX_PATH, &serial, &maxLen, &flags, fs, MAX_PATH);
                GetDiskFreeSpaceExA(root.c_str(), &freeB, &totalB, &totalFreeB);

                AppendLog("\r\n--- HARDWARE SYSTEM STORAGE TELEMETRY [" + root + "] ---\r\n");
                AppendLog("FileSystem FormatType: " + string(fs) + "\r\n");
                AppendLog("Volume Label Identifier: " + string(name) + "\r\n");
                AppendLog("Hardware Serial Key: " + to_string(serial) + "\r\n");
                AppendLog("Total Raw Capacity: " + to_string(totalB.QuadPart / (1024 * 1024)) + " MB\r\n");
                AppendLog("Available Open Sectors: " + to_string(freeB.QuadPart / (1024 * 1024)) + " MB\r\n------------------------\r\n");
            }
            else if (wmId == IDC_BTN_VERIFY) {
                char inputBuf[1024] = {0}; 
                GetWindowTextA(hEditInput, inputBuf, 1023);
                stringstream ss(inputBuf); 
                int val; 
                vector<BYTE> currentInput; // Fixed missing type definition
                
                while(ss >> val) {
                    currentInput.push_back(static_cast<BYTE>(val));
                }

                bool perfectMatch = true;
                if(currentInput.size() == 32) {
                    for(int i = 0; i < 32; i++) {
                        if(currentInput[i] != lastReadBuffer[i]) perfectMatch = false;
                    }
                    if(perfectMatch) {
                        AppendLog("INTEGRITY VERIFIED: Input matches sector layout arrays perfectly.\r\n");
                    } else {
                        AppendLog("INTEGRITY ALERT: Hardware mismatches text lines. Check values.\r\n");
                    }
                } else { 
                    AppendLog("Error: Input array sequence incomplete for alignment testing.\r\n"); 
                }
            }
            break;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, uMsg, wp, lp);
}

// WinMain Global Bootloader Environment Entry
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if (!IsRunAsAdmin()) { 
        ElevateToAdmin(); 
        return 0; 
    }

    const char CLASS_NAME[] = "ByteReaderWriterWindow";
    WNDCLASSA wc = {};
    wc.lpfnWndProc = WindowProc; 
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME; 
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassA(&wc);

    // Dynamic, Always-on-Top Resizable System Window Configuration Setup
    HWND hwnd = CreateWindowExA(
        WS_EX_TOPMOST, // Pins application workspace on top of every standard window layer
        CLASS_NAME, 
        "USB Enterprise Advanced Operational Dashboard",
        WS_OVERLAPPEDWINDOW, // Permits full responsive system maximize and scaling resizing features
        CW_USEDEFAULT, CW_USEDEFAULT, 700, 600,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) return 0;

    ShowWindow(hwnd, nCmdShow);
    
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) { 
        TranslateMessage(&msg); 
        DispatchMessage(&msg); 
    }
    return 0;
}
