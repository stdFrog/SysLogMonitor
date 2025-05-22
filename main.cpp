// build - Unicode
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>

static HANDLE hCtrlEvent = NULL, hEvent = NULL;
BOOL WINAPI ConsoleHandler(DWORD dwCtrlType) {
	// 콘솔 앱에서 종료 이벤트가 발생할 때 실행된다.
	// 1. Ctrl+C(CTRL_C_EVENT)
	// 2. 닫기 버튼(CTRL_CLOSE_EVENT)
	// 3. Ctrl+Break(CTRL_BREAK_EVENT)
	// 4. 시스템 종료 또는 로그오프(CTRL_SHUTDOWN_EVENT, CTRL_LOGOFF_EVENT)
	// 이벤트가 발생하면 운영체제가 ConsoleHandler(DWORD ctrlType)을 호출한다.

	switch(dwCtrlType){
		case CTRL_C_EVENT:
		case CTRL_CLOSE_EVENT:
		case CTRL_SHUTDOWN_EVENT:
			printf("\nThe program is terminating. Resources and memory are being cleaned up.\n");
			SetEvent(hCtrlEvent);
			SetEvent(hEvent);
			return TRUE;
		default:
			return FALSE;
	}
}

void GetEventMessageFromDll(DWORD MessageID, const char* Message) {
	HANDLE hEventLog = OpenEventLog(NULL, Message);
	if(!hEventLog){
		throw "OpenEventLog Failed";
	}

	// 메시지 파일 로드
	HMODULE hModule = LoadLibraryEx("C:\\Windows\\System32\\EventLog.dll", NULL, LOAD_LIBRARY_AS_DATAFILE);
	if (!hModule) {
		CloseEventLog(hEventLog);
		throw "Failed to load Message DLL";
	}

	// 메시지 ID를 기반으로 문자열 변환
	char Buffer[4096];
	DWORD dwMessageSize = FormatMessage(
			FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
			hModule,
			MessageID,
			0, Buffer, sizeof(Buffer),
			NULL
			);

	if(dwMessageSize){
		printf("Event ID: %d\nMessage: %s\n", MessageID, Buffer);
	}else{
		FreeLibrary(hModule);
		CloseEventLog(hEventLog);
		throw "Failed To Retrieve Message";
	}

	FreeLibrary(hModule);
	CloseEventLog(hEventLog);
}

int main(){
	hCtrlEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if(!SetConsoleCtrlHandler(ConsoleHandler, TRUE)){
		printf("SetConsoleCtrlHandler Failed: %d\n", GetLastError());
		return 1;
	}

	// L"\\\\localhost"
	HANDLE hEventLog = OpenEventLog(NULL, "System");

	// 자동, 비신호
	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	BYTE Buffer[0x1000],
	*pBuffer = (BYTE*)malloc(0x1000);

	DWORD ret = 0,
		  CtrlRet = 0,
		  dwRead = 0,
		  dwNeeded = 0,
		  LastRecordNumber = 0;

	BOOL bTrue = ReadEventLog(hEventLog, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ, 0, Buffer, sizeof(Buffer), &dwRead, &dwNeeded);
	if(bTrue){ LastRecordNumber = ((EVENTLOGRECORD*)Buffer)->RecordNumber; }

	printf("Monitoring Event Log Changes\n");
	while(WaitForSingleObject(hCtrlEvent, 0) == WAIT_TIMEOUT){
		if(!NotifyChangeEventLog(hEventLog, hEvent)){
			printf("Listening Failed: %d\n", GetLastError());
			break;
		}

		ret = WaitForSingleObject(hEvent, INFINITE);
		CtrlRet = WaitForSingleObject(hCtrlEvent, 0);
		if(CtrlRet == WAIT_TIMEOUT && ret == WAIT_OBJECT_0){
			printf("New Event Log Detected\n");

			// Read Log
			while(WaitForSingleObject(hCtrlEvent, 0) == WAIT_TIMEOUT){
				bTrue = ReadEventLog(
						hEventLog,
						EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ,
						0, pBuffer, sizeof(BYTE) * 0x1000,
						&dwRead,
						&dwNeeded
						);

				if(!bTrue && GetLastError() == ERROR_INSUFFICIENT_BUFFER){
					free(pBuffer);
					pBuffer = (BYTE*)malloc(dwNeeded);
					continue;
				}

				EVENTLOGRECORD* pRecord = (EVENTLOGRECORD*)pBuffer;
				while(WaitForSingleObject(hCtrlEvent, 0) == WAIT_TIMEOUT && ((BYTE*)pRecord < (pBuffer + dwRead))){
					if(pRecord->Length == 0){ printf("Invalid Record Length\n"); break; }

					if(pRecord->RecordNumber > LastRecordNumber){
						// UNIX Timestamp: 1970.01.01
						ULONGLONG TimeOffset = pRecord->TimeGenerated * 10000000ULL + (369.0 * 365.2422 * 24.0 * 60.0 * 60.0 * 10000000.0);

						// 1601.01.01
						FILETIME ft;
						SYSTEMTIME st;
						ft.dwLowDateTime = (DWORD)TimeOffset;
						ft.dwHighDateTime = (DWORD)(TimeOffset >> 32);
						FileTimeToSystemTime(&ft, &st);

						char TimeBuffer[0x100];
						wsprintf(TimeBuffer, "%d-%d-%d %d:%d:%d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

						static const char* lpszEventType[] = {
							"Success",
							"Error",
							"Warning",
							"Unknown",
							"Information",
							"Unknown",
							"Unknown",
							"Unknown",
							"Audit Success",
							"Unknown",
							"Unknown",
							"Unknown",
							"Unknown",
							"Unknown",
							"Unknown",
							"Unknown",
							"Audit Failure"
						};
						const char* pEventType = lpszEventType[pRecord->EventType];

						const char* Message = "No Message Available";
						if(pRecord->StringOffset != 0){
							Message = (const char*)((BYTE*)pRecord + pRecord->StringOffset);
						}

						struct EventInfo{
							DWORD ID;
							const char* Description;
						} static const EventTable[] = {
							{2,		"Interactive logon: Someone has logged on interactively to the computer."},
							{3,		"Network logon: Someone attempted to access a resource on the computer."},
							{4,		"Batch logon: The NT Scheduler service attempted to access using a script or batch file."},
							{5,		"Service logon: One of the NT services was started using a specific user account."},
							{6,		"Proxy logon: Someone has logged on via a proxy."},
							{7,		"The workstation has been locked."},
							{512,	"Windows started."},
							{513,	"Windows terminated."},
							{514,	"The LSA has loaded an authentication package."},
							{515,	"A trusted logon processor registers with the LSA."},
							{517,	"The security event log has been deleted."},
							{518,	"A package has been loaded by the Security Account Manager."},
							{520,	"The system time has been changed."},
							{528,	"Successfully logged on to the computer."},
							{529,	"An attempt was made to log on using an unknown username or a known username with an incorrect password."},
							{530,	"An attempt was made to log on outside the allowed logon time."},
							{531,	"An attempt was made to log on using a locked username."},
							{532,	"An attempt was made to log on using a username with an expired account."},
							{533,	"An attempt was made to log on using a username that is not allowed to log on."},
							{534,	"An attempt was made to log on using a disallowed logon type (such as network or interactive service)."},
							{535,	"A user has a password that has expired."},
							{536,	"Logon failed because the NetLogon service was not started."},
							{537,	"Logon failed due to an unexpected error."},
							{538,	"The user has logged off."},
							{539,	"The user account has been locked due to failed logon attempts exceeding the set limit."},
							{540,	"Successfully logged on to the network."},
							{612,	"Security audit policy has been changed."},
							{624,	"A new user has been created."},
							{625,	"The user type has been changed."},
							{626,	"A locked user account has been unlocked."},
							{627,	"An attempt was made to change the password."},
							{628,	"The user password has been set."},
							{629,	"User account locking has been configured."},
							{630,	"The user account has been permanently deleted."},
							{631,	"A security-enabled global group has been created."},
							{632,	"A member has been added to the security-enabled global group."},
							{633,	"A member has been removed from the security-enabled global group."},
							{634,	"The security-enabled global group has been deleted."},
							{635,	"An unsecured local group has been created."},
							{636,	"User account group has been changed (a member has been added to the local group)."},
							{637,	"User account group has been changed (a member has been removed from the local group)."},
							{638,	"User account group has been changed (the local group has been deleted)."},
							{639,	"User account group has been changed (a local group member has been modified)."},
							{641,	"User account group has been changed (the local group has been modified)."},
							{642,	"The username has been changed."},
							{643,	"The domain policy has been changed."},
							{644,	"The user account has been automatically locked."},
							{668,	"The group type has been changed."},
							{681,	"An attempt was made to log on using a domain account."},
							{682,	"The user reconnected to a disconnected Terminal Services session."},
							{683,	"The user disconnected from the Terminal Services session without logging off."},
							{4198,	"A duplicate MAC address has been detected on the network."},
							{4199,	"A duplicate IP address has been detected on the network."},
							{4688,	"New process created."},
							{4624,	"User successfully logged in."},
							{4634,	"User logged off."},
							{7036,	"Service status changed."},
							{7045,	"New service installed."},
							{1102,	"Audit log cleared."},
							{0,		"Unknown event ID."} // Default value
						};

						const char* Description = NULL;
						for(int i=0; i<sizeof(EventTable) / sizeof(EventTable[0]); i++){
							if(EventTable[i].ID == pRecord->EventID){
								Description = EventTable[i].Description;
							}
						}

						printf("===============================================\n");
						printf("Event ID: %s\n", Description);
						printf("Level	: %s\n", pEventType);
						printf("Time	: %s\n", TimeBuffer);
						try {
							int MessageID = atoi(Message);
							GetEventMessageFromDll(MessageID, Message);
						} catch (const char* ErrorMessage){
							printf("[Failed To Convert Message]\n%s, Error Code: %d\n", ErrorMessage, GetLastError());
							printf("Message	: %s\n", Message);
						}
						printf("===============================================\n");

						LastRecordNumber = pRecord->RecordNumber;
					}

					pRecord = (EVENTLOGRECORD*)((BYTE*)pRecord + pRecord->Length);
				}
			}
		}else{
			if(CtrlRet == WAIT_OBJECT_0){ break; }
			if(ret == WAIT_TIMEOUT){ continue; }
			if(ret == WAIT_FAILED){
				DWORD dwError = GetLastError();

				switch (dwError) {
					case ERROR_INVALID_HANDLE:
						printf("ERROR_INVALID_HANDLE: %d\n", dwError);
						break;

					case ERROR_ACCESS_DENIED:
						printf("ERROR_ACCESS_DENIED: %d\n", dwError);
						break;

					case ERROR_NOT_ENOUGH_MEMORY:
						printf("ERROR_NOT_ENOUGH_MEMORY: %d\n", dwError);
						break;

					case ERROR_OPERATION_ABORTED:
						printf("ERROR_OPERATION_ABORTED: %d\n", dwError);
						break;

					case ERROR_INVALID_PARAMETER:
						printf("ERROR_INVALID_PARAMETER: %d\n", dwError);
						break;

					default:
						printf("unexpected error: %d\n", dwError);
						break;
				}
			}
		}
	}

	free(pBuffer);
	CloseHandle(hEvent);
	CloseEventLog(hEventLog);
	CloseHandle(hCtrlEvent);

	printf("\n\nThe clean-up process has been completed.\n");
	system("pause");
	return 0;
}
