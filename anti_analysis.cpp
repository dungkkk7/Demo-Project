// --- BỘ INCLUDE ĐÚNG THỨ TỰ ---

// 1. Luôn đặt Winsock2 trước Windows.h để tránh xung đột
#include <winsock2.h>

// 2. Header chính của Windows
#include <windows.h>

// 3. Header cho các API mạng phụ trợ (phụ thuộc vào 1 và 2)
#include <iphlpapi.h>

// --- Các header khác ---
#include <iostream>
#include <vector>
#include <TlHelp32.h>
#include <intrin.h>
#include <string> // Thêm string để đầy đủ

// --- Header của bạn ---
#include "anti_analysis.h"

// Lệnh liên kết thư viện
#pragma comment(lib, "iphlpapi.lib")

// Khai báo namespace
using namespace std;

// --- Phần còn lại của mã nguồn ---

// cnstructor
AntiAnalysis::AntiAnalysis() {}


// destructor
AntiAnalysis::~AntiAnalysis() {}


// Check if the process is running under a debugger
void AntiAnalysis::IsDebuggerPresentCheck() {

	if (IsDebuggerPresent()){
		// nếu process đang chạy dưới debugger thì sẽ trả về true
		ExitProcess(0);
	}
}

void AntiAnalysis::CheckRemoteDebuggerPresentCheck() {
	BOOL debuggerPresent = FALSE;
	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent)) {
		// nếu process đang chạy dưới debugger thì sẽ trả về true
		ExitProcess(0);
	}

}; 


void AntiAnalysis::NtQueryInformationProcessCheck() {
	// triển khai với api Hàm này nằm trong ntdll.dll, gọi thẳng vào kernel mode.
	/*
	* Truy vấn trường ProcessDebugPort (ID = 7) của tiến trình hiện tại.

	  Nếu có giá trị khác 0 → tiến trình đang bị debug!
	*/
	typedef NTSTATUS(WINAPI* NtQueryInformationProcessFunc)(HANDLE, ULONG, PVOID, ULONG, PULONG);
	NtQueryInformationProcessFunc NtQueryInformationProcess = (NtQueryInformationProcessFunc)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

	if (NtQueryInformationProcess) {  // Nếu địa chỉ tìm thấy hợp lệ
		DWORD debugPort = 0;
		NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(DWORD), NULL);
		if (status == 0 && debugPort != 0) {
			ExitProcess(0);
		}; 
	}; 

}; 


void AntiAnalysis::TimingCheck() {
	/*
	Bình thường, gọi Sleep(10) thì chương trình sẽ pause tầm 10ms.

	Nhưng nếu process bị debugger pause (do đặt breakpoint, step, hoặc bị sandbox hook API làm chậm), thời gian thực tế sẽ lâu hơn.
	*/
	DWORD start = GetTickCount();
	Sleep(10);
	DWORD elapsed = GetTickCount() - start;
	if (elapsed > 20) {  // sẽ đo lại 
		ExitProcess(0); 
	}
}


void AntiAnalysis::PEBFlagCheck() {

	/*
	32-bit (x86) → dùng FS:[0x30] để lấy PEB (vì Windows mapping PEB tại đó cho process x86)

	64-bit (x64) → dùng GS:[0x60] để lấy PEB (Windows mapping PEB cho process x64 tại đây)
	typedef struct _PEB {
    BYTE InheritedAddressSpace;     // +0x000
    BYTE ReadImageFileExecOptions;  // +0x001
    BYTE BeingDebugged;             // +0x002 <--- Dùng nhiều nhất cho anti-debug
    BYTE Spare;                     // +0x003
    // ... còn nhiều trường khác
    PVOID Mutant;                   // +0x004
    PVOID ImageBaseAddress;         // +0x008
    // ...
    // Nhiều trường liên quan loader, heap, OS version,...
	} PEB, *PPEB;

	
	#ifdef, #ifndef, #else, #endif là lệnh của preprocessor C/C++ (trình tiền xử lý, chạy trước khi compiler dịch code).
	Dùng để kiểm tra macro định nghĩa khi build, ví dụ:  _M_IX86 sẽ được define khi build target là 32-bit trên MSVC.
	Nếu build 64-bit, macro này không có.



	#ifdef _M_IX86  // Nếu đang build cho 32-bit

		// Lấy PEB từ FS:[0x30]
		__asm { // inline assembly chỉ dùng được với MSVC 32-bit, không dùng cho 64-bit hoặc các compiler hiện đại
			mov eax, fs:[0x30]  // Lấy địa chỉ PEB vào EAX
			movzx ebx, byte ptr [eax + 2]  // Lấy trường BeingDebugged (byte thứ 3) vào EBX
			test ebx, ebx  // Kiểm tra xem EBX có khác 0 không , nếu ebx = 0 thì ZF =1 , nếu ebx != 0 thì ZF = 0
			jz debugger  // Nếu EBX != 0 -- > zf = 0  ,  bị debug
		debugger: 
			// Nếu EBX != 0, tức là đang bị debug, thực hiện hành động cần thiết (ví dụ: thoát)
			ExitProcess(0);  // Thoát chương trình nếu bị debug
		}
	#else // Nếu đang build cho 64-bit
	  

	# endif
	*/

	#ifdef _M_IX86
		PBYTE pPEB = (PBYTE)__readfsdword(0x30);
	#else
		PBYTE pPEB = (PBYTE)__readgsqword(0x60);
	#endif
		BYTE beingDebugged = *(pPEB + 2);
		if (beingDebugged) {
			ExitProcess(0);  // Nếu trường BeingDebugged khác 0, thoát chương trình
		}

}

void AntiAnalysis::checkVirtualHardwareConfig() {
	// Check CPU ID (CPUID instruction) -- kiểm tra thông tin CPU, nếu là máy ảo thì sẽ có thông tin khác với máy thật

	/*
	SYSTEMINFOR là struct chứa thông tin hệ thống, bao gồm kiến trúc CPU, số lượng core, kích thước page memory, v.v.
	| Field                         | Ý nghĩa                                                           |
	| ----------------------------- | ----------------------------------------------------------------- |
	| `wProcessorArchitecture`      | Kiến trúc CPU: x86, x64, ARM, IA64...                             |
	| `wReserved`                   | Không sử dụng (reserved).                                         |
	| `dwPageSize`                  | Kích thước 1 page memory (byte), thường là 4096                   |
	| `lpMinimumApplicationAddress` | Địa chỉ thấp nhất tiến trình có thể dùng                          |
	| `lpMaximumApplicationAddress` | Địa chỉ cao nhất tiến trình có thể dùng                           |
	| `dwActiveProcessorMask`       | Mask, chỉ processor nào đang active                               |
	| `dwNumberOfProcessors`        | **Số lượng core logic hiện tại (dùng để check VM)**               |
	| `dwProcessorType`             | Kiểu CPU: x86, ARM...                                             |
	| `dwAllocationGranularity`     | Độ lớn tối thiểu khi cấp phát bộ nhớ (VD: 64KB)                   |
	| `wProcessorLevel`             | Level của processor (ví dụ 6 là Intel Core, 15 là Pentium 4, ...) |
	| `wProcessorRevision`          | Version của processor                                             |
	 


	MEMORYSTATUSEX là struct dùng để lấy thông tin về bộ nhớ hệ thống, thường dùng trong các ứng dụng Windows.
	| Field                     | Ý nghĩa                                                  |
	| ------------------------- | -------------------------------------------------------- |
	| `dwLength`                | Kích thước struct (luôn truyền `sizeof(MEMORYSTATUSEX)`) |
	| `dwMemoryLoad`            | % sử dụng RAM hiện tại (0–100)                           |
	| `ullTotalPhys`            | **Tổng dung lượng RAM vật lý (byte)**                    |
	| `ullAvailPhys`            | RAM vật lý còn trống (byte)                              |
	| `ullTotalPageFile`        | Tổng page file (swap RAM+HDD, byte)                      |
	| `ullAvailPageFile`        | Phần page file còn trống (byte)                          |
	| `ullTotalVirtual`         | Tổng virtual memory (RAM ảo, byte)                       |
	| `ullAvailVirtual`         | Virtual memory còn trống (byte)                          |
	| `ullAvailExtendedVirtual` | Dành cho bản Windows Server > 2008, thường là 0 trên PC  |

	---- Nếu số lượng core logic ≤ 2, rất nghi ngờ đây là máy ảo. 
	---- Nếu RAM vật lý < 4GB thì khả năng cao là máy ảo, vì VM thường chỉ cấp 1-2GB RAM cho nhẹ.
	*/

	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	MEMORYSTATUSEX memStatus = { sizeof(memStatus) };
	GlobalMemoryStatusEx(&memStatus);

	// Kiểm tra số lượng core logic
	if (sysInfo.dwNumberOfProcessors <= 4) {  // thường là máy ảo sẽ chỉ có 1-2 core logic | nhưng tăng lên 4 để tránh vì nhiều người tăng máy ảo len 4 core cho đỡ lag 

		ExitProcess(0);

	}
	// Kiểm tra RAM vật lý

	if (memStatus.ullTotalPhys < 4 * 1024 * 1024 * 1024) {  // nếu RAM < 4GB có thể là máy ảo 
		ExitProcess(0);
	}
}

void AntiAnalysis::checkVMDrivers() {
	//  // Kiểm tra phần mềm/driver đặc trưng của VM (VM-Specific Software/Drivers)

	// --- PHẦN 1: KIỂM TRA SỰ TỒN TẠI CỦA CÁC TỆP TIN DRIVER ---
	// Lấy đường dẫn đến thư mục drivers của hệ thống
	char systemBuffer[MAX_PATH]; // Tạo một mảng ký tự (chuỗi char) có độ dài tối đa là MAX_PATH (thường là 260 ký tự).
	GetEnvironmentVariableA("SystemRoot", systemBuffer, MAX_PATH);  

	/*
	Gọi hàm Windows API để lấy giá trị biến môi trường tên "SystemRoot".
	"SystemRoot" là biến môi trường mặc định trỏ tới thư mục cài Windows (thường là C:\Windows).
	*/

	string driversPath = std::string(systemBuffer) + "\\System32\\drivers\\";  //  C:\Windows\System32\drivers\

	// Danh sách các tệp driver đáng ngờ và máy ảo tương ứng
         vector<std::pair<const char*, const char*>> suspiciousDrivers = {
		// VirtualBox
		{ "VBoxMouse.sys",    "VirtualBox" },
		{ "VBoxGuest.sys",    "VirtualBox" },
		{ "VBoxSF.sys",       "VirtualBox" },
		{ "VBoxVideo.sys",    "VirtualBox" },
		// VMware
		{ "vmhgfs.sys",       "VMware" },
		{ "vmmouse.sys",      "VMware" },
		{ "vmsci.sys",        "VMware" },
		{ "vmx_svga.sys",     "VMware" },
		// QEMU/KVM
		{ "vioser.sys",       "QEMU/KVM (VirtIO)" },
		// Parallels
		{ "prl_fs.sys",       "Parallels" }
	};


	for (const auto& driverInfo : suspiciousDrivers) {
		string fullPath = driversPath + driverInfo.first;
		/*
		Dùng GetFileAttributesA để kiểm tra file driver có thật trên ổ cứng không.
		Nếu có, nghĩa là máy này đã từng cài máy ảo hoặc đang chạy trong VM → Thoát chương trình (anti-analysis).
		*/
		if (GetFileAttributesA(fullPath.c_str()) != INVALID_FILE_ATTRIBUTES) {  
			ExitProcess(0);
		}
	}

	// --- PHẦN 2: KIỂM TRA SỰ TỒN TẠI CỦA CÁC THIẾT BỊ ẢO ---

	// Danh sách các thiết bị ảo đáng ngờ
		vector<std::pair<const char*, const char*>> suspiciousDevices = {
		{ "\\\\.\\VBoxGuest",   "VirtualBox" },
		{ "\\\\.\\HGFS",        "VMware" },
		{ "\\\\.\\Vmci",        "VMware" }
	};
	/*
	Các VM sẽ tạo ra một số device ảo đặc trưng (ví dụ \\.\VBoxGuest của VirtualBox).
	Dùng CreateFileA để thử mở device đó.
	Nếu mở được (handle khác INVALID_HANDLE_VALUE), thiết bị ảo của VM đang thực sự tồn tại → chắc chắn đang chạy trên VM.
	*/
	
	for (const auto& deviceInfo : suspiciousDevices) {
		// Thực hiện kiểm tra thiết bị ngay tại đây
		HANDLE hDevice = CreateFileA(deviceInfo.first, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hDevice != INVALID_HANDLE_VALUE) {
			// Đã tìm thấy thiết bị, đóng handle ngay lập tức
			CloseHandle(hDevice);
			ExitProcess(0);
		}
	}


}

void AntiAnalysis::	checkHypervisorArtifacts() {

	// kiểm tra các khóa registry đặc trưng của máy ảo (VM) hoặc hypervisor
	std::vector<const char*> suspiciousRegistryKeys = {
		// VMware
		"SOFTWARE\\VMware, Inc.\\VMware Tools",
		"SYSTEM\\CurrentControlSet\\Services\\VMTools",
		"HARDWARE\\ACPI\\DSDT\\VBOX__",
		// VirtualBox
		"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
		"SOFTWARE\\VBoxGuest",
		"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
		// QEMU/KVM
		"SOFTWARE\\QEMU",
		"HARDWARE\\ACPI\\DSDT\\QEMU",
		// Parallels
		"SYSTEM\\CurrentControlSet\\Services\\prl_tg",
		// Hyper-V
		"SYSTEM\\CurrentControlSet\\Services\\vmicheartbeat",
		"SYSTEM\\CurrentControlSet\\Services\\vmicvss",
		
	};

	for(auto& key : suspiciousRegistryKeys) {
		HKEY hKey;
		LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey);
		/*
		* LONG RegOpenKeyExA(
		  HKEY    hKey,        // Handle tới khóa cha (ví dụ HKEY_LOCAL_MACHINE)
		  LPCSTR  lpSubKey,    // Chuỗi tên nhánh con cần mở (dạng char*)
		  DWORD   ulOptions,   // Tùy chọn, thường để 0
		  REGSAM  samDesired,  // Quyền truy cập muốn lấy (thường là KEY_READ)
		  PHKEY   phkResult    // Con trỏ nhận về handle khóa vừa mở
		);

		Gọi Windows API RegOpenKeyExA để mở nhánh registry đó ở nhánh lớn HKLM (HKEY_LOCAL_MACHINE).
		Nếu key tồn tại và mở được, hàm trả về ERROR_SUCCESS.
		Nếu không tồn tại (key không có thật trên máy này), trả về lỗi khác.
		
		*/
		if (result == ERROR_SUCCESS) {
			// Nếu mở thành công, khóa registry tồn tại → máy có thể đang chạy trên VM hoặc hypervisor
			RegCloseKey(hKey);  // Đóng khóa registry
			ExitProcess(0); 
		}
	}

	// 2  KIỂM TRA CÁC TIỀN TỐ (PREFIXES) CỦA ĐỊA CHỈ MAC
	/*
	IP_ADAPTER_ADDRESSES
	Nguồn: Định nghĩa trong <iphlpapi.h>

	Dùng cho: GetAdaptersAddresses (lấy thông tin card mạng, MAC Address, IP, v.v.)

	Struct rút gọn:


	typedef struct _IP_ADAPTER_ADDRESSES {
		ULONG Length;                        // Kích thước struct
		DWORD IfIndex;                       // Index adapter
		struct _IP_ADAPTER_ADDRESSES* Next;  // Con trỏ tới adapter tiếp theo (linked list)
		PCHAR AdapterName;                   // Tên adapter (chuỗi)
		PIP_ADAPTER_UNICAST_ADDRESS FirstUnicastAddress; // Địa chỉ IP
		ULONG PhysicalAddressLength;         // Độ dài MAC (thường là 6)
		BYTE PhysicalAddress[MAX_ADAPTER_ADDRESS_LENGTH]; // Địa chỉ MAC (byte[])
		// ... còn nhiều trường khác
	} IP_ADAPTER_ADDRESSES, *PIP_ADAPTER_ADDRESSES;
	Giải thích:

	Linked list: Mỗi adapter là một node, trường Next trỏ sang adapter tiếp theo.

	PhysicalAddress: Mảng 6 byte chính là MAC address của card mạng (ethernet chuẩn).

	PhysicalAddressLength: Chỉ cần kiểm tra == 6 là biết đó là MAC của card mạng thực/ảo.




	API
	ULONG GetAdaptersAddresses(
	  ULONG Family,                // Loại địa chỉ IP cần lấy (IPv4, IPv6, hoặc cả hai )  AF_UNSPEC:Lấy tất cả loại địa chỉ IP (cả IPv4 và IPv6).Nếu chỉ muốn IPv4 thì dùng AF_INET, chỉ IPv6 thì AF_INET6.
	  ULONG Flags,                 // Cờ tuỳ chọn mở rộng
	  PVOID Reserved,              // Không dùng, phải để NULL
	  PIP_ADAPTER_ADDRESSES AdapterAddresses, // Buffer nhận danh sách adapter , Ở lần gọi đầu, bạn để NULL vì chỉ muốn biết cần cấp phát buffer bao nhiêu là đủ
	  PULONG SizePointer           // [IN/OUT] Truyền vào kích thước buffer, nhận về kích thước cần thiết
	);
	*/
	ULONG bufferSize = 0;
	if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &bufferSize) == ERROR_BUFFER_OVERFLOW) {
		vector<BYTE> buffer(bufferSize);
		PIP_ADAPTER_ADDRESSES pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

		// Gọi lần hai để lấy dữ liệu
		if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &bufferSize) == NO_ERROR) {
			for (PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses; pCurrAddresses != NULL; pCurrAddresses = pCurrAddresses->Next) {  // lặp quá linklist 
				if (pCurrAddresses->PhysicalAddressLength == 6) { // MAC address có 6 byte
					BYTE* mac = pCurrAddresses->PhysicalAddress;

					// so sánh 3 bte đầu tiên của địa chỉ MAC với các tiền tố (prefixes) của các nhà cung cấp máy ảo phổ biến
					// VMware 

					if (mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69 ||
						mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29 ||
						mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56) {
						ExitProcess(0);
					}
					// VirtualBox
					else if (mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27) {
						ExitProcess(0);
					}
					// Parallels
					else if (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x42) {
						ExitProcess(0);
					}
					// Hyper-V
					else if (mac[0] == 0x00 && mac[1] == 0x15 && mac[2] == 0x5D) {
						ExitProcess(0);
					}
					/*
					VMware: 00:05:69, 00:0C:29, 00:50:56

					VirtualBox: 08:00:27

					Parallels: 00:1C:42

					Hyper-V: 00:15:5D

					*/


				}
			}
		}


	}
}

	void AntiAnalysis::CPUIDInterrogationCheck
	() {
		/*
		- **Truy vấn CPUID (CPUID Interrogation)**
		- **Mô tả:** Lệnh CPUID cung cấp thông tin bộ xử lý, bao gồm cả việc nó có đang chạy trên hypervisor hay không.
		- **Kỹ thuật:** Khi EAX=0x40000000, CPUID trả về chuỗi định danh hypervisor (ví dụ: "VMwareVMware").152 Khi EAX=1, bit 31 của ECX (bit HV) được đặt nếu chạy trên hypervisor.152
		- Việc thay đổi giá trị CPUID trả về (ví dụ: qua cấu hình VMX của VMware 152) là một kỹ thuật phổ biến để hardening VM. Tuy nhiên, malware có thể tìm kiếm các dấu hiệu khác của
		việc giả mạo CPUID hoặc sự không nhất quán giữa các kết quả kiểm tra.
		
		*/
		
			bool vmDetected = false;

			// Mảng để lưu kết quả từ CPUID [EAX, EBX, ECX, EDX]
			int cpuInfo[4];

			// --- KỸ THUẬT 1: TRUY VẤN CHUỖI ĐỊNH DANH HYPERVISOR ---
			// Thực hiện lệnh CPUID với EAX = 0x40000000
			__cpuid(cpuInfo, 0x40000000);

			// Chuỗi định danh được trả về trong 3 thanh ghi: EBX, ECX, EDX == tổng cộng 12 byte
			char hypervisorVendor[13];
			memcpy(hypervisorVendor, &cpuInfo[1], 4); // EBX
			memcpy(hypervisorVendor + 4, &cpuInfo[2], 4); // ECX     ===> nối 3 phần của vender 
			memcpy(hypervisorVendor + 8, &cpuInfo[3], 4); // EDX
			hypervisorVendor[12] = '\0'; // Kết thúc chuỗi

			string vendorStr(hypervisorVendor); //  ==>  Chuyển đổi sang std::string để dễ xử lý

			// So sánh với các chuỗi định danh đã biết
			if (vendorStr == "VMwareVMware" || vendorStr == "VMware SVGA II") {
				ExitProcess(0);
			}
			else if (vendorStr == "Microsoft Hv") {
				ExitProcess(0);
			}
			else if (vendorStr == "KVMKVMKVM") {
				ExitProcess(0);
			}
			else if (vendorStr == "XenVMMXenVMM") {
				ExitProcess(0);
			}
			else if (vendorStr == "prl hyperv" || vendorStr == "prl hyperv  ") {
				ExitProcess(0);
			}


			// --- KỸ THUẬT 2: KIỂM TRA BIT HIỆN DIỆN HYPERVISOR (HV BIT) ---

			// Thực hiện lệnh CPUID với EAX = 1
			__cpuid(cpuInfo, 1);

			// Bit 31 của thanh ghi ECX được gọi là "Hypervisor-Present Bit".
			// Nếu bit này bằng 1, nghĩa là đang chạy trên một hypervisor.
			// (1 << 31) là một mặt nạ bit để chỉ kiểm tra bit thứ 31.
			if ((cpuInfo[2] & (1 << 31)) != 0) {
				ExitProcess(0);
			}

	
	}

	// sanbox thường thiếu hành vi người dùng bình thường như di chuyển chuột, nhập bàn phím, v.v.
void AntiAnalysis::	SystemUserBehaviorAnalysisCheck()
{

	bool sandboxSuspected = false;

	// --- KỸ THUẬT 1: KIỂM TRA THỜI GIAN HOẠT ĐỘNG VÀ TƯƠNG TÁC CHUỘT ---

	// Kiểm tra uptime: Sandbox thường được khởi động lại ngay trước khi phân tích.
	ULONGLONG uptimeMinutes = GetTickCount64() / (1000 * 60);
	const ULONGLONG MIN_UPTIME_MINUTES = 30; // Ngưỡng: 30 phút
	if (uptimeMinutes < MIN_UPTIME_MINUTES) {
		 // std::cout << "  [!] CẢNH BÁO: Thời gian hoạt động của hệ thống quá thấp, đáng ngờ!" << std::endl;
		ExitProcess(0);
	}

	// Kiểm tra di chuyển chuột: Trong sandbox tự động, chuột thường đứng yên.
	POINT p1, p2;
	GetCursorPos(&p1);
	Sleep(2000); // Chờ 2 giây
	GetCursorPos(&p2);
	 // std::cout << "  [-] Kiểm tra di chuyển chuột..." << std::endl;
	if (p1.x == p2.x && p1.y == p2.y) {
	 // 	std::cout << "  [!] CẢNH BÁO: Không phát hiện di chuyển chuột!" << std::endl;
		ExitProcess(0);
	}

	
}


/*

| API                          | Thuộc thư viện              | Link runtime                 |
| ---------------------------- | --------------------------- | ---------------------------- |
| `IsDebuggerPresent`          | `kernel32.dll`              | Static link via windows.h    |
| `CheckRemoteDebuggerPresent` | `kernel32.dll`              | Static                       |
| `NtQueryInformationProcess`  | `ntdll.dll`                 | Dynamic via `GetProcAddress` |
| `__cpuid`, `__readgsqword`   | `intrin.h` (compiler instr) | Built-in MSVC                |
| `Sleep`, `GetTickCount`,...  | `kernel32.dll`              | Static                       |
| `GetLastInputInfo`           | `user32.dll`                | Static                       |



*/