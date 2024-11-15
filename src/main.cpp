#include <iostream>
#include <filesystem>
#include <thread>
#include "hash_verifier.hpp"
#include "file_copier.hpp"
#include "task_queue.hpp"
#include "address_parser.hpp"


namespace fs = std::filesystem;

void worker(TaskQueue& taskQueue, const std::string& destination, bool verify);

int main(int argc, char** argv) {
    try {
        AddressParser parser(argc, argv);
        TaskQueue taskQueue;

        // 遍历源目录并将任务加入队列
        for (const auto& entry : fs::recursive_directory_iterator(parser.getSourcePath())) {
            if (entry.is_regular_file()) {
                taskQueue.pushTask(entry.path().string());
            }
        }



        // 多线程复制任务
        std::vector<std::thread> threads;
        for (int i = 0; i < std::thread::hardware_concurrency(); ++i) {
            threads.emplace_back(worker, std::ref(taskQueue), parser.getDestinationPath(), parser.isVerifyEnabled());
        }

        // 等待所有线程完成
        for (auto& thread : threads) {
            thread.join();
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

void worker(TaskQueue& taskQueue, const std::string& destination, bool verify) {
    while (!taskQueue.isEmpty()) {
        std::string source = taskQueue.popTask();
        std::string dest = destination + "/" + fs::path(source).filename().string();
        FileCopier::copyFile(source, dest);
        if (verify && !HashVerifier::verifyFile(source, dest)) {
            std::cerr << "Hash verification failed for file: " << source << std::endl;
        }
    }
}
