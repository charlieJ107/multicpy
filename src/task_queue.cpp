// TaskQueue.cpp
#include "task_queue.hpp"

void TaskQueue::pushTask(const std::string& task) {
    std::lock_guard<std::mutex> lock(queueMutex);
    tasks.push(task);
    condition.notify_one();
}

std::string TaskQueue::popTask() {
    std::unique_lock<std::mutex> lock(queueMutex);
    condition.wait(lock, [this] { return !tasks.empty(); });
    std::string task = tasks.front();
    tasks.pop();
    return task;
}

bool TaskQueue::isEmpty() const {
    std::lock_guard<std::mutex> lock(queueMutex);
    return tasks.empty();
}