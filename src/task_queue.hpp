// TaskQueue.h
#ifndef TASK_QUEUE_H
#define TASK_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <string>

class TaskQueue {
public:
    void pushTask(const std::string& task);
    std::string popTask();
    bool isEmpty() const;

private:
    std::queue<std::string> tasks;
    mutable std::mutex queueMutex;
    std::condition_variable condition;
};

#endif // TASK_QUEUE_H