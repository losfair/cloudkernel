#pragma once

#include <queue>
#include <condition_variable>
#include <mutex>

template<class T> class BQueue {
    private:
    std::mutex mu;
    std::condition_variable cv;
    std::queue<T> elements;
    
    public:
    BQueue() {}
    BQueue(const BQueue& that) = delete;
    BQueue(BQueue&& that) = delete;
    virtual ~BQueue() {}

    void push(T&& value) {
        {
            std::unique_lock<std::mutex> lg(mu);
            elements.push(std::move(value));
        }
        cv.notify_one();
    }

    T pop() {
        std::unique_lock<std::mutex> lg(mu);
        cv.wait(lg, [this]() { return !elements.empty(); });
        T ret = std::move(elements.front());
        elements.pop();
        return ret;
    }
};
