#pragma once

#include <queue>
#include <condition_variable>
#include <mutex>
#include <optional>

template<class T> class BQueue {
    private:
    std::mutex mu;
    std::condition_variable cv;
    std::queue<T> elements;
    bool closed = false;
    size_t capacity = 0;
    
    public:
    BQueue() {}
    BQueue(const BQueue& that) = delete;
    BQueue(BQueue&& that) = delete;
    virtual ~BQueue() {}

    void set_capacity(size_t new_cap) {
        std::unique_lock<std::mutex> lg(mu);
        capacity = new_cap;
    }

    void close() {
        {
            std::unique_lock<std::mutex> lg(mu);
            closed = true;
        }
        cv.notify_all();
    }

    bool push(T&& value) {
        {
            std::unique_lock<std::mutex> lg(mu);
            if(capacity != 0 && elements.size() >= capacity) {
                return false;
            }
            elements.push(std::move(value));
        }
        cv.notify_one();
        return true;
    }

    std::optional<T> pop() {
        std::unique_lock<std::mutex> lg(mu);
        cv.wait(lg, [this]() { return closed || !elements.empty(); });
        if(closed) return std::nullopt;
        T ret = std::move(elements.front());
        elements.pop();
        return ret;
    }
};
