#pragma once

#include <array>
#include <atomic>
#include <ck-hypervisor/shmem.h>
#include <functional>
#include <memory>
#include <mutex>
#include <stdint.h>
#include <unordered_map>

class Tun {
public:
  int fd = -1;

  Tun(const char *name);
  Tun(const Tun &that) = delete;
  Tun(Tun &&that) = delete;
  virtual ~Tun();
  int write(const uint8_t *packet, size_t len);
  int read(uint8_t *packet, size_t len);
};

class RoutingEndpoint {
public:
  __uint128_t ck_pid; // used for identifying endpoint ownership

  std::mutex mu;
  std::function<void(uint8_t *, size_t)> on_packet;
  std::function<void()> on_destroy;

  ~RoutingEndpoint() {
    if (on_destroy)
      on_destroy();
  }
};

using IPAddress = __uint128_t;

class Router {
private:
  std::mutex mu;
  std::unordered_map<IPAddress, std::shared_ptr<RoutingEndpoint>> routes;
  std::unique_ptr<Tun> tun;

public:
  inline void setup_tun() {
    tun = std::unique_ptr<Tun>(new Tun("tun-cloudkernel"));
  }

  void register_route(IPAddress addr,
                      std::shared_ptr<RoutingEndpoint> &&endpoint);
  void unregister_route(IPAddress addr, __uint128_t ck_pid);
  void dispatch_packet(uint8_t *data, size_t len);
  void run_loop();
};

extern Router global_router;

// fixed and aligned to 2048 bytes
struct SharedQueueElement {
  std::atomic<uint32_t> filled; // is there unused data in this element?
  uint32_t _padding;
  std::atomic<uint64_t> len;
  uint8_t data[2048 - 16];
};
static_assert(sizeof(SharedQueueElement) == 2048,
              "invalid SharedQueueElement size");

// SharedQueue itself is NOT thread safe.
class SharedQueue {
private:
  SharedQueueElement *elements = nullptr;
  size_t num_elements = 0;
  size_t next_element = 0;
  std::atomic<bool> termination_requested = std::atomic<bool>(false);

public:
  SharedMemory shm;

  SharedQueue(size_t new_num_elements);
  SharedQueue(const SharedQueue &that) = delete;
  SharedQueue(SharedQueue &&that) = delete;

  virtual ~SharedQueue();
  uint8_t *get_data_ptr();
  bool can_push();
  void push(size_t len);
  bool can_pop();
  bool wait_pop();
  size_t current_len();
  void pop();

  inline void request_termination() { termination_requested.store(true); }

  static inline constexpr size_t data_size() {
    return sizeof(((SharedQueueElement *)(nullptr))->data);
  }
};
