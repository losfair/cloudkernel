#pragma once

#include <array>
#include <atomic>
#include <ck-hypervisor/profile.h>
#include <ck-hypervisor/shmem.h>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdint.h>
#include <sys/uio.h>
#include <unordered_map>

class Tun {
public:
  int fd = -1;

  Tun(const char *name, bool multiqueue = false);
  Tun(const Tun &that) = delete;
  Tun(Tun &&that) = delete;
  virtual ~Tun();
  int write(const uint8_t *packet, size_t len);
  int read(uint8_t *packet, size_t len);
  int writev(const iovec *iov, int iovcnt);
  int readv(const iovec *iov, int iovcnt);
};

class RoutingEndpoint {
public:
  __uint128_t ck_pid; // used for identifying endpoint ownership

  std::function<void(uint8_t *, size_t, volatile uint8_t *, size_t)> on_packet;
  std::function<void()> on_destroy;

  ~RoutingEndpoint() {
    if (on_destroy)
      on_destroy();
  }
};

using IPAddress = __uint128_t;

class Router {
private:
  std::shared_mutex routes_mu;
  std::unordered_map<IPAddress, std::shared_ptr<RoutingEndpoint>> routes;
  std::vector<std::unique_ptr<Tun>> tuns;

  Tun *choose_tun();
  void run_loop(Tun *dev);

public:
  Router(int n_threads);

  void register_route(IPAddress addr,
                      std::shared_ptr<RoutingEndpoint> &&endpoint);
  void unregister_route(IPAddress addr, __uint128_t ck_pid);
  void dispatch_packet(volatile uint8_t *data, size_t len,
                       std::shared_ptr<AppNetworkProfile> profile = nullptr);
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
