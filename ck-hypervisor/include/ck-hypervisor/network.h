#pragma once

#include <array>
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
  int write(uint8_t *packet, size_t len);
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
