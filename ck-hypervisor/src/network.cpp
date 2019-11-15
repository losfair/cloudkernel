#include <ck-hypervisor/network.h>
#include <fcntl.h>
#include <iostream>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <optional>
#include <stdexcept>
#include <stdint.h>
#include <string.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

Router global_router;

static std::optional<IPAddress>
extract_destination_address_from_packet(const uint8_t *data, size_t len) {
  if (len < 1)
    return std::nullopt;
  switch (data[0] >> 4) {
  case 4: {
    if (len < 20)
      return std::nullopt;
    uint32_t addr = *(uint32_t *)&data[16];
    std::reverse((uint8_t *)&addr, ((uint8_t *)&addr) + 4);
    return ((__uint128_t)0xffff00000000ull) | (__uint128_t)addr;
  }
  case 6: {
    if (len < 40)
      return std::nullopt;
    __uint128_t addr = *(__uint128_t *)&data[24];
    std::reverse((uint8_t *)&addr, ((uint8_t *)&addr) + 16);
    return addr;
  }
  default:
    return std::nullopt;
  }
}

void Router::register_route(IPAddress addr,
                            std::shared_ptr<RoutingEndpoint> &&endpoint) {
  std::lock_guard<std::mutex> lg(mu);
  routes[addr] = std::move(endpoint);
}

void Router::unregister_route(IPAddress addr, __uint128_t ck_pid) {
  std::lock_guard<std::mutex> lg(mu);
  if (auto it = routes.find(addr);
      it != routes.end() && it->second->ck_pid == ck_pid) {
    routes.erase(it);
  }
}

void Router::dispatch_packet(uint8_t *data, size_t len) {
  IPAddress addr;
  if (auto maybe_addr = extract_destination_address_from_packet(data, len)) {
    addr = maybe_addr.value();
  } else {
    return;
  }

  std::shared_ptr<RoutingEndpoint> endpoint;

  {
    std::lock_guard<std::mutex> lg(mu);
    if (auto it = routes.find(addr); it != routes.end()) {
      endpoint = it->second;
    }
  }

  if (endpoint) {
    std::lock_guard<std::mutex> lg(endpoint->mu);
    if (endpoint->on_packet)
      endpoint->on_packet(data, len);
  } else {
    tun->write(data, len); // packet to outside
  }
}

void Router::run_loop() {
  uint8_t buf[1500];

  while (true) {
    int n = tun->read(buf, sizeof(buf));
    if (n <= 0) {
      std::cout << "tun->read() failed: " << n << std::endl;
      continue;
    }
    dispatch_packet(buf, n);
  }
}

Tun::Tun(const char *name) {
  int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    throw std::runtime_error("cannot open tun device");
  }

  ifreq ifr;
  memset((char *)&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

  if (name) {
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
  }

  if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
    close(fd);
    throw std::runtime_error("cannot set ifreq");
  }

  if (ioctl(fd, TUNSETPERSIST, 1) < 0) {
    close(fd);
    throw std::runtime_error("cannot set persist");
  }

  this->fd = fd;
}

Tun::~Tun() { close(fd); }

int Tun::write(uint8_t *packet, size_t len) { return ::write(fd, packet, len); }

int Tun::read(uint8_t *packet, size_t len) { return ::read(fd, packet, len); }
