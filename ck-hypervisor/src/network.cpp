#include <assert.h>
#include <ck-hypervisor/byteutils.h>
#include <ck-hypervisor/external.h>
#include <ck-hypervisor/network.h>
#include <fcntl.h>
#include <iostream>
#include <linux/futex.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <optional>
#include <random>
#include <stdexcept>
#include <stdint.h>
#include <string.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <thread>
#include <unistd.h>

static const char *dev_name = "tun-cloudkernel";

// Seems that using more than one tx/rx queues does not improve throughput.
// (mutex contention?)
Router global_router(1);

struct PacketMetadata {
  bool is_ipv6 = false;
  IPAddress src_addr = 0;
  IPAddress dst_addr = 0;
  size_t header_size = 0;
  uint8_t header[40] = {};
};

static inline IPAddress decode_packet_ipv4(volatile uint8_t *data) {
  uint32_t addr = *(uint32_t *)data;
  std::reverse((uint8_t *)&addr, (uint8_t *)(&addr + 1));
  return ((__uint128_t)0xffff00000000ull) | (__uint128_t)addr;
}

static inline IPAddress decode_packet_ipv6(volatile uint8_t *data) {
  __uint128_t addr = *(__uint128_t *)data;
  std::reverse((uint8_t *)&addr, (uint8_t *)(&addr + 1));
  return addr;
}

// `decode_packet_header` is designed to prevent the TOCTOU problem with
// untrusted input.
static std::optional<PacketMetadata>
decode_packet_header(volatile uint8_t *unsafe_data, size_t len) {
  if (len < 1)
    return std::nullopt;

  PacketMetadata md;

  uint8_t ty = (unsafe_data[0] >> 4);
  switch (ty) {
  case 4: {
    if (len < 20)
      return std::nullopt;
    std::copy(unsafe_data, unsafe_data + 20, md.header);
    if ((md.header[0] >> 4) != ty)
      return std::nullopt;

    md.is_ipv6 = false;
    md.src_addr = decode_packet_ipv4(&md.header[12]);
    md.dst_addr = decode_packet_ipv4(&md.header[16]);
    md.header_size = 20;
    return md;
  }
  case 6: {
    if (len < 40)
      return std::nullopt;
    std::copy(unsafe_data, unsafe_data + 40, md.header);
    if ((md.header[0] >> 4) != ty)
      return std::nullopt;

    md.is_ipv6 = true;
    md.src_addr = decode_packet_ipv6(&md.header[8]);
    md.dst_addr = decode_packet_ipv6(&md.header[24]);
    md.header_size = 40;
    return md;
  }
  default:
    return std::nullopt;
  }
}

Router::Router(int n_threads) {
  if (n_threads <= 0) {
    throw std::runtime_error("n_threads must be greater than zero");
  }

  for (int i = 0; i < n_threads; i++) {
    auto tun = std::unique_ptr<Tun>(new Tun(dev_name, true));
    tuns.push_back(std::move(tun));
  }

  if (call_external("ip", {"ip", "link", "set", dev_name, "up"}) != 0) {
    throw std::runtime_error("Unable to set link to up");
  }

  for (auto &t : tuns) {
    Tun *dev = &*t;
    std::thread([this, dev]() { run_loop(dev); }).detach();
  }
}

static thread_local std::random_device rand_dev;
static thread_local std::mt19937 rand_gen = std::mt19937(rand_dev());

static inline bool is_ipv4_address(IPAddress addr) {
  return (addr >> 32 == 0xffff);
}

static void update_os_route(IPAddress addr, const char *action) {
  if (is_ipv4_address(addr)) {
    std::string fmt = encode_ipv4_address((uint32_t)addr);
    if (call_external(
            "ip", {"ip", "route", action, fmt.c_str(), "dev", dev_name}) != 0) {
      printf("Unable to update IPv4 route\n");
    }
  } else {
    std::string fmt = encode_ipv6_address(addr);
    if (call_external("ip", {"ip", "-6", "route", action, fmt.c_str(), "dev",
                             dev_name}) != 0) {
      printf("Unable to update IPv6 route\n");
    }
  }
}

Tun *Router::choose_tun() {
  std::uniform_int_distribution<uint64_t> dist(0, tuns.size() - 1);
  return &*tuns.at(dist(rand_gen));
}

void Router::register_route(IPAddress addr,
                            std::shared_ptr<RoutingEndpoint> &&endpoint) {
  std::unique_lock<std::shared_mutex> lg(routes_mu);
  bool existed_before = routes.find(addr) != routes.end();
  routes[addr] = std::move(endpoint);

  if (!existed_before) {
    update_os_route(addr, "add");
  }
}

void Router::unregister_route(IPAddress addr, __uint128_t ck_pid) {
  std::unique_lock<std::shared_mutex> lg(routes_mu);
  if (auto it = routes.find(addr);
      it != routes.end() && it->second->ck_pid == ck_pid) {
    routes.erase(it);
    update_os_route(addr, "del");
  }
}

void Router::dispatch_packet(volatile uint8_t *unsafe_data, size_t len,
                             std::shared_ptr<AppNetworkProfile> profile) {
  PacketMetadata metadata;
  if (auto maybe_md = decode_packet_header(unsafe_data, len)) {
    metadata = maybe_md.value();
  } else {
    return;
  }

  if (profile) {
    if (!profile->no_source_verification) {
      if (!metadata.is_ipv6 &&
          (!profile->ipv4_address ||
           *profile->ipv4_address != (uint32_t)metadata.src_addr))
        return;
      if (metadata.is_ipv6 && (!profile->ipv6_address ||
                               *profile->ipv6_address != metadata.src_addr))
        return;
    }
  }

  std::shared_ptr<RoutingEndpoint> endpoint;

  {
    std::shared_lock<std::shared_mutex> lg(routes_mu);
    if (auto it = routes.find(metadata.dst_addr); it != routes.end()) {
      endpoint = it->second;
    }
  }

  if (endpoint) {
    if (endpoint->on_packet)
      endpoint->on_packet(metadata.header, metadata.header_size,
                          unsafe_data + metadata.header_size,
                          len - metadata.header_size);
  } else {
    iovec iov[2];
    iov[0].iov_base = (void *)metadata.header;
    iov[0].iov_len = metadata.header_size;
    iov[1].iov_base = (void *)(unsafe_data + metadata.header_size);
    iov[1].iov_len = len - metadata.header_size;
    choose_tun()->writev(iov, 2); // packet to outside
  }
}

void Router::run_loop(Tun *dev) {
  uint8_t buf[1500];

  while (true) {
    int n = dev->read(buf, sizeof(buf));
    if (n <= 0) {
      std::cout << "tun->read() failed: " << n << std::endl;
      continue;
    }
    dispatch_packet(buf, n);
  }
}

Tun::Tun(const char *name, bool multiqueue) {
  int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    throw std::runtime_error("cannot open tun device");
  }

  ifreq ifr;
  memset((char *)&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if (multiqueue)
    ifr.ifr_flags |= IFF_MULTI_QUEUE;

  if (name) {
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
  }

  if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
    close(fd);
    throw std::runtime_error("cannot set ifreq");
  }

  this->fd = fd;
}

Tun::~Tun() { close(fd); }

int Tun::write(const uint8_t *packet, size_t len) {
  return ::write(fd, packet, len);
}

int Tun::read(uint8_t *packet, size_t len) { return ::read(fd, packet, len); }

int Tun::writev(const iovec *iov, int iovcnt) {
  return ::writev(fd, iov, iovcnt);
}

int Tun::readv(const iovec *iov, int iovcnt) {
  return ::readv(fd, iov, iovcnt);
}

static int futex(int *uaddr, int futex_op, int val,
                 const struct timespec *timeout, int *uaddr2, int val3) {
  return syscall(__NR_futex, (long)uaddr, (long)futex_op, (long)val,
                 (long)timeout, (long)uaddr2, (long)val3);
}

SharedQueue::SharedQueue(size_t new_num_elements)
    : num_elements(new_num_elements),
      shm(sizeof(SharedQueueElement) * new_num_elements, false) {
  if (num_elements == 0) {
    throw std::runtime_error("number of elements must be greater than zero");
  }
  elements = (SharedQueueElement *)shm.get_mapping();
}

SharedQueue::~SharedQueue() {
  // storage destruction handled by SharedMemory
}

uint8_t *SharedQueue::get_data_ptr() { return elements[next_element].data; }

bool SharedQueue::can_push() {
  return elements[next_element].filled.load() ? false : true;
}

void SharedQueue::push(size_t len) {
  SharedQueueElement *element = &elements[next_element];
  element->len.store(len);
  element->filled.store(true);

  futex((int *)&element->filled, FUTEX_WAKE, 1, nullptr, nullptr, 0);

  if (next_element + 1 == num_elements)
    next_element = 0;
  else
    next_element++;
}

bool SharedQueue::can_pop() {
  return elements[next_element].filled.load() ? true : false;
}

bool SharedQueue::wait_pop() {
  SharedQueueElement *element = &elements[next_element];
  while (!element->filled.load()) {
    if (termination_requested.load())
      return false;
    timespec timeout = {
        .tv_sec = 0,
        .tv_nsec = 100 * 1000 * 1000, // 100 ms
    };
    int code =
        futex((int *)&element->filled, FUTEX_WAIT, 0, &timeout, nullptr, 0);
    int err = errno;
    if (code == 0)
      continue;
    if (code == -1 && (err == EINTR || err == EAGAIN || err == ETIMEDOUT))
      continue;
    throw std::logic_error("unexpected result from futex(FUTEX_WAIT)");
  }
  return true;
}

size_t SharedQueue::current_len() {
  uint64_t len = elements[next_element].len.load();
  if (len > data_size())
    return 0;
  else
    return len;
}

void SharedQueue::pop() {
  elements[next_element].filled.store(false);
  if (next_element + 1 == num_elements)
    next_element = 0;
  else
    next_element++;
}