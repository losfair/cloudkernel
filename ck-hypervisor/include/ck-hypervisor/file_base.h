#pragma once

enum class FileInstanceType {
    INVALID,
    IDMAP, // identical mapping
    HYPERVISOR, // hypervisor fd
    NORMAL, // normal files
    USER, // triggers SIGSYS on I/O
};
