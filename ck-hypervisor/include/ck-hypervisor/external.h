#pragma once

#include <vector>

int call_external(const char *cmd, std::vector<const char *> args);
int forked_call_external(const char *cmd, std::vector<const char *> args);
