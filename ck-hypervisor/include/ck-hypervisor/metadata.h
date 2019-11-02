#pragma once

#include <ck-hypervisor/symbol.h>
#include <ck-hypervisor/consts.h>
#include <vector>
#include <string>
#include <functional>
#include <ck-hypervisor/module.h>

class ModuleMetadata {
    public:
    std::string name;
    VersionCode version;
    bool privileged = false;
    std::vector<Symbol> symbols;

    std::vector<uint8_t> serialized;

    void parse(std::function<int (uint8_t *, size_t)> read) {
        uint32_t magic;

        if(read((uint8_t *) &magic, sizeof(magic)) != sizeof(magic)) throw std::runtime_error("unable to read magic");
        if(magic != CK_MODULE_MAGIC) throw std::runtime_error("invalid magic");

        uint32_t num_symbols;
        if(read((uint8_t *) &num_symbols, sizeof(num_symbols)) != sizeof(num_symbols)) throw std::runtime_error("unable to read number of symbols");
        for(uint32_t i = 0; i < num_symbols; i++) {
            Symbol sym;
            
            if(read((uint8_t *) &sym.addr, sizeof(sym.addr)) != sizeof(sym.addr)) throw std::runtime_error("unable to read symbol address");
            uint32_t name_len;
            if(read((uint8_t *) &name_len, sizeof(name_len)) != sizeof(name_len)) throw std::runtime_error("unable to read symbol name length");
            if(name_len > 1024 || name_len == 0) throw std::runtime_error("invalid symbol name");
            sym.name = std::string(name_len, '\0');
            if(read((uint8_t *) &sym.name[0], name_len) != name_len) throw std::runtime_error("unable to read symbol name");
            symbols.push_back(std::move(sym));
        }
    }
};
