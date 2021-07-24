#pragma once

#include <ida.hpp>
#include <idp.hpp>
#include <funcs.hpp>
#include <segregs.hpp>
#include <nalt.hpp>
#include <sstream>
#include <string>
#include <vector>

#include "ida_helper.h"

namespace fugue
{
  namespace ida
  {
    uint64_t input_file_size()
    {
      return retrieve_input_file_size();
    }

    std::string input_file_path()
    {
      char buf[8192] = { 0 };
      get_input_file_path(buf, sizeof(buf));
      return std::string(static_cast<const char *>(buf));
    }

    std::vector<uint8_t> input_file_md5()
    {
      uint8_t hash[16];
      retrieve_input_file_md5(hash);
      return std::vector<uint8_t>(static_cast<const uint8_t *>(hash), static_cast<const uint8_t *>(hash + 16));
    }

    std::vector<uint8_t> input_file_sha256()
    {
      uint8_t hash[32];
      retrieve_input_file_sha256(hash);
      return std::vector<uint8_t>(static_cast<const uint8_t *>(hash), static_cast<const uint8_t *>(hash + 32));
    }

    std::string ida_version()
    {
      std::stringstream ss;
      ss << IDA_SDK_VERSION / 100 << "." << (IDA_SDK_VERSION / 10) % 10;
      return ss.str();
    }

    bool is_thumb_ea(ea_t ea)
    {
      const auto T = 20;

      if (get_proc_id() == PLFM_ARM && !inf_is_64bit())
      {
        auto tbit = get_sreg(ea, T);
        return tbit != 0 && tbit != BADSEL;
      }
      return false;
    }

    struct Architecture
    {
      std::string processor;
      std::string variant;
      uint32_t bits;
      bool is_be;

      Architecture(ea_t at = BADADDR)
      {
        auto name = std::string(inf.procname);
#if IDA_SDK_VERSION < 760
        bits = inf_is_64bit() ? 64 : inf_is_32bit() ? 32
#else
        bits = inf_is_64bit() ? 64 : inf_is_32bit_exactly() ? 32
#endif
                                                    : 16;
        is_be = inf_is_be();

        auto family = get_proc_id();
        switch (family)
        {
        case PLFM_386:
          processor = "x86";
          variant = bits != 16 ? "default" : "Protected Mode";
          break;
        case PLFM_ARM:
          if (bits == 64) {
            processor = "AARCH64";
            variant = "v8A";
          } else {
            processor = "ARM";
            variant = "v7";
          }
          break;
        case PLFM_MIPS:
          processor = "MIPS";
          variant = "default";
          break;
        case PLFM_PPC:
          processor = "PowerPC";
          variant = "default";
          break;
/*
        case PLFM_NEC_V850X:
          variant = "V850";
          break;
        case PLFM_SH:
          variant = "SH";
          break;
*/
        default:
          processor = name;
          variant = "";
          break;
        }
      }

      friend bool operator<(const Architecture &l, const Architecture &r)
      {
        // NOTE: we know that all fields but variant will always be constant
        return l.variant < r.variant;
      }
    };

    std::string get_argument(const char *view)
    {
      const char *option = get_plugin_options((std::string("Fugue") + view).c_str());
      return option ? option : "";
    }

  }; // namespace ida
};   // namespace fugue
