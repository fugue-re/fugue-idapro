/*
        This is the MAC OS X x86 user land debugger entry point file
*/
#ifndef __GNUC__
//lint -esym(750, __LITTLE_ENDIAN__) not referenced
#define __LITTLE_ENDIAN__
#endif
//#define __inline__ inline
#define REMOTE_DEBUGGER
#define RPC_CLIENT

static const char wanted_name[] = "Remote Mac OS X debugger";
#define DEBUGGER_NAME  "macosx"
#define PROCESSOR_NAME "metapc"
#define DEFAULT_PLATFORM_NAME "macosx"
#define TARGET_PROCESSOR PLFM_386
#define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_MACOSX_USER
#define DEBUGGER_FLAGS (DBG_FLAG_REMOTE    \
                      | DBG_FLAG_LOWCNDS   \
                      | DBG_FLAG_DEBTHREAD)
#define DEBUGGER_RESMOD (DBG_RESMOD_STEP_INTO)
#define HAVE_APPCALL
#define S_FILETYPE     f_MACHO
#define SET_DBG_OPTIONS set_mac_options
#define MAC_NODE "$ remote mac options"

#include <pro.h>
#include <idp.hpp>
#include <idd.hpp>
#include <ua.hpp>
#include <range.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <network.hpp>

#include "dbg_rpc_client.h"
#include "rpc_debmod.h"
#include "symmacho.hpp"

class rstub_debmod_t : public rpc_debmod_t
{
  typedef rpc_debmod_t inherited;

public:
  dyld_utils_t dyld;

  rstub_debmod_t() : inherited(DEFAULT_PLATFORM_NAME), dyld(this, TARGET_PROCESSOR) {}

  // handle an RPC_IMPORT_DLL request from the server. see SYMBOL_PATH in dbg_macosx.cfg.
  virtual bool import_dll(const import_request_t &req) override
  {
    dyld.update_bitness();
    struct ida_local dll_importer_t : public macho_visitor_t
    {
      dll_importer_t() : macho_visitor_t(MV_SYMBOLS) {}
      void visit_symbol(ea_t ea, const char *name) override
      {
        set_debug_name(ea, name);
      }
    };
    dll_importer_t di;
    return dyld.parse_local_symbol_file(req.base, req.path.c_str(), req.uuid, di);
  }
};

rstub_debmod_t g_dbgmod;
#include "common_stub_impl.cpp"

#include "pc_local_impl.cpp"
#include "mac_local_impl.cpp"
#include "common_local_impl.cpp"
