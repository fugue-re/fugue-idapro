#include <loader.hpp>

#include "macho_rebase.cpp"

//--------------------------------------------------------------------------
// installs or uninstalls debugger specific idc functions
inline bool register_idc_funcs(bool)
{
  return true;
}

//--------------------------------------------------------------------------
void idaapi rebase_if_required_to(ea_t new_base)
{
  // not a shared cache lib: it's safe to just use the imagebase
  ea_t base = get_imagebase();
  if ( base == 0 )
  {
    // old databases don't have it set; use info from netnode
    netnode n(MACHO_NODE);
    if ( exist(n) )
      base = n.altval(MACHO_ALT_IMAGEBASE);
  }

  if ( base != BADADDR
    && new_base != BADADDR
    && base != new_base
    && !rebase_scattered_segments(new_base) )
  {
    rebase_or_warn(base, new_base);
  }
}

//--------------------------------------------------------------------------
enum macopt_idx_t
{
  MAC_OPT_SYMBOL_PATH // path to symbols extracted from dyld shared cache
};

//--------------------------------------------------------------------------
struct mac_cfgopt_t
{
  const char *name;
  char type;
  char index;
  void *var;
  size_t size;
};

//lint -esym(843, g_must_save_cfg) could be declared as const
static bool g_must_save_cfg = false;

//--------------------------------------------------------------------------
static const mac_cfgopt_t g_cfgopts[] =
{
  { "SYMBOL_PATH", IDPOPT_STR, MAC_OPT_SYMBOL_PATH, &g_dbgmod.dyld.symbol_path, 0 },
};
CASSERT(IS_QSTRING(g_dbgmod.dyld.symbol_path));

//--------------------------------------------------------------------------
static const mac_cfgopt_t *find_option(const char *name)
{
  for ( int i=0; i < qnumber(g_cfgopts); i++ )
    if ( strcmp(g_cfgopts[i].name, name) == 0 )
      return &g_cfgopts[i];
  return NULL;
}

//--------------------------------------------------------------------------
static void load_mac_options()
{
  if ( !netnode::inited() )
    return;

  netnode node(MAC_NODE);
  if ( !exist(node) )
    return;

  for ( int i = 0; i < qnumber(g_cfgopts); i++ )
  {
    const mac_cfgopt_t &opt = g_cfgopts[i];
    if ( opt.type == IDPOPT_STR )
      node.supstr((qstring *)opt.var, opt.index);
    else
      node.supval(opt.index, opt.var, opt.size);
  }
}

//--------------------------------------------------------------------------
static void save_mac_options()
{
  if ( !g_must_save_cfg || !netnode::inited() )
    return;

  netnode node;
  node.create(MAC_NODE);
  if ( node != BADNODE )
  {
    for ( int i = 0; i < qnumber(g_cfgopts); i++ )
    {
      const mac_cfgopt_t &opt = g_cfgopts[i];
      if ( opt.type == IDPOPT_STR )
        node.supset(opt.index, ((qstring *)opt.var)->c_str(), 0);
      else
        node.supset(opt.index, opt.var, opt.size);
    }
  }

  g_must_save_cfg = false;
}

//--------------------------------------------------------------------------
const char *idaapi set_mac_options(const char *keyword, int pri, int value_type, const void *value)
{
  if ( keyword == NULL )
  {
    static const char form[] =
      "Mac OSX Debugger Options\n%/"
      "<#Path to symbol files extracted from dyld_shared_cache#~S~ymbol path:q:1023:60::>\n";

    qstring path = g_dbgmod.dyld.symbol_path;
    if ( !ask_form(form, NULL, &path) )
      return IDPOPT_OK;

    g_dbgmod.dyld.symbol_path = path;
    g_must_save_cfg = true;
  }
  else
  {
    if ( *keyword == '\0' )
    {
      load_mac_options();
      return IDPOPT_OK;
    }

    const mac_cfgopt_t *opt = find_option(keyword);
    if ( opt == NULL )
      return IDPOPT_BADKEY;
    if ( opt->type != value_type )
      return IDPOPT_BADTYPE;

    if ( opt->type == IDPOPT_STR )
    {
      qstring *pvar = (qstring *)opt->var;
      *pvar = (char *)value;
    }

    if ( pri == IDPOPT_PRI_HIGH )
      g_must_save_cfg = true;
  }

  return IDPOPT_OK;
}

//--------------------------------------------------------------------------
static ssize_t idaapi ui_callback(void *, int notification_code, va_list)
{
  if ( notification_code == ui_saving )
    save_mac_options();
  return 0;
}

//--------------------------------------------------------------------------
static bool init_plugin(void)
{
#ifndef RPC_CLIENT
  if ( !init_subsystem() )
    return false;
#endif

  if ( !netnode::inited() || is_miniidb() || inf_is_snapshot() )
  {
#ifdef __MAC__
    // local debugger is available if we are running under MAC OS X
    return true;
#else
    // for other systems only the remote debugger is available
    return debugger.is_remote();
#endif
  }

  if ( inf_get_filetype() != S_FILETYPE ) // only Mach-O files
    return false;
  processor_t &ph = PH;
  if ( ph.id != TARGET_PROCESSOR && ph.id != -1 )
    return false;

  hook_to_notification_point(HT_UI, ui_callback);
  return true;
}

//--------------------------------------------------------------------------
inline void term_plugin(void)
{
#ifndef RPC_CLIENT
  term_subsystem();
#endif
  unhook_from_notification_point(HT_UI, ui_callback);
  save_mac_options();
}

//--------------------------------------------------------------------------
static const char comment[] = "Userland Mac OS X debugger plugin.";
