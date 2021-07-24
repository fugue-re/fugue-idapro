// read Mach-O symbols

#include <pro.h>
#include <diskio.hpp>
#include "debmod.h"
#include "../../ldr/ar/ar.hpp"
#include "../../ldr/ar/aixar.hpp"
#include "../../ldr/ar/arcmn.cpp" // for is_ar_file
#define BUILD_DEBUGGER
#include "../../ldr/mach-o/common.cpp"
#include "../../ldr/mach-o/dsym.cpp"
#include "symmacho.hpp"

//--------------------------------------------------------------------------
macho_utils_t::macho_utils_t(debmod_t *_dbgmod, int _arch)
  : dbgmod(_dbgmod),
    arch(_arch),
    addrsize(DEF_ADDRSIZE),
    is64(false),
    warned(false)
{
}

//--------------------------------------------------------------------------
void macho_utils_t::clear(void)
{
  addrsize = DEF_ADDRSIZE;
  is64 = false;
  warned = false;
  strcache.clear();
}

//--------------------------------------------------------------------------
int macho_utils_t::get_cputype(void) const
{
  switch ( arch )
  {
    case PLFM_386:
      return is64 ? CPU_TYPE_X86_64 : CPU_TYPE_I386;
    case PLFM_ARM:
      return is64 ? CPU_TYPE_ARM64 : CPU_TYPE_ARM;
    default:
      break;
  }
  return CPU_TYPE_ANY;
}

//--------------------------------------------------------------------------
size_t macho_utils_t::read_mem(ea_t ea, void *buf, size_t bufsize)
{
  return dbgmod->dbg_read_memory(ea, buf, bufsize, NULL);
}

//--------------------------------------------------------------------------
void macho_utils_t::update_bitness()
{
  debapp_attrs_t attrs;
  dbgmod->dbg_get_debapp_attrs(&attrs);
  addrsize = attrs.addrsize;
  is64 = addrsize > 4;
}

//--------------------------------------------------------------------------
linput_t *macho_utils_t::create_mem_input(ea_t base)
{
  struct ida_local meminput_t : public generic_linput_t
  {
    ea_t base;
    macho_utils_t *mu;
    meminput_t(ea_t _base, macho_utils_t *_mu) : base(_base), mu(_mu)
    {
      // macho images in memory have indeterminate size.
      // set it to the max possible size to keep anybody from complaining.
      filesize = INT_MAX;
      blocksize = 0;
    }
    virtual ssize_t idaapi read(qoff64_t off, void *buffer, size_t nbytes) override
    {
      return mu->read_mem(base+off, buffer, nbytes);
    }
  };
  meminput_t *pmi = new meminput_t(base, this);
  return create_generic_linput(pmi);
}

//--------------------------------------------------------------------------
void macho_utils_t::get_ptr_value(ea_t *val, const uchar *buf) const
{
  if ( addrsize == 8 )
    *val = *(const uint64 *)buf;
  else
    *val = *(const uint32 *)buf;
}

//--------------------------------------------------------------------------
static void visit_macho_segments(macho_file_t &mfile, macho_visitor_t &mv)
{
  const segcmdvec_t &segcmds = mfile.get_segcmds();
  const secvec_t &sections = mfile.get_sections();

  for ( size_t i = 0, size = segcmds.size(); i < size; i++ )
  {
    const segment_command_64 &sg = segcmds[i];
    if ( sg.vmsize == 0 )
      continue;

    qstring segname(sg.segname, sizeof(sg.segname));
    if ( (mv.flags & MV_SEGMENTS) != 0 )
    {
      mv.visit_segment(
          sg.vmaddr + mv.slide,
          sg.vmaddr + sg.vmsize + mv.slide,
          segname,
          (sg.flags & VM_PROT_EXECUTE) != 0 || segname == SEG_TEXT);
    }

    if ( (mv.flags & MV_SECTIONS) != 0 )
    {
      // special check for the header
      if ( sections.size() > 0
        && strneq(segcmds[i].segname, "__TEXT", 6)
        && segcmds[i].vmaddr < sections[0].addr )
      {
        mv.visit_section(
            segcmds[i].vmaddr + mv.slide,
            sections[0].addr + mv.slide,
            "HEADER",
            segname,
            false);
      }

      // visit all sections in the segment
      for ( size_t j = 0; j < sg.nsects; j++ )
      {
        const section_64 &sect = sections[mfile.get_seg2section(i) + j];
        qstring sectname(sect.sectname, sizeof(sect.sectname));
        mv.visit_section(
            sect.addr + mv.slide,
            sect.addr + sect.size + mv.slide,
            sectname,
            segname,
            (sect.flags & (S_ATTR_PURE_INSTRUCTIONS|S_ATTR_SOME_INSTRUCTIONS)) != 0);
      }
    }
  }
}

//--------------------------------------------------------------------------
static void visit_macho_symbols(
        const nlistvec_t &symbols,
        const qstring &strings,
        macho_visitor_t &mv,
        int cputype)
{
  for ( size_t i=0; i < symbols.size(); i++ )
  {
    const struct nlist_64 &nl = symbols[i];
    if ( nl.n_un.n_strx > strings.size() )
      continue;

    const char *name = &strings[nl.n_un.n_strx];
    if ( qstrlen(name) == 0 )
      continue;

    ea_t ea = nl.n_value + mv.slide;

    int type = nl.n_type & N_TYPE;
    switch ( type )
    {
      case N_UNDF:
      case N_PBUD:
      case N_ABS:
      case N_INDR:
        break;
      case N_SECT:
        // process exported and private symbols
        if ( ((nl.n_type & (N_EXT|N_PEXT)) == N_EXT) || nl.n_sect != NO_SECT )
        {
          // only set thumb-ness for arm32 symbols in the __text section (n_sect=1)
          if ( cputype == CPU_TYPE_ARM && nl.n_sect == 1 )
            mv.handle_thumb(ea, name, (nl.n_desc & 0xF) == N_ARM_THUMB_DEF);

          mv.visit_symbol(ea, name);
        }
        break;
      default:
        break;
    }
  }
}

//--------------------------------------------------------------------------
static void visit_macho_function_starts(
        macho_file_t &mfile,
        macho_visitor_t &mv,
        int cputype)
{
  struct ida_local symmacho_fsv_t : public function_starts_visitor_t
  {
    macho_visitor_t &mv;
    int cputype;

    symmacho_fsv_t(macho_visitor_t &_mv, int _cputype)
      : mv(_mv), cputype(_cputype) {}

    virtual int visit_start(uint64_t address) override
    {
      // create a debugger-friendly address
      if ( cputype == CPU_TYPE_ARM && (address & 1) != 0 )
        address ^= 1;
      mv.visit_function_start(address + mv.slide);
      return 0;
    }
    virtual void handle_error() override
    {
      mv.handle_function_start_error();
    }
  };

  symmacho_fsv_t fsv(mv, cputype);
  mfile.visit_function_starts(fsv);
}

//--------------------------------------------------------------------------
static void visit_macho_uuid(macho_file_t &mfile, macho_visitor_t &mv)
{
  uint8 uuid[16];
  if ( mfile.get_uuid(uuid) )
    mv.uuid = bytevec_t(uuid, sizeof(uuid));
}

//--------------------------------------------------------------------------
bool macho_utils_t::parse_macho_file(
        const char *path,
        ea_t base,
        macho_visitor_t &mv,
        const bytevec_t &uuid) const
{
  linput_t *li = open_linput(path, false);
  if ( li == NULL )
    return false;
  linput_janitor_t janitor(li);
  if ( !match_macho_uuid(li, uuid) )
    return false;
  return parse_macho_input(li, base, mv);
}

//--------------------------------------------------------------------------
static bool get_platform_version(
        macho_visitor_t &mv,
        const macho_platform_version_t &mpv)
{
  if ( mpv.plfm != 0 && mpv.major != 0 )
  {
    if ( mpv.plfm == PLATFORM_MACOS )
      mv.version = mpv.minor; // major is always 10 for OSX, which is assumed
    else
      mv.version = mpv.major;
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
static bool visit_macho_platform_info(macho_file_t &mfile, macho_visitor_t &mv)
{
  macho_platform_version_info_t mpvi;
  if ( !mfile.get_platform_version_info(&mpvi) )
    return false;

  // platform version could be encoded in multiple different load commands.
  // the sdk versions usually provide the most accurate info.
  return get_platform_version(mv, mpvi.build_sdk)
      || get_platform_version(mv, mpvi.min_sdk)
      || get_platform_version(mv, mpvi.build_minos)
      || get_platform_version(mv, mpvi.min_version);
}

//--------------------------------------------------------------------------
static bool parse_macho_common(
        macho_file_t &mfile,
        macho_visitor_t &mv,
        ea_t base,
        int cputype)
{
  if ( !mfile.parse_header() || !mfile.select_subfile(cputype) )
    return false;

  mv.subtype = mfile.get_mach_header().filetype;

  ea_t maxea = 0;
  ea_t imagebase = BADADDR;
  const segcmdvec_t &segcmds = mfile.get_segcmds();

  // since mac os x can scatter application segments over the memory
  // we calculate only the text segment size
  for ( size_t i = 0; i < segcmds.size(); i++ )
  {
    const segment_command_64 &sg = segcmds[i];
    if ( is_text_segment(sg) )
    {
      if ( imagebase == BADADDR )
        imagebase = sg.vmaddr;
      ea_t end = sg.vmaddr + sg.vmsize;
      if ( maxea < end )
        maxea = end;
    }
  }

  if ( imagebase == BADADDR )
    return false;

  mv.size = maxea - imagebase;
  if ( base != BADADDR )
    mv.slide = base - imagebase;

  if ( (mv.flags & MV_UUID) != 0 )
    visit_macho_uuid(mfile, mv);

  if ( (mv.flags & MV_FUNCTION_STARTS) != 0 )
    visit_macho_function_starts(mfile, mv, cputype);

  if ( (mv.flags & (MV_SEGMENTS|MV_SECTIONS)) != 0 )
    visit_macho_segments(mfile, mv);

  if ( (mv.flags & MV_PLATFORM_INFO) != 0 )
    visit_macho_platform_info(mfile, mv);

  return true;
}

//--------------------------------------------------------------------------
bool macho_utils_t::parse_macho_input(
        linput_t *li,
        ea_t base,
        macho_visitor_t &mv) const
{
  macho_file_t mfile(li);
  int cputype = get_cputype();

  if ( !parse_macho_common(mfile, mv, base, cputype) )
    return false;

  if ( (mv.flags & MV_SYMBOLS) != 0 )
  {
    qstring strings;
    nlistvec_t symbols;
    mfile.get_symbol_table_info(&symbols, &strings);
    visit_macho_symbols(symbols, strings, mv, cputype);
  }

  return true;
}

//--------------------------------------------------------------------------
bool macho_utils_t::parse_macho_mem(ea_t base, macho_visitor_t &mv, uint32 hints)
{
  linput_t *li = create_mem_input(base);
  if ( li == NULL )
    return false;

  linput_janitor_t janitor(li);

  macho_file_t mfile(li, 0, MACHO_HINT_MEM_IMAGE | hints);
  int cputype = get_cputype();

  if ( !parse_macho_common(mfile, mv, base, cputype) )
    return false;

  if ( (mv.flags & MV_SYMBOLS) != 0 )
  {
    struct symtab_command st = { 0 };
    if ( !mfile.get_symtab_command(&st) )
      return false;

    nlistvec_t symbols;
    mfile.get_symbol_table(st, &symbols);

    // check if this is a new string table
    strings_cache_t::const_iterator i = strcache.find(st.stroff);
    if ( i == strcache.end() )
    {
      qstring buf;
      mfile.get_string_table(st, &buf);
      const qstring &strings = strcache.insert(std::make_pair(st.stroff, buf)).first->second;
      visit_macho_symbols(symbols, strings, mv, cputype);
    }
    else
    {
      // if not, use the existing one
      visit_macho_symbols(symbols, i->second, mv, cputype);
    }
  }

  return true;
}

//--------------------------------------------------------------------------
bool macho_utils_t::calc_macho_uuid(bytevec_t *out, linput_t *li) const
{
  uint8 uuid[16];
  macho_file_t mfile(li);

  if ( mfile.parse_header()
    && mfile.select_subfile(get_cputype())
    && mfile.get_uuid(uuid) )
  {
    *out = bytevec_t(uuid, sizeof(uuid));
    return true;
  }

  return false;
}

//--------------------------------------------------------------------------
bool macho_utils_t::match_macho_uuid(linput_t *li, const bytevec_t &uuid) const
{
  macho_file_t mfile(li);

  return mfile.parse_header()
      && mfile.select_subfile(get_cputype())
      && mfile.match_uuid(uuid);
}

//--------------------------------------------------------------------------
bool macho_utils_t::is_exe_header(ea_t base)
{
  macho_visitor_t v;
  parse_macho_mem(base, v);
  return v.subtype == MH_EXECUTE;
}

//--------------------------------------------------------------------------
bool macho_utils_t::calc_image_info(
        uint32 *subtype,
        asize_t *size,
        bytevec_t *uuid,
        linput_t *li,
        ea_t base) const
{
  macho_visitor_t v(MV_UUID);
  if ( !parse_macho_input(li, base, v) )
    return false;

  if ( subtype != NULL )
    *subtype = v.subtype;
  if ( size != NULL )
    *size = v.size;
  if ( uuid != NULL )
    *uuid = v.uuid;

  return true;
}

//--------------------------------------------------------------------------
bool macho_utils_t::calc_image_info(
        uint32 *subtype,
        asize_t *size,
        bytevec_t *uuid,
        const char *path) const
{
  linput_t *li = open_linput(path, false);
  if ( li == NULL )
    return false;
  bool ok = calc_image_info(subtype, size, uuid, li, BADADDR);
  close_linput(li);
  return ok;
}

//--------------------------------------------------------------------------
bool macho_utils_t::calc_image_info(
        uint32 *subtype,
        asize_t *size,
        bytevec_t *uuid,
        ea_t base)
{
  linput_t *li = create_mem_input(base);
  if ( li == NULL )
    return false;
  bool ok = calc_image_info(subtype, size, uuid, li, base);
  close_linput(li);
  return ok;
}

//--------------------------------------------------------------------------
qstring macho_utils_t::expand_home_dir(const char *path)
{
  qstring home;
  qstring tmp(path);

  char buf[QMAXPATH];
  if ( tmp.length() > 0 && tmp[0] == '~' && qgetenv("HOME", &home) )
    return qmakepath(buf, sizeof(buf), home.c_str(), tmp.substr(1).c_str(), NULL);

  return path;
}

//--------------------------------------------------------------------------
// merge 2 range sets
// high priority overrides what is defined in low priority
// FIXME: this function was stolen from ui/memregs.cpp. Since memregs.cpp is
// part of the ui, we can't use it when building the mac_server, and I don't
// think this code is worth moving into dumb.a.
void macho_utils_t::merge(
        meminfo_vec_t &res,
        const meminfo_vec_t &low,
        const meminfo_vec_t &high)
{
  if ( low.empty() )
  {
    res = high;
    return;
  }

  if ( high.empty() )
  {
    res = low;
    return;
  }

  int l = 0;
  meminfo_vec_t tmp;
  ea_t end = 0;
  ea_t lea = low[0].start_ea;
  for ( int h=0; ; h++ )
  {
    ea_t hea = h < high.size() ? high[h].start_ea : BADADDR;
    if ( hea != end )
    {
      while ( l < low.size() && lea < hea )
      { // add ranges before the high priority range
        if ( low[l].end_ea > end )
        {
          tmp.push_back(low[l]);
          if ( end >= lea )
            tmp.back().start_ea = end;
          end = low[l].end_ea;
          if ( end > hea )
          {
            end = lea = hea;
            tmp.back().end_ea = end;
            break;
          }
        }
        l++;
        if ( l < low.size() )
          lea = low[l].start_ea;
      }
    }
    if ( h == high.size() )
      break;
    tmp.push_back(high[h]);
    end = high[h].end_ea;
  }
  tmp.swap(res);
}

//--------------------------------------------------------------------------
dyld_utils_t::dyld_utils_t(debmod_t *_dbgmod, int _arch)
  : inherited(_dbgmod, _arch)
{
  base_ea = BADADDR;
  entry_ea = BADADDR;
  infos_ea = BADADDR;
  ranges_ea = BADADDR;
}

//--------------------------------------------------------------------------
void dyld_utils_t::clear(void)
{
  inherited::clear();
  infos.clear();
  shared_cache_ranges.clear();
  base_ea = BADADDR;
  entry_ea = BADADDR;
  infos_ea = BADADDR;
  ranges_ea = BADADDR;
}

//--------------------------------------------------------------------------
void dyld_all_image_infos_t::clear()
{
  version = 0;
  num_info = 0;
  info_array = 0;
  dyld_notify = 0;
  dyld_image_load_address = 0;
  dyld_image_infos_address = 0;
  shared_cache_slide = 0;
  shared_cache_base_address = 0;
}

//--------------------------------------------------------------------------
bool dyld_utils_t::untag(ea_t *ea) const
{
  if ( !is64 )
    return false;

  uint64 mask = 0;
  switch ( arch )
  {
    case PLFM_ARM:
      // MACH_VM_MAX_ADDRESS = 0x0000000FC0000000, tag stored in bits 36-63
      mask = uint64(0xFFFFFFF) << 36;
      break;
    case PLFM_386:
      // MACH_VM_MAX_ADDRESS = 0x00007FFFFFE00000, tag stored in bits 48-63
      mask = uint64(0xFFFF) << 48;
      break;
  }

  ea_t orig = *ea;
  ea_t addr = uint64(orig) & ~mask;
  if ( addr != orig )
  {
    *ea = addr;
    return true;
  }

  return false;
}

//--------------------------------------------------------------------------
bool dyld_utils_t::update_infos()
{
  // read the important fields from _dyld_all_image_infos in a version-independent
  // and bitness-independent manner.
  infos.clear();
  if ( infos_ea == BADADDR )
    return false;
  ea_t off = infos_ea;
  if ( !read(off, &infos.version, sizeof(infos.version)) || infos.version < 1 )
    return false;
  off += sizeof(infos.version);
  if ( !read(off, &infos.num_info, sizeof(infos.num_info)) )
    return false;
  off += sizeof(infos.num_info);
  if ( !read(off, &infos.info_array, addrsize) )
    return false;
  off += addrsize;
  if ( !read(off, &infos.dyld_notify, addrsize) || infos.version < 2 )
    return false;
  off += addrsize      // dyld_notify
       + sizeof(uint8) // processDetachedFromSharedRegion
       + sizeof(uint8) // libSystemInitialized
       + addrsize - 2; // padding
  if ( !read(off, &infos.dyld_image_load_address, addrsize) || infos.version < 9 )
    return false;
  off += addrsize      // dyldImageLoadAddress
       + addrsize      // jitInfo
       + addrsize      // dyldVersion
       + addrsize      // errorMessage
       + addrsize      // terminationFlags
       + addrsize      // coreSymbolicationShmPage
       + addrsize      // systemOrderFlag
       + addrsize      // uuidArrayCount
       + addrsize;     // uuidArray
  if ( !read(off, &infos.dyld_image_infos_address, addrsize) )
    return false;
  // we will need to know the base address of the shared cache for OSX 10.13/iOS 11 and later
  if ( infos.version >= 15 )
  {
    off += addrsize    // dyldAllImageInfosAddress
         + addrsize    // initialImageCount
         + addrsize    // errorKind
         + addrsize    // errorClientOfDylibPath
         + addrsize    // errorTargetDylibPath
         + addrsize;   // errorSymbol
    if ( !read(off, &infos.shared_cache_slide, addrsize) )
      return false;
    off += addrsize    // sharedCacheSlide
         + 16;         // sharedCacheUUID
    if ( !read(off, &infos.shared_cache_base_address, addrsize) )
      return false;
  }
  // remove any tags from the pointer values
  untag(&infos.info_array);
  untag(&infos.dyld_notify);
  untag(&infos.dyld_image_load_address);
  untag(&infos.dyld_image_infos_address);
  untag(&infos.shared_cache_base_address);
  // it's possible that dyld has been relocated but the fields in dyld_all_image_infos
  // haven't been updated yet - do it now.
  if ( infos_ea != infos.dyld_image_infos_address )
  {
    adiff_t slide = infos_ea - infos.dyld_image_infos_address;
    infos.dyld_image_load_address += slide;
    infos.dyld_image_infos_address += slide;
    infos.dyld_notify += slide;
    infos.info_array += slide;
  }
  // gdb_image_notifier could be a thumb function - clear the thumb bit if needed
  if ( arch == PLFM_ARM && !is64 && (infos.dyld_notify & 1) != 0 )
    infos.dyld_notify ^= 1;
  return true;
}

//--------------------------------------------------------------------------
bool dyld_utils_t::update_ranges()
{
  if ( !shared_cache_ranges.empty() )
    return true;

  if ( ranges_ea != BADADDR )
  {
    // parse the _dyld_shared_cache_ranges symbol in memory
    ea_t count = 0;
    if ( !read(ranges_ea, &count, addrsize) )
      return false;

    for ( ea_t i = 0, ptr = ranges_ea + addrsize; i < count; i++, ptr += 2 * addrsize )
    {
      ea_t start = 0;
      if ( !read(ptr, &start, addrsize) )
        return false;

      ea_t size = 0;
      if ( !read(ptr+addrsize, &size, addrsize) )
        return false;

      range_t r(start, start+size);
      dbgmod->dmsg("shared cache range: %a..%a\n", r.start_ea, r.end_ea);
      shared_cache_ranges.add(r);
    }
  }
  else
  {
    // _dyld_shared_cache_ranges is no longer present in dyld for OSX 10.13/iOS 11.
    // fall back to parsing the mappings in the dyld cache header.
    dbgmod->debdeb("parsing cache header: version=%d, shared_cache_base_address=%a, shared_cache_slide=%a\n",
                   infos.version,
                   infos.shared_cache_base_address,
                   infos.shared_cache_slide);

    struct ida_local mapping_visitor_t : public dyld_cache_visitor_t
    {
      debmod_t *dm;
      rangeset_t *ranges;

      mapping_visitor_t(debmod_t *_dm, rangeset_t *_ranges)
        : dyld_cache_visitor_t(DCV_MAPPINGS), dm(_dm), ranges(_ranges) {}

      virtual void visit_mapping(ea_t start_ea, ea_t end_ea) override
      {
        dm->dmsg("shared cache mapping: %a..%a\n", start_ea, end_ea);
        ranges->add(range_t(start_ea, end_ea));
      }
    };

    mapping_visitor_t mapv(dbgmod, &shared_cache_ranges);
    parse_dyld_cache_header(mapv);
  }

  return !shared_cache_ranges.empty();
}

//--------------------------------------------------------------------------
bool dyld_utils_t::parse_info_array(uint32 count, ea_t info_array, dll_visitor_t &dv)
{
  size_t bufsize = count * addrsize * 3; // 3 pointers per dyld_image_info element

  bytevec_t buf;
  buf.resize(bufsize);

  if ( !read(info_array, buf.begin(), bufsize) )
    return false;

  const uchar *ptr = buf.begin();
  const uchar *end = buf.begin() + bufsize;

  for ( ; ptr < end; ptr += addrsize * 3 )
  {
    // dyld_image_info::addr
    ea_t base = 0;
    get_ptr_value(&base, ptr);

    // dyld_image_info::name
    ea_t name_ptr = 0;
    get_ptr_value(&name_ptr, ptr+addrsize);

    char name[1024] = { 0 };
    read(name_ptr, name, sizeof(name)); // may fail because we don't know exact size
    name[sizeof(name)-1] = '\0';

    asize_t size = 0;
    bytevec_t uuid;
    calc_image_info(NULL, &size, &uuid, base);

    dv.visit_dll(base, size, name, uuid);
  }

  return true;
}

//--------------------------------------------------------------------------
template <typename H> bool dyld_utils_t::is_dyld_header(
        ea_t base,
        char *filename,
        size_t namesize,
        uint32 magic)
{
  H mh;
  if ( !read(base, &mh, sizeof(mh)) )
    return false;

  if ( mh.magic != magic || mh.filetype != MH_DYLINKER )
    return false;

  // seems to be dylib
  // find its file name
  filename[0] = '\0';
  ea_t ea = base + sizeof(mh);
  for ( int i=0; i < mh.ncmds; i++ )
  {
    struct load_command lc;
    lc.cmd = 0;
    read(ea, &lc, sizeof(lc));
    if ( lc.cmd == LC_ID_DYLIB )
    {
      struct dylib_command dcmd;
      read(ea, &dcmd, sizeof(dcmd));
      read(ea+dcmd.dylib.name.offset, filename, namesize);
      break;
    }
    else if ( lc.cmd == LC_ID_DYLINKER )
    {
      struct dylinker_command dcmd;
      read(ea, &dcmd, sizeof(dcmd));
      read(ea+dcmd.name.offset, filename, namesize);
      break;
    }
    ea += lc.cmdsize;
  }

  return true;
}

//--------------------------------------------------------------------------
bool dyld_utils_t::is_dyld_header_64(ea_t base, char *filename, size_t namesize)
{
  return is_dyld_header<mach_header_64>(base, filename, namesize, MH_MAGIC_64);
}

//--------------------------------------------------------------------------
bool dyld_utils_t::is_dyld_header_32(ea_t base, char *filename, size_t namesize)
{
  return is_dyld_header<mach_header>(base, filename, namesize, MH_MAGIC);
}

//--------------------------------------------------------------------------
bool dyld_utils_t::is_dyld_header(ea_t base, char *filename, size_t namesize)
{
  return is64
       ? is_dyld_header_64(base, filename, namesize)
       : is_dyld_header_32(base, filename, namesize);
}

//--------------------------------------------------------------------------
bool dyld_utils_t::parse_dyld_cache_header(dyld_cache_visitor_t &dcv)
{
  ea_t base = infos.shared_cache_base_address;
  if ( base == 0 )
    return false;

  linput_t *li = create_mem_input(base);
  if ( li == NULL )
    return false;

  dyld_cache_t dyldcache(li);
  linput_janitor_t janitor(li);

  uint32 hflags = (dcv.flags & DCV_MAPPINGS) != 0 ? PHF_MAPPINGS : 0;

  if ( !dyldcache.parse_header(hflags) )
    return false;

  ea_t slide = infos.shared_cache_slide;

  if ( (dcv.flags & DCV_MAPPINGS) != 0 )
  {
    for ( int i = 0, nmaps = dyldcache.get_nummappings(); i < nmaps; i++ )
    {
      const dyld_cache_mapping_info &mi = dyldcache.get_mapping_info(i);
      ea_t start_ea = mi.address + slide;
      ea_t end_ea   = mi.address + slide + mi.size;
      dcv.visit_mapping(start_ea, end_ea);
    }
  }

  return true;
}

//--------------------------------------------------------------------------
bool dyld_utils_t::parse_macho_mem(ea_t base, macho_visitor_t &mv, uint32 hints)
{
  if ( is_shared_cache_lib(base) )
    hints |= MACHO_HINT_SHARED_CACHE_LIB;

  return inherited::parse_macho_mem(base, mv, hints);
}

//--------------------------------------------------------------------------
bool dyld_utils_t::get_symbol_file_path(qstring *path, const char *module) const
{
  if ( symbol_path.empty() )
    return false;

  char buf[QMAXPATH];
  qmakepath(buf, sizeof(buf), symbol_path.c_str(), module, NULL);
  *path = inherited::expand_home_dir(buf);

  return true;
}

//--------------------------------------------------------------------------
bool dyld_utils_t::parse_local_symbol_file(
        ea_t base,
        const char *module,
        const bytevec_t &uuid,
        macho_visitor_t &mv)
{
  qstring path;
  if ( !get_symbol_file_path(&path, module) )
  {
    // we only show a warning for the iOS debugger, since it's a more serious issue.
    // symbol loading is almost unusably slow when the local symbol cache is not present,
    // so we make sure the user has a hint of what's wrong.
    if ( arch == PLFM_ARM && !warned )
    {
      msg("WARNING: No path to local symbol cache specified. Symbol loading might be very slow. "
          "You can set SYMBOL_PATH in the debugger's cfg file for faster and more detailed debugging.\n");
      warned = true;
    }
    return false;
  }

  linput_t *li = open_linput(path.c_str(), false);
  linput_janitor_t lij(li);

  if ( li == NULL )
  {
    // It is normal that a library on the remote machine does not have a corresponding local symbol file.
    // Still, we print a message in case the user is looking for symbols in this missing module,
    // or if they have accidentally set SYMBOL_PATH in the cfg to a bogus directory - in which case
    // a ton of these messages will be printed and it should be pretty obvious what is wrong.
    msg("WARNING: symbol file not found %s.\n", path.c_str());
    return false;
  }

  if ( !match_macho_uuid(li, uuid) )
  {
    // This is a pretty serious issue and we should print a warning message for the user.
    // Symbol files extracted from different iOS/OSX machines may not be compatible, even if
    // they have the exact same iOS version. This stumped me for a little while
    // and it would have been nice if I had this message.
    msg("WARNING: UUID mismatch for symbol file %s. "
        "Please make sure SYMBOL_PATH in the debugger's cfg file points to symbols that are compatible with the remote machine.\n",
        path.c_str());
    return false;
  }

  return parse_macho_input(li, base, mv);
}

//--------------------------------------------------------------------------
void kernel_utils_t::clear(void)
{
  inherited::clear();

  kdk_path.clear();
  prelinked_kexts.clear();
  prelink_data_off = 0;

  if ( kcache_li != NULL )
    close_linput(kcache_li);

  kcache_li = NULL;
}

//--------------------------------------------------------------------------
void kernel_utils_t::set_kdk_path(const qstring &path)
{
  kdk_path = macho_utils_t::expand_home_dir(path.c_str());
}

//--------------------------------------------------------------------------
struct callback_info_t
{
  qstring path;
  uint32 flags;
  callback_info_t(uint32 _flags) : flags(_flags) {}
};

//--------------------------------------------------------------------------
static int kdk_callback(
        macho_file_t &,
        void *ud,
        const char *path,
        const macho_ident_t &ident)
{
  callback_info_t *info = (callback_info_t *)ud;

  if ( (info->flags & KDK_SEARCH_KCACHE) != 0 && (ident.flags & AUF_IS_KCACHE) == 0 )
    return -1; // not a kernelcache

  if ( (info->flags & KDK_SEARCH_DSYM) != 0 )
  {
    struct ida_local lambda_t
    {
      static int accept(macho_file_t &, void *, const char *, const macho_ident_t &)
      {
        return 0; // accept file
      }
    };
    if ( find_dsym_macho(path, ident, lambda_t::accept, NULL) != 0 )
      return -1; // no companion dsym
  }

  info->path = path;
  return 0;
}

//--------------------------------------------------------------------------
bool kernel_utils_t::find_kdk_file(
        qstring *path,
        int cpu_subtype,
        const bytevec_t &uuid,
        const char *name,
        uint32 flags) const
{
  if ( kdk_path.empty() )
    return false;

  if ( uuid.size() != sizeof(macho_ident_t::uuid) )
    return false;

  macho_ident_t ident;
  ident.cpu_type = get_cputype();
  ident.cpu_subtype = cpu_subtype;

  memcpy(ident.uuid, uuid.begin(), sizeof(ident.uuid));

  int code = -1;
  callback_info_t info(flags);
  const char *dir = kdk_path.c_str();

  switch ( cpu_subtype )
  {
    case MH_EXECUTE:
      code = find_dsym_kernel(dir, ident, kdk_callback, &info);
      break;
    case MH_KEXT_BUNDLE:
      code = find_dsym_kext(dir, ident, name, kdk_callback, &info);
      break;
  }

  if ( code != 0 )
    return false;

  if ( path != NULL )
    *path = info.path;

  return true;
}

//--------------------------------------------------------------------------
uint64 kernel_utils_t::find_kext_offset(const bytevec_t &uuid) const
{
  for ( size_t i = 0, size = prelinked_kexts.size(); i < size; i++ )
  {
    if ( prelinked_kexts[i].uuid == uuid )
      return prelinked_kexts[i].off;
  }
  return BADADDR64;
}

//--------------------------------------------------------------------------
bool kernel_utils_t::parse_prelinked_kext(
        macho_visitor_t &mv,
        ea_t base,
        const bytevec_t &uuid)
{
  if ( kcache_li == NULL )
    return false;

  uint64 start_off = find_kext_offset(uuid);
  if ( start_off == BADADDR64 )
    return false;

  kcache_single_kmod_input_t *kli = new kcache_single_kmod_input_t(
          kcache_li,
          start_off,
          prelink_data_off);

  linput_t *li = create_generic_linput(kli);
  QASSERT(1750, li != NULL);
  linput_janitor_t lij(li);

  return parse_macho_input(li, base, mv);
}

//--------------------------------------------------------------------------
bool kernel_utils_t::parse_kcache(const bytevec_t &kernel_uuid)
{
  // look for a matching kernelcache in the KDK
  qstring path;
  if ( !find_kdk_file(&path, MH_EXECUTE, kernel_uuid, NULL, KDK_SEARCH_KCACHE) )
    return false;

  kcache_li = open_linput(path.c_str(), false);
  if ( kcache_li == NULL )
    return false;

  macho_file_t kcache(kcache_li);
  if ( !kcache.parse_header() || !kcache.select_subfile(get_cputype()) )
    return false;

  dbgmod->dmsg("found kernelcache: %s\n", path.c_str());

  // extract info about the prelinked kexts. we will use it later.
  const kmod_params_vec_t &kpv = kcache.get_kmod_info();

  for ( size_t i = 0, size = kpv.size(); i < size; i++ )
  {
    kext_info_t &info = prelinked_kexts.push_back();
    info.uuid = bytevec_t(kpv[i].uuid, sizeof(kpv[i].uuid));
    info.off = kpv[i].off;
  }

  section_64 s;
  if ( kcache.get_prelink_data(&s) )
    prelink_data_off = s.offset;

  return true;
}

//--------------------------------------------------------------------------
bool kernel_utils_t::find_kext(const bytevec_t &uuid, const char *kext_name) const
{
  return find_kext_offset(uuid) != BADADDR64
      || find_kdk_file(NULL, MH_KEXT_BUNDLE, uuid, kext_name);
}
