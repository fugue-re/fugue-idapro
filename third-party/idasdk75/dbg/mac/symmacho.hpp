#ifndef SYMMACHO_H
#define SYMMACHO_H

// manage the mach-o images in a darwin process

#include <pro.h>
#include <idd.hpp>
#include <map>

class debmod_t;
class linput_t;

typedef std::map<ea_t, qstring> strings_cache_t;

//--------------------------------------------------------------------------
struct macho_visitor_t
{
  int flags;
#define MV_UUID             0x0001 // visit uuid
#define MV_FUNCTION_STARTS  0x0002 // visit function start eas
#define MV_SYMBOLS          0x0004 // visit symbols
#define MV_SEGMENTS         0x0008 // visit segments
#define MV_SECTIONS         0x0010 // visit sections
#define MV_PLATFORM_INFO    0x0020 // visit build version info

  uint32 subtype;  // mh.filetype
  asize_t size;    // image size
  sval_t slide;    // ASLR slide
  bytevec_t uuid;  // filled if MV_UUID is set
  uint32 version;  // platform version

  macho_visitor_t(int _flags = 0)
    : flags(_flags), subtype(0), size(0), slide(0), version(0) {}

  virtual void visit_function_start(ea_t /*ea*/) {}
  virtual void visit_symbol(ea_t /*ea*/, const char * /*name*/) {}
  virtual void visit_segment(ea_t /*start*/, ea_t /*end*/, const qstring & /*name*/, bool /*is_code*/) {}
  virtual void visit_section(ea_t /*start*/, ea_t /*end*/, const qstring & /*sect*/, const qstring & /*seg*/, bool /*is_code*/) {}

  // called when function start info could not be found/loaded
  virtual void handle_function_start_error() {}
  // called just before a symbol is visited when cpu is CPU_TYPE_ARM
  virtual void handle_thumb(ea_t /*ea*/, const char * /*name*/, bool /*is_thumb*/) {}

  DEFINE_VIRTUAL_DTOR(macho_visitor_t)
};

//--------------------------------------------------------------------------
class macho_utils_t
{
public:
  debmod_t *dbgmod;

  int arch;     // PLFM_386 or PLFM_ARM
  int addrsize; // size of an address in the target process
  bool is64;    // is target process 64-bit?
  bool warned;  // warned the user about using SYMBOL_PATH when remote debugging

  // sometimes macho images might share a common string table. ensure the same string table isn't loaded twice.
  strings_cache_t strcache;

  macho_utils_t(debmod_t *_dbgmod, int _arch);
  DEFINE_VIRTUAL_DTOR(macho_utils_t)

  virtual void clear(void);

  int get_cputype(void) const;
  void update_bitness(void);

  size_t read_mem(ea_t ea, void *buf, size_t size);
  bool read(ea_t ea, void *buf, size_t size) { return read_mem(ea, buf, size) == size; }
  void get_ptr_value(ea_t *val, const uchar *buf) const;

  bool is_exe_header(ea_t base);

  virtual bool parse_macho_file(const char *path, ea_t base, macho_visitor_t &mv, const bytevec_t &uuid) const;
  virtual bool parse_macho_input(linput_t *li, ea_t base, macho_visitor_t &mv) const;
  virtual bool parse_macho_mem(ea_t base, macho_visitor_t &mv, uint32 hints = 0);

  linput_t *create_mem_input(ea_t base);

  bool calc_macho_uuid(bytevec_t *uuid, linput_t *li) const;
  bool match_macho_uuid(linput_t *li, const bytevec_t &uuid) const;

  bool calc_image_info(uint32 *subtype, asize_t *size, bytevec_t *uuid, ea_t base);
  bool calc_image_info(uint32 *subtype, asize_t *size, bytevec_t *uuid, const char *path) const;
  bool calc_image_info(uint32 *subtype, asize_t *size, bytevec_t *uuid, linput_t *li, ea_t base) const;

  static qstring expand_home_dir(const char *path);

  static void merge(
        meminfo_vec_t &res,
        const meminfo_vec_t &low,
        const meminfo_vec_t &high);
};

//--------------------------------------------------------------------------
struct dyld_all_image_infos_t
{
  uint32 version;
  uint32 num_info;
  ea_t info_array;
  ea_t dyld_notify;
  ea_t dyld_image_load_address;
  ea_t dyld_image_infos_address;
  ea_t shared_cache_slide;
  ea_t shared_cache_base_address;

  dyld_all_image_infos_t() { clear(); }

  void clear();
};

//--------------------------------------------------------------------------
enum dyld_image_mode_t
{
  DYLD_IMAGE_ERROR = -1,
  DYLD_IMAGE_ADDING = 0,
  DYLD_IMAGE_REMOVING = 1,
  DYLD_IMAGE_INFO_CHANGE = 2,
};

//--------------------------------------------------------------------------
struct dll_visitor_t
{
  virtual void visit_dll(
        ea_t base,
        asize_t size,
        const char *name,
        const bytevec_t &uuid) = 0;

  DEFINE_VIRTUAL_DTOR(dll_visitor_t)
};

//--------------------------------------------------------------------------
struct dyld_cache_visitor_t
{
  int flags;
#define DCV_MAPPINGS 0x1 // visit shared region mappings

  dyld_cache_visitor_t(int _flags) : flags(_flags) {}

  virtual void visit_mapping(ea_t /*start_ea*/, ea_t /*end_ea*/) {}
};

//--------------------------------------------------------------------------
class dyld_utils_t : public macho_utils_t
{
  typedef macho_utils_t inherited;

  template<typename H> bool is_dyld_header(ea_t base, char *filename, size_t namesize, uint32 magic);

  bool is_dyld_header_64(ea_t base, char *filename, size_t namesize);
  bool is_dyld_header_32(ea_t base, char *filename, size_t namesize);

public:
  ea_t base_ea;   // base address of dyld ifself
  ea_t entry_ea;  // dyld's entry point
  ea_t infos_ea;  // address of _dyld_all_image_infos
  ea_t ranges_ea; // address of _dyld_shared_cache_ranges

  dyld_all_image_infos_t infos;

  rangeset_t shared_cache_ranges;

  qstring symbol_path;

  dyld_utils_t(debmod_t *_dbgmod, int _arch);
  DEFINE_VIRTUAL_DTOR(dyld_utils_t)

  virtual void clear(void) override;

  bool is_shared_cache_lib(ea_t base) const { return shared_cache_ranges.contains(base); }
  bool is_system_lib(ea_t base) const { return base == base_ea || is_shared_cache_lib(base); }

  bool is_dyld_header(ea_t base, char *filename, size_t namesize);

  bool update_infos(void);
  bool update_ranges(void);

  virtual bool parse_macho_mem(ea_t base, macho_visitor_t &mv, uint32 hints = 0) override;

  bool parse_info_array(uint32 count, ea_t info_array, dll_visitor_t &dv);
  bool parse_dyld_cache_header(dyld_cache_visitor_t &dcv);

  bool untag(ea_t *ea) const;

  bool get_symbol_file_path(qstring *path, const char *module) const;
  bool parse_local_symbol_file(
        ea_t base,
        const char *module,
        const bytevec_t &uuid,
        macho_visitor_t &mv);
};

struct kext_info_t
{
  uint64 off;
  bytevec_t uuid;
};
DECLARE_TYPE_AS_MOVABLE(kext_info_t);
typedef qvector<kext_info_t> kext_info_vec_t;

//--------------------------------------------------------------------------
class kernel_utils_t : public macho_utils_t
{
  typedef macho_utils_t inherited;

  qstring kdk_path;                // path to a Kernel Development Kit
  linput_t *kcache_li;             // if a kernelcache is present in the KDK, we can use it to parse kexts
  uint64 prelink_data_off;         // offset of __PRELINK_DATA, required for parsing prelinked kexts
  kext_info_vec_t prelinked_kexts; // associate each kext's UUID with its offset in the kernelcache

  uint64 find_kext_offset(const bytevec_t &uuid) const;

public:
  kernel_utils_t(debmod_t *_dbgmod, int _arch)
    : inherited(_dbgmod, _arch), kcache_li(NULL), prelink_data_off(0) {}

  virtual ~kernel_utils_t(void) { kernel_utils_t::clear(); }

  virtual void clear(void) override;

  void set_kdk_path(const qstring &path);

  // detect if a kernelcache is present and collect the prelinked kext info
  bool parse_kcache(const bytevec_t &kernel_uuid);

  // apply the given visitor to a matching kext in the kernelcache
  bool parse_prelinked_kext(macho_visitor_t &mv, ea_t base, const bytevec_t &uuid);

#define KDK_SEARCH_DEFAULT 0x0 // look for any matching binary
#define KDK_SEARCH_DSYM    0x1 // look for a binary with a companion dSYM
#define KDK_SEARCH_KCACHE  0x2 // look for a kernelcache

  // get the path to a matching binary in the KDK
  bool find_kdk_file(
        qstring *path,
        int cpu_subtype,
        const bytevec_t &uuid,
        const char *name,
        uint32 flags = KDK_SEARCH_DEFAULT) const;

  // check if the given kext appears in the KDK, either as a standalone binary
  // or as a prelinked kext in a kernelcache
  bool find_kext(const bytevec_t &uuid, const char *kext_name) const;
};

#endif // SYMMACHO_H
