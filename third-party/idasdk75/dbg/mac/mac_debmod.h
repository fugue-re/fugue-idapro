#ifndef __MAC_DEBUGGER_MODULE__
#define __MAC_DEBUGGER_MODULE__

/*
*  This is the mach (MAC OS X) debugger module
*
*  Functions unique for Mach (MAC OS X)
*
*/
#include <map>

#include <pro.h>
#include <fpro.h>
#include <err.h>
#include <ida.hpp>
#include <idp.hpp>
#include <idd.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <diskio.hpp>
#include <ua.hpp>

#define MD msg("at line %d\n", __LINE__);

#define processor_t mach_processor_t

#include <grp.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <mach-o/reloc.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>
#include <mach/mach.h>
#include <mach/shared_region.h>
#include <Security/Security.h>
#include <Security/SecCode.h> // needed for SDK versions <= 10.7
#undef processor_t

#include "macbase_debmod.h"

typedef int HANDLE;
class mac_debmod_t;

#define INVALID_HANDLE_VALUE (-1)

//--------------------------------------------------------------------------
//
//      DEBUGGER INTERNAL DATA
//
//--------------------------------------------------------------------------
enum run_state_t
{
  rs_running,
  rs_pausing,
  rs_suspended, // used by iphone
  rs_exiting,
  rs_exited
};

// image information
struct image_info_t
{
  ea_t base;
  asize_t size;
  qstring name;
  bytevec_t uuid;

  image_info_t() { clear(); }
  image_info_t(ea_t _base, uint32 _size, const qstring &_name, const bytevec_t &_uuid)
    : base(_base), size(_size), name(_name), uuid(_uuid) {}

  void clear()
  {
    base = BADADDR;
    size = 0;
    name.clear();
    uuid.clear();
  }
};

typedef std::map<ea_t, image_info_t> images_t; // key: image base address

union my_mach_msg_t
{
  mach_msg_header_t hdr;
  char data[1024];
  void display(const char *header);
};

//--------------------------------------------------------------------------
enum block_type_t
{
  bl_none,                      // process is running
  bl_signal,                    // blocked due to a signal (must say PTRACE_CONT)
  bl_exception,                 // blocked due to an exception (must say task_resume())
};

//--------------------------------------------------------------------------
// thread information
//-V:ida_thread_info_t:730 Not all members of a class are initialized inside the constructor. Consider inspecting: excmsg.
struct ida_thread_info_t
{
  ida_thread_info_t(thid_t t, mach_port_t p)
    : tid(t), port(p), child_signum(0), asked_step(false), single_step(false),
    pending_sigstop(false), block(bl_none), run_handled(false) {}
  int tid;
  mach_port_t port;
  int child_signum;
  bool asked_step;
  bool single_step;
  bool pending_sigstop;
  block_type_t block;
  my_mach_msg_t excmsg;
  bool run_handled;
  bool blocked(void) const { return block != bl_none; }
};

typedef std::map<int, ida_thread_info_t> threads_t; // (tid -> info)

//--------------------------------------------------------------------------
struct mach_exception_port_info_t
{
  exception_mask_t masks[EXC_TYPES_COUNT];
  mach_port_t ports[EXC_TYPES_COUNT];
  exception_behavior_t behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t flavors[EXC_TYPES_COUNT];
  mach_msg_type_number_t count;
};

typedef qvector<struct nlist_64> nlists_t;

//--------------------------------------------------------------------------
struct mach_exception_info_t
{
  task_t task_port;
  thread_t thread_port;
  exception_type_t exception_type;
  exception_data_t exception_data;
  mach_msg_type_number_t data_count;
};

//--------------------------------------------------------------------------
typedef janitor_t<AuthorizationRef> auth_ref_janitor_t;
template <> inline auth_ref_janitor_t::~janitor_t()
{
  if ( resource != NULL )
    AuthorizationFree(resource, kAuthorizationFlagDefaults);
}

//--------------------------------------------------------------------------
typedef janitor_t<AuthorizationRights *> auth_rights_janitor_t;
template <> inline auth_rights_janitor_t::~janitor_t()
{
  if ( resource != NULL )
    AuthorizationFreeItemSet(resource);
}

//--------------------------------------------------------------------------
typedef janitor_t<SecCodeRef> sec_code_janitor_t;
template <> inline sec_code_janitor_t::~janitor_t()
{
  if ( resource != NULL )
    CFRelease(resource);
}

struct vm_region_visitor_t
{
  virtual int visit_region(memory_info_t &mi) = 0;
};

//--------------------------------------------------------------------------
struct machine_thread_state_t
{
  ea_t __eax;
  ea_t __ebx;
  ea_t __ecx;
  ea_t __edx;
  ea_t __edi;
  ea_t __esi;
  ea_t __ebp;
  ea_t __esp;
  ea_t __eip;
  ea_t __r8;
  ea_t __r9;
  ea_t __r10;
  ea_t __r11;
  ea_t __r12;
  ea_t __r13;
  ea_t __r14;
  ea_t __r15;
  ea_t __eflags;
  ea_t __ss;
  ea_t __cs;
  ea_t __ds;
  ea_t __es;
  ea_t __fs;
  ea_t __gs;
};

//--------------------------------------------------------------------------
struct machine_float_state_t
{
  uint16 __fpu_fcw;
  uint16 __fpu_fsw;
  uint8  __fpu_ftw;
  uint16 __fpu_fop;
  uint32 __fpu_ip;
  uint16 __fpu_cs;
  uint32 __fpu_dp;
  uint16 __fpu_ds;
  uint32 __fpu_mxcsr;
  uint32 __fpu_mxcsrmask;

  _STRUCT_MMST_REG __fpu_stmm0;
  _STRUCT_MMST_REG __fpu_stmm1;
  _STRUCT_MMST_REG __fpu_stmm2;
  _STRUCT_MMST_REG __fpu_stmm3;
  _STRUCT_MMST_REG __fpu_stmm4;
  _STRUCT_MMST_REG __fpu_stmm5;
  _STRUCT_MMST_REG __fpu_stmm6;
  _STRUCT_MMST_REG __fpu_stmm7;

  _STRUCT_XMM_REG  __fpu_xmm0;
  _STRUCT_XMM_REG  __fpu_xmm1;
  _STRUCT_XMM_REG  __fpu_xmm2;
  _STRUCT_XMM_REG  __fpu_xmm3;
  _STRUCT_XMM_REG  __fpu_xmm4;
  _STRUCT_XMM_REG  __fpu_xmm5;
  _STRUCT_XMM_REG  __fpu_xmm6;
  _STRUCT_XMM_REG  __fpu_xmm7;
  _STRUCT_XMM_REG  __fpu_xmm8;
  _STRUCT_XMM_REG  __fpu_xmm9;
  _STRUCT_XMM_REG  __fpu_xmm10;
  _STRUCT_XMM_REG  __fpu_xmm11;
  _STRUCT_XMM_REG  __fpu_xmm12;
  _STRUCT_XMM_REG  __fpu_xmm13;
  _STRUCT_XMM_REG  __fpu_xmm14;
  _STRUCT_XMM_REG  __fpu_xmm15;

  _STRUCT_XMM_REG  __fpu_ymmh0;
  _STRUCT_XMM_REG  __fpu_ymmh1;
  _STRUCT_XMM_REG  __fpu_ymmh2;
  _STRUCT_XMM_REG  __fpu_ymmh3;
  _STRUCT_XMM_REG  __fpu_ymmh4;
  _STRUCT_XMM_REG  __fpu_ymmh5;
  _STRUCT_XMM_REG  __fpu_ymmh6;
  _STRUCT_XMM_REG  __fpu_ymmh7;
  _STRUCT_XMM_REG  __fpu_ymmh8;
  _STRUCT_XMM_REG  __fpu_ymmh9;
  _STRUCT_XMM_REG  __fpu_ymmh10;
  _STRUCT_XMM_REG  __fpu_ymmh11;
  _STRUCT_XMM_REG  __fpu_ymmh12;
  _STRUCT_XMM_REG  __fpu_ymmh13;
  _STRUCT_XMM_REG  __fpu_ymmh14;
  _STRUCT_XMM_REG  __fpu_ymmh15;
};

//--------------------------------------------------------------------------
struct machine_debug_state_t
{
  ea_t __dr0;
  ea_t __dr1;
  ea_t __dr2;
  ea_t __dr3;
  ea_t __dr4;
  ea_t __dr5;
  ea_t __dr6;
  ea_t __dr7;
};

//--------------------------------------------------------------------------
class mac_debmod_t: public macbase_debmod_t
{
  typedef macbase_debmod_t inherited;
public:
  procinfo_vec_t processes;

  // debugged process information
  mach_port_t task;        // debugged application's task port

  cpu_type_t cputype;      // process' CPU type (e.g. CPU_TYPE_I386 or CPU_TYPE_X86_64)

  bool in_ptrace;          // We use ptrace to start the debugging session
                           // but since it is badly broken, we detach and
                           // revert to low-level mach api immediately after that

  run_state_t run_state;

  dyld_utils_t dyld;

  image_info_t exeimg;     // image info for the exe module

  images_t dlls;           // list of loaded dynamic libraries

  easet_t dlls_to_import;  // list of dlls to import information from

  inline bool exited(void)
  {
    return run_state == rs_exited;
  }

  threads_t threads;

  struct stored_signal_t
  {
    pid_t pid;
    int status;
  };
  typedef qvector<stored_signal_t> stored_signals_t;
  static stored_signals_t pending_signals; // signals retrieved by other threads

  bool attaching;          // Handling events linked to PTRACE_ATTACH, don't run the program yet
  bool is64;               // is target 64-bit?

  mach_port_t exc_port;
  mach_exception_port_info_t saved_exceptions;

  regctx_t *reg_ctx;

  mac_debmod_t();
  ~mac_debmod_t();

  void init_reg_ctx(void);
  void term_reg_ctx(void);

  void handle_dyld_bpt(const debug_event_t *event);
  bool retrieve_pending_signal(int *status);
  kern_return_t read_mem(ea_t ea, void *buffer, int size, int *read_size);
  void unblock_all_threads();
  void resume_all_threads();
  bool suspend_all_threads();
  bool my_resume_thread(ida_thread_info_t &ti);
  pid_t qwait(int *status, bool hang);
  void get_debug_events(int timeout_ms);
  kern_return_t
    catch_exception_raise(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    exception_data_t code_vector,
    mach_msg_type_number_t code_count);
  ea_t get_ip(thid_t tid);
  uval_t get_dr(thid_t tid, int idx);
  bool set_dr(thid_t tid, int idx, uval_t value);
  bool idaapi thread_get_fs_base(thid_t tid, int reg_idx, ea_t *pea);
  bool parse_macho_image(macho_visitor_t &mv, const image_info_t &ii);
  void clean_stack_regions(meminfo_vec_t &miv) const;
  drc_t get_memory_info(meminfo_vec_t &miv, bool suspend);
  void init_dyld(void);
  void init_exeimg(pid_t _pid, thid_t tid);
  void update_dyld(void);
  bool exist_dll(const images_t &images, ea_t base);
  virtual bool refresh_hwbpts() override;
  virtual bool set_hwbpts(int hThread) newapi;
  bool handle_process_start(pid_t _pid);
  void term_exception_ports(void);
  void init_exception_ports(void);
  thid_t init_main_thread(bool reattaching);
  bool update_threads(void);
  bool thread_exit_event_planned(thid_t tid);
  void cleanup(void);
  bool xfer_memory(ea_t ea, void *buffer, int size, bool write);
  void add_dll(const image_info_t &ii);
  int _write_memory(ea_t ea, const void *buffer, int size, bool suspend=false);
  int _read_memory(ea_t ea, void *buffer, int size, bool suspend=false);
  bool xfer_page(ea_t ea, void *buffer, int size, bool write);
  kern_return_t write_mem(ea_t ea, void *buffer, int size);
  int exception_to_signal(const mach_exception_info_t *exinf);
  bool check_for_exception(int timeout, mach_exception_info_t *exinf);
  bool handle_signal(
        int code,
        debug_event_t *event,
        block_type_t block,
        const my_mach_msg_t *excmsg);
  bool check_for_exception(
        int timeout,
        mach_exception_info_t *exinf,
        my_mach_msg_t *excmsg);
  bool is_task_valid(task_t task);
  int32 qptrace(int request, pid_t pid, caddr_t addr, int data);
  ida_thread_info_t *get_thread(thid_t tid);
  int handle_bpts(debug_event_t *event, bool asked_step);

  //--------------------------------------------------------------------------
  #define DEFINE_GET_STATE_FUNC(name, type, flavor, flavor_count)       \
  bool name(thid_t tid, type *state)                                    \
  {                                                                     \
    ida_thread_info_t *ti = get_thread(tid);                            \
    if ( ti == NULL )                                                   \
      return false;                                                     \
    mach_port_t port = ti->port;                                        \
    mach_msg_type_number_t stateCount = flavor_count;                   \
    kern_return_t err;                                                  \
    err = thread_get_state(port,                                        \
                           flavor,                                      \
                           (thread_state_t)state,                       \
                           &stateCount);                                \
    QASSERT(30105, stateCount == flavor_count);                         \
    if ( err != KERN_SUCCESS )                                          \
    {                                                                   \
      debdeb("tid=%d port=%d: " #name ": %s\n", tid, port, mach_error_string(err)); \
      return false;                                                     \
    }                                                                   \
    return true;                                                        \
  }

  #define DEFINE_SET_STATE_FUNC(name, type, flavor, flavor_count) \
  bool name(thid_t tid, const type *state)                        \
  {                                                               \
    ida_thread_info_t *ti = get_thread(tid);                      \
    if ( ti == NULL )                                             \
      return false;                                               \
    mach_port_t port = ti->port;                                  \
    mach_msg_type_number_t stateCount = flavor_count;             \
    kern_return_t err;                                            \
    err = thread_set_state(port,                                  \
                           flavor,                                \
                           (thread_state_t)state,                 \
                           stateCount);                           \
    QASSERT(30106, stateCount == flavor_count);                   \
    return err == KERN_SUCCESS;                                   \
  }

  DEFINE_GET_STATE_FUNC(get_thread_state64, x86_thread_state64_t, x86_THREAD_STATE64, x86_THREAD_STATE64_COUNT)
  DEFINE_SET_STATE_FUNC(set_thread_state64, x86_thread_state64_t, x86_THREAD_STATE64, x86_THREAD_STATE64_COUNT)
  DEFINE_GET_STATE_FUNC(get_thread_state32, x86_thread_state32_t, x86_THREAD_STATE32, x86_THREAD_STATE32_COUNT)
  DEFINE_SET_STATE_FUNC(set_thread_state32, x86_thread_state32_t, x86_THREAD_STATE32, x86_THREAD_STATE32_COUNT)
  DEFINE_GET_STATE_FUNC(get_float_state64,  x86_avx_state64_t,    x86_AVX_STATE64,    x86_AVX_STATE64_COUNT)
  DEFINE_SET_STATE_FUNC(set_float_state64,  x86_avx_state64_t,    x86_AVX_STATE64,    x86_AVX_STATE64_COUNT)
  DEFINE_GET_STATE_FUNC(get_float_state32,  x86_avx_state32_t,    x86_AVX_STATE32,    x86_AVX_STATE32_COUNT)
  DEFINE_SET_STATE_FUNC(set_float_state32,  x86_avx_state32_t,    x86_AVX_STATE32,    x86_AVX_STATE32_COUNT)
  DEFINE_GET_STATE_FUNC(get_debug_state64,  x86_debug_state64_t,  x86_DEBUG_STATE64,  x86_DEBUG_STATE64_COUNT)
  DEFINE_SET_STATE_FUNC(set_debug_state64,  x86_debug_state64_t,  x86_DEBUG_STATE64,  x86_DEBUG_STATE64_COUNT)
  DEFINE_GET_STATE_FUNC(get_debug_state32,  x86_debug_state32_t,  x86_DEBUG_STATE32,  x86_DEBUG_STATE32_COUNT)
  DEFINE_SET_STATE_FUNC(set_debug_state32,  x86_debug_state32_t,  x86_DEBUG_STATE32,  x86_DEBUG_STATE32_COUNT)

  bool get_thread_state(thid_t tid, machine_thread_state_t *state);
  bool set_thread_state(thid_t tid, const machine_thread_state_t *state);
  bool get_float_state(thid_t tid, machine_float_state_t *state);
  bool set_float_state(thid_t tid, const machine_float_state_t *state);
  bool get_debug_state(thid_t tid, machine_debug_state_t *state);
  bool set_debug_state(thid_t tid, const machine_debug_state_t *state);

  bool qthread_setsinglestep(ida_thread_info_t &ti);

  bool patch_reg_context(
        machine_thread_state_t *cpu,
        machine_float_state_t *fpu,
        int reg_idx,
        const regval_t *value) const;

  //--------------------------------------------------------------------------
  inline thid_t maintid(void)
  {
    return threads.begin()->first;
  }

  void create_process_start_event(pid_t pid, thid_t tid);
  void create_process_attach_event(pid_t pid);

  //
  virtual void idaapi dbg_set_debugging(bool _debug_debugger) override;
  virtual drc_t idaapi dbg_init(uint32_t *flags2, qstring *errbuf) override;
  virtual void idaapi dbg_term(void) override;
  virtual drc_t idaapi dbg_detach_process(void) override;
  virtual drc_t idaapi dbg_start_process(
        const char *path,
        const char *args,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32,
        qstring *errbuf) override;
  virtual gdecode_t idaapi dbg_get_debug_event(debug_event_t *event, int timeout_ms) override;
  virtual drc_t idaapi dbg_attach_process(
        pid_t process_id,
        int event_id,
        int flags,
        qstring *errbuf) override;
  virtual drc_t idaapi dbg_prepare_to_pause_process(qstring *errbuf) override;
  virtual drc_t idaapi dbg_exit_process(qstring *errbuf) override;
  virtual drc_t idaapi dbg_continue_after_event(const debug_event_t *event) override;
  virtual void idaapi dbg_stopped_at_debug_event(
        import_infos_t *infos,
        bool dlls_added,
        thread_name_vec_t *thr_names) override;
  virtual drc_t idaapi dbg_thread_suspend(thid_t thread_id) override;
  virtual drc_t idaapi dbg_thread_continue(thid_t thread_id) override;
  virtual drc_t idaapi dbg_set_resume_mode(thid_t thread_id, resume_mode_t resmod) override;
  virtual drc_t idaapi dbg_read_registers(
        thid_t thread_id,
        int clsmask,
        regval_t *values,
        qstring *errbuf) override;
  virtual drc_t idaapi dbg_write_register(
        thid_t thread_id,
        int reg_idx,
        const regval_t *value,
        qstring *errbuf) override;
  virtual drc_t idaapi dbg_thread_get_sreg_base(
        ea_t *ea,
        thid_t thread_id,
        int sreg_value,
        qstring *errbuf) override;
  virtual drc_t idaapi dbg_get_memory_info(meminfo_vec_t &miv, qstring *errbuf) override;
  virtual int idaapi dbg_get_scattered_image(scattered_image_t &sci, ea_t base) override;
  virtual bool idaapi dbg_get_image_uuid(bytevec_t *uuid, ea_t base) override;
  virtual ea_t idaapi dbg_get_segm_start(ea_t base, const qstring &segname) override;
  virtual ssize_t idaapi dbg_read_memory(ea_t ea, void *buffer, size_t size, qstring *errbuf) override;
  virtual ssize_t idaapi dbg_write_memory(ea_t ea, const void *buffer, size_t size, qstring *errbuf) override;
  virtual int idaapi dbg_add_bpt(bytevec_t *orig_bytes, bpttype_t type, ea_t ea, int len) override;
  virtual int idaapi dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len) override;
  virtual bool idaapi write_registers(
        thid_t tid,
        int start,
        int count,
        const regval_t *values) override;

  virtual int dbg_freeze_threads_except(thid_t tid) override;
  virtual int dbg_thaw_threads_except(thid_t tid) override;

  virtual bool idaapi dbg_continue_broken_connection(pid_t pid) override;
  virtual bool idaapi dbg_prepare_broken_connection(void) override;

  void get_image_meminfo(meminfo_vec_t &out, const image_info_t &ii);

  int get_task_suspend_count(void);

  int visit_vm_regions(vm_region_visitor_t &rv);

  static bool acquire_taskport_right();
  static bool verify_code_signature();
  static bool verify_user_privilege();

  bool import_symbols(const image_info_t &ii);

  virtual bool import_dll(const import_request_t &req) override;

  bool get_image_info(image_info_t *ii, ea_t base) const;
};

#endif
