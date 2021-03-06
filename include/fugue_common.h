#pragma once

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <sstream>
#include <exception>
#include <vector>

#include <fugue_generated.h>

#ifdef _WIN32
#define NOMINMAX 1
#include <windows.h>
#include <shlwapi.h>
#include <io.h>
#include <sys\stat.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fugue
{

  const int EXIT_OK = 100;
  const int EXIT_IO_ERROR = 101;
  const int EXIT_IMPORT_ERROR = 102;
  const int EXIT_UNSUPPORTED_ERROR = 103;
  const int EXIT_REBASE_ERROR = 104;

  uint64_t start_timestamp = 0;

  struct BasicBlock;
  struct Function;
  struct Segment;

  template <typename T>
  class Id
  {
  public:
    Id() : id{std::numeric_limits<uint32_t>::max()} {}
    Id(uint32_t id) : id{id} {}

    inline size_t index() const { return id; }
    inline uint32_t value() const { return id; }

    friend bool operator<(const Id<T> &l, const Id<T> &r)
    {
      return l.id < r.id;
    }

    friend bool operator==(const Id<T> &l, const Id<T> &r)
    {
      return l.id == r.id;
    }

  private:
    uint32_t id;
  };

  template <>
  class Id<BasicBlock>
  {
  public:
    Id() : id(std::numeric_limits<uint64_t>::max()) {}
    Id(const Id<Function> &fid, uint32_t id) : id(static_cast<uint64_t>(fid.value()) << 32ULL | id) {}

    inline size_t index() const { return id & 0xffffffffULL; }
    inline uint64_t value() const { return id; }

    friend bool operator<(const Id<BasicBlock> &l, const Id<BasicBlock> &r)
    {
      return l.id < r.id;
    }

    friend bool operator==(const Id<BasicBlock> &l, const Id<BasicBlock> &r)
    {
      return l.id == r.id;
    }

  private:
    uint64_t id;
  };

  inline bool opt_true(const std::string &opt)
  {
    return std::equal(std::begin(opt), std::end(opt), "true", [](char a, char b) { return tolower(a) == tolower(b); });
  }

  inline bool file_exists(const char *path)
  {
#ifdef _WIN32
    return PathFileExists(path) == TRUE;
#else
    struct stat file_info;
    if (stat(path, &file_info) == -1)
    {
      return false;
    }
    return S_ISREG(file_info.st_mode);
#endif
  }

  inline uint64_t current_timestamp()
  {
#ifdef _WIN32
    auto now = std::chrono::system_clock::now();
#else
    auto now = std::chrono::high_resolution_clock::now();
#endif
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
  }

  template <typename Architecture>
  class ProjectBuilder
  {
  public:
    ProjectBuilder() : arches{}, message{1024}, project_aux{1024} {
      project_aux_off = project_aux.StartMap();
    }

    bool write_to_file(const std::string &path)
    {
#ifdef _WIN32
      int fd = 0;
      errno_t err = _sopen_s(&fd, path.c_str(), _O_CREAT | _O_TRUNC | _O_BINARY | _O_WRONLY, _SH_DENYNO, _S_IREAD | _S_IWRITE);
      if (err != 0)
      {
        msg("Fugue IDB exporter: could not open file for writing\n");
        return false;
      }
#else
      int fd = open(path.c_str(), O_CREAT | O_TRUNC | O_BINARY | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
      if (fd < 0)
      {
        msg("Fugue IDB exporter: could not open file for writing\n");
        return false;
      }
#endif

      build_arches();
      build_project();

      auto success = false;
      uint8_t *buf = message.GetBufferPointer();
      size_t size = message.GetSize();

#ifdef _WIN32
      ssize_t result = _write(fd, buf, size);
#else
      ssize_t result = write(fd, buf, size);
#endif
      if (static_cast<size_t>(result) == size) {
        success = true;
      } else {
        msg("Fugue IDB exporter: ");

        char errbuf[80] = { 0 };

#ifdef _WIN32
        bool ok = 0 == _strerror_s(errbuf, nullptr);
#else
        bool ok = 0 == strerror_r(errno, errbuf, sizeof(errbuf));
#endif

        if (ok) {
          msg("%s", errbuf);
        } else {
          msg("could not write serialised database to file\n");
        }

        success = false;
      }

#ifdef _WIN32
      _close(fd);
#else
      close(fd);
#endif

      return success;
    }

    Id<Architecture> architecture(Architecture &&arch)
    {
      if (auto idt = arches.find(arch); idt != std::end(arches))
      {
        return idt->second;
      }

      auto id = Id<Architecture>(std::size(arches));
      arches.insert({arch, id});
      return id;
    }

    inline void set_metadata(
        const std::string &input_format,
        const std::string &input_path,
        const std::vector<uint8_t> &input_md5,
        const std::vector<uint8_t> &input_sha256,
        uint32_t input_size,
        const std::string &exporter)
    {
      metadata = fugue::schema::CreateMetadataDirect(
          message,
          input_format.c_str(),
          input_path.c_str(),
          &input_md5,
          &input_sha256,
          input_size,
          exporter.c_str()
      );
    }

    inline void reserve_functions(size_t amount)
    {
      functions.resize(amount);
    }

    inline void reserve_function_blocks(size_t amount)
    {
      function_blocks.clear();
      function_blocks.resize(amount);
    }

    inline void reserve_function_refs(size_t amount)
    {
      function_refs.clear();
      function_refs.resize(amount);
    }

    inline void set_function(Id<Function> id, const std::string &symbol, uint64_t address, Id<BasicBlock> entry)
    {
      auto symbol_str = message.CreateString(symbol);
      auto fblocks = message.CreateVector(function_blocks.data(), std::size(function_blocks));
      auto frefs = message.CreateVector(function_refs.data(), std::size(function_refs));

      functions[id.index()] = fugue::schema::CreateFunction(
          message,
          symbol_str,
          address,
          entry.value(),
          fblocks,
          frefs
      );
    }

    inline void reserve_block_succs(size_t amount)
    {
      block_succs = std::vector<flatbuffers::Offset<fugue::schema::IntraRef>>(amount);
    }

    inline void reserve_block_preds(size_t amount)
    {
      block_preds = std::vector<flatbuffers::Offset<fugue::schema::IntraRef>>(amount);
    }

    inline void set_block(Id<BasicBlock> bid, uint64_t address, uint32_t size, Id<Architecture> arch)
    {
      auto bpreds = message.CreateVector(block_preds.data(), std::size(block_preds));
      auto bsuccs = message.CreateVector(block_succs.data(), std::size(block_succs));

      function_blocks[bid.index()] = fugue::schema::CreateBasicBlock(
          message,
          address,
          size,
          arch.value(),
          bpreds,
          bsuccs
      );
    }

    inline void set_function_ref(Id<Function> fid, size_t index, uint64_t address, Id<Function> source, bool call)
    {
      function_refs[index] = fugue::schema::CreateInterRefDirect(
          message,
          address,
          source.value(),
          fid.value(),
          call
      );
    }

    inline void set_block_pred(Id<Function> fid, Id<BasicBlock> bid, size_t index, Id<BasicBlock> source)
    {
      block_preds[index] = fugue::schema::CreateIntraRefDirect(
          message,
          source.value(),
          bid.value(),
          fid.value()
      );
    }

    inline void set_block_succ(Id<Function> fid, Id<BasicBlock> bid, size_t index, Id<BasicBlock> target)
    {
      block_succs[index] = fugue::schema::CreateIntraRefDirect(
          message,
          bid.value(),
          target.value(),
          fid.value()
      );
    }

    inline size_t function_count()
    {
      auto *proj = fugue::schema::GetProject(message.GetBufferPointer());
      return proj->functions()->size();
    }

    inline size_t segment_count()
    {
      auto *proj = fugue::schema::GetProject(message.GetBufferPointer());
      return proj->segments()->size();
    }

    inline std::string function_names()
    {
      auto ss = std::stringstream();
      auto *proj = fugue::schema::GetProject(message.GetBufferPointer());

      auto fns = proj->functions();
      for (auto fn = fns->begin(); fn != fns->end(); ++fn)
      {
        auto symbol = fn->symbol();
        auto s = symbol->c_str();
        ss << s << std::endl;
      }
      return ss.str();
    }

    inline void reserve_segments(size_t amount)
    {
      segments.resize(amount);
    }

    inline uint8_t *reserve_segment_bytes(size_t amount) {
      uint8_t *ptr = nullptr;
      segment_bytes = message.CreateUninitializedVector<uint8_t>(amount, &ptr);
      return ptr;
    }

    inline void set_segment(
        Id<Segment> id,
        const std::string &name,
        uint64_t address,
        uint32_t size,
        uint32_t address_size,
        uint32_t alignment,
        uint32_t bits,
        bool endian,
        bool code,
        bool data,
        bool external,
        bool readable,
        bool writable,
        bool executable)
    {
      auto name_str = message.CreateString(name);
      segments[id.index()] = fugue::schema::CreateSegment(
          message,
          name_str,
          address,
          size,
          address_size,
          alignment,
          bits,
          endian,
          code,
          data,
          external,
          readable,
          writable,
          executable,
          segment_bytes);
    }

    template<typename F> inline size_t vector_aux(const char *name, F f)
    {
      return project_aux.Vector(name, f);
    }

    inline size_t string_aux(const char *s)
    {
      return project_aux.String(s);
    }

    inline void uint64_aux(uint64_t v)
    {
      project_aux.UInt(v);
    }

  private:
    inline void build_arches()
    {
      architectures.resize(std::size(arches));
      for (auto &[arch, id] : arches)
      {
        auto processor = message.CreateString(arch.processor);
        auto variant = message.CreateString(arch.variant);

        architectures[id.index()] = fugue::schema::CreateArchitecture(
            message,
            processor,
            arch.is_be,
            arch.bits,
            variant
        );
      }
    }

    inline void build_project()
    {
      auto archv = message.CreateVector(architectures);
      auto segsv = message.CreateVector(segments);
      auto funsv = message.CreateVector(functions);

      project_aux.EndMap(project_aux_off);

      auto aux_buf = project_aux.GetBuffer();
      uint8_t *aux_ptr = nullptr;

      auto aux = message.CreateUninitializedVector<uint8_t>(std::size(aux_buf), &aux_ptr);
      std::copy(std::begin(aux_buf), std::end(aux_buf), aux_ptr);

      project = fugue::schema::CreateProject(
          message,
          archv,
          segsv,
          funsv,
          metadata,
          aux
      );
      fugue::schema::FinishProjectBuffer(message, project);
    }

    std::map<Architecture, Id<Architecture>> arches;
    flatbuffers::FlatBufferBuilder message;

    size_t project_aux_off;
    flexbuffers::Builder project_aux;

    // architectures
    std::vector<flatbuffers::Offset<fugue::schema::Architecture>> architectures;

    // metadata
    flatbuffers::Offset<fugue::schema::Metadata> metadata;

    // functions
    std::vector<flatbuffers::Offset<fugue::schema::Function>> functions;
    std::vector<flatbuffers::Offset<fugue::schema::BasicBlock>> function_blocks;
    std::vector<flatbuffers::Offset<fugue::schema::InterRef>> function_refs;

    // blocks
    std::vector<flatbuffers::Offset<fugue::schema::IntraRef>> block_succs;
    std::vector<flatbuffers::Offset<fugue::schema::IntraRef>> block_preds;

    // segments
    std::vector<flatbuffers::Offset<fugue::schema::Segment>> segments;
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> segment_bytes;

    // project
    flatbuffers::Offset<fugue::schema::Project> project;
  };

}; // namespace fugue
