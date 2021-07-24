#pragma once

#include <ida.hpp>
#include <string>

using plugin_init_t = decltype(PLUGIN_OK);

#if IDA_SDK_VERSION < 730
bool inf_is_64bit()
{
  return inf.is_64bit();
}

bool inf_is_32bit()
{
  return inf.is_32bit();
}

bool inf_is_be()
{
  return inf.is_be();
}

filetype_t inf_get_filetype()
{
  return (filetype_t)inf.filetype;
}
#endif

int get_proc_id()
{
#if IDA_SDK_VERSION < 750
  return ph.id;
#else
  return PH.id;
#endif
}

std::string get_procname()
{
#if IDA_SDK_VERSION < 730
  return std::string(inf.procname);
#else
  return std::string(inf_get_procname().c_str());
#endif
}
