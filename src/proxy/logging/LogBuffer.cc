/** @file

  This file implements the LogBuffer class, a thread-safe buffer for

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  @section description
  This file implements the LogBuffer class, a thread-safe buffer for
  recording log entries. See the header file LogBuffer.h for more
  information on the structure of a LogBuffer.
 */
#include "tscore/ink_platform.h"
#include "tsutil/ts_bw_format.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "../../iocore/eventsystem/P_EventSystem.h"
#include "proxy/logging/LogField.h"
#include "proxy/logging/LogFilter.h"
#include "proxy/logging/LogFormat.h"
#include "proxy/logging/LogUtils.h"
#include "proxy/logging/LogFile.h"
#include "proxy/logging/LogObject.h"
#include "proxy/logging/LogAccess.h"
#include "proxy/logging/LogConfig.h"
#include "proxy/logging/LogBuffer.h"
#include "proxy/logging/Log.h"

struct FieldListCacheElement {
  LogFieldList *fieldlist;
  char         *symbol_str;
};

enum {
  FIELDLIST_CACHE_SIZE = 256,
};

FieldListCacheElement fieldlist_cache[FIELDLIST_CACHE_SIZE];
int                   fieldlist_cache_entries = 0;
int32_t               LogBuffer::M_ID;

namespace
{
DbgCtl dbg_ctl_log_logbuffer{"log-logbuffer"};
DbgCtl dbg_ctl_log_fieldlist{"log-fieldlist"};

} // end anonymous namespace

/*-------------------------------------------------------------------------
  The following LogBufferHeader routines are used to grab strings out from
  the data section using the offsets held in the buffer header.
  -------------------------------------------------------------------------*/

char *
LogBufferHeader::fmt_fieldlist()
{
  char *addr = nullptr;
  if (fmt_fieldlist_offset) {
    addr = reinterpret_cast<char *>(this) + fmt_fieldlist_offset;
  }
  return addr;
}

char *
LogBufferHeader::fmt_printf()
{
  char *addr = nullptr;
  if (fmt_printf_offset) {
    addr = reinterpret_cast<char *>(this) + fmt_printf_offset;
  }
  return addr;
}

char *
LogBufferHeader::src_hostname()
{
  char *addr = nullptr;
  if (src_hostname_offset) {
    addr = reinterpret_cast<char *>(this) + src_hostname_offset;
  }
  return addr;
}

char *
LogBufferHeader::log_filename()
{
  char *addr = nullptr;
  if (log_filename_offset) {
    addr = reinterpret_cast<char *>(this) + log_filename_offset;
  }
  return addr;
}

LogBuffer::LogBuffer(const LogConfig *cfg, LogObject *owner, size_t size, size_t buf_align, size_t write_align)
  : m_size(size), m_buf_align(buf_align), m_write_align(write_align), m_owner(owner), m_references(0)
{
  size_t hdr_size;

  // create the buffer
  //
  int64_t alloc_size = size + buf_align;

  if (alloc_size <= BUFFER_SIZE_FOR_INDEX(cfg->logbuffer_max_iobuf_index)) {
    m_buffer_fast_allocator_size = buffer_size_to_index(alloc_size, cfg->logbuffer_max_iobuf_index);
    m_unaligned_buffer           = static_cast<char *>(ioBufAllocator[m_buffer_fast_allocator_size].alloc_void());
  } else {
    m_buffer_fast_allocator_size = -1;
    m_unaligned_buffer           = static_cast<char *>(ats_malloc(alloc_size));
  }
  m_buffer = static_cast<char *>(align_pointer_forward(m_unaligned_buffer, buf_align));

  // add the header
  hdr_size = _add_buffer_header(cfg);

  // initialize buffer state
  m_state.s.offset = hdr_size;

  // update the buffer id (m_id gets the old value)
  m_id = static_cast<uint32_t>(ink_atomic_increment(&M_ID, 1));

  m_expiration_time = LogUtils::timestamp() + cfg->max_secs_per_buffer;

  Dbg(dbg_ctl_log_logbuffer, "[%p] Created buffer %u for %s at address %p, size %d", this_ethread(), m_id,
      m_owner->get_base_filename(), m_buffer, (int)size);
}

LogBuffer::LogBuffer(LogObject *owner, LogBufferHeader *header)
  : m_unaligned_buffer(nullptr),
    m_buffer(reinterpret_cast<char *>(header)),
    m_size(0),
    m_buf_align(LB_DEFAULT_ALIGN),
    m_write_align(INK_MIN_ALIGN),
    m_buffer_fast_allocator_size(-1),
    m_expiration_time(0),
    m_owner(owner),
    m_header(header),
    m_references(0)
{
  // This constructor does not allocate a buffer because it gets it as
  // an argument. We set m_unaligned_buffer to NULL, which means that
  // no checkout writes or checkin writes are allowed. This is enforced
  // by the asserts in checkout_write and checkin_write

  // update the buffer id (m_id gets the old value)
  //
  m_id = static_cast<uint32_t>(ink_atomic_increment(&M_ID, 1));

  Dbg(dbg_ctl_log_logbuffer, "[%p] Created repurposed buffer %u for %s at address %p", this_ethread(), m_id,
      m_owner->get_base_filename(), m_buffer);
}

void
LogBuffer::freeLogBuffer()
{
  char *log_buffer = nullptr;

  if (m_unaligned_buffer) {
    log_buffer = m_unaligned_buffer;
  } else {
    log_buffer = m_buffer;
  }
  if (log_buffer) {
    Dbg(dbg_ctl_log_logbuffer, "[%p] Deleting buffer %u at address %p", this_ethread(), m_id, log_buffer);
    if (m_buffer_fast_allocator_size >= 0) {
      ioBufAllocator[m_buffer_fast_allocator_size].free_void(log_buffer);
    } else {
      ats_free(log_buffer);
    }
  }
}

LogBuffer::~LogBuffer()
{
  freeLogBuffer();
  m_buffer           = nullptr;
  m_unaligned_buffer = nullptr;
}

/*-------------------------------------------------------------------------
  LogBuffer::fast_write

  This function is used for the thread-local 'fast' log buffer mode and is not thread-safe.
  In 'fast' mode, each thread owns its own LogBuffer rather than multiple threads contending over one.
  -------------------------------------------------------------------------*/

LogBuffer::LB_ResultCode
LogBuffer::fast_write(size_t *write_offset, size_t write_size)
{
  LB_ResultCode ret_val           = LB_OK;
  size_t        actual_write_size = INK_ALIGN(write_size + sizeof(LogEntryHeader), m_write_align);
  if (m_state.s.offset + actual_write_size <= m_size) {
    size_t offset = m_state.s.offset;

    LogEntryHeader *entry_header = reinterpret_cast<LogEntryHeader *>(&m_buffer[offset]);
    struct timeval  tp           = ink_hrtime_to_timeval(ink_get_hrtime());

    entry_header->timestamp      = tp.tv_sec;
    entry_header->timestamp_usec = tp.tv_usec;
    entry_header->entry_len      = actual_write_size;

    *write_offset = offset + sizeof(LogEntryHeader);

    m_state.s.offset += actual_write_size;
    m_state.s.num_entries++;
  } else {
    ret_val = LB_FULL_NO_WRITERS;
  }

  return ret_val;
}

/*-------------------------------------------------------------------------
  LogBuffer::checkout_write
  -------------------------------------------------------------------------*/

LogBuffer::LB_ResultCode
LogBuffer::checkout_write(size_t *write_offset, size_t write_size)
{
  // checkout_write should not be called if m_unaligned_buffer was
  // not allocated, which means that the actual buffer data was given
  // to the buffer upon construction. Or, in other words, that
  // LogBuffer::LogBuffer(LogObject *owner, LogBufferHeader *header)
  // was used to construct the object
  //
  ink_assert(m_unaligned_buffer);

  LB_ResultCode ret_val = LB_BUSY;
  LB_State      old_s, new_s;
  size_t        offset            = 0;
  size_t        actual_write_size = INK_ALIGN(write_size + sizeof(LogEntryHeader), m_write_align);

  uint64_t retries = static_cast<uint64_t>(-1);
  do {
    // we want sequence points between these two statements
    old_s = m_state;
    new_s = old_s;

    if (old_s.s.full) {
      // the buffer has already been set to full by somebody else
      // just tell the caller to retry
      ret_val = LB_RETRY;
      break;
    } else {
      // determine what the state would be if nobody changes it
      // before we do

      if (write_offset) {
        if (old_s.s.offset + actual_write_size <= m_size) {
          // there is room for this entry, update the state

          offset = old_s.s.offset;

          ++new_s.s.num_writers;
          new_s.s.offset += actual_write_size;
          ++new_s.s.num_entries;

          ret_val = LB_OK;
        } else {
          // there is no room for this entry

          if (old_s.s.num_entries == 0) {
            ret_val = LB_BUFFER_TOO_SMALL;
          } else {
            new_s.s.full = 1;
            ret_val      = old_s.s.num_writers ? LB_FULL_ACTIVE_WRITERS : LB_FULL_NO_WRITERS;
          }
        }
      } else {
        // this is a request to set the buffer as full
        // (write_offset == NULL)

        if (old_s.s.num_entries) {
          new_s.s.full = 1;

          ret_val = (old_s.s.num_writers ? LB_FULL_ACTIVE_WRITERS : LB_FULL_NO_WRITERS);
        } else {
          // the buffer has no entries, do nothing

          ret_val = LB_OK;
          break;
        }
      }

      if (switch_state(old_s, new_s)) {
        // we succeeded in setting the new state
        break;
      }
    }
    ret_val = LB_BUSY;
  } while (--retries);

  // add the entry header to the buffer if this was a real checkout and
  // the checkout was successful
  //
  if (write_offset && ret_val == LB_OK) {
    // disable statistics for now
    // ProxyMutex *mutex = this_ethread()->mutex;
    // ink_release_assert(mutex->thread_holding == this_ethread());
    // SUM_DYN_STAT(log_stat_bytes_buffered_stat, actual_write_size);

    LogEntryHeader *entry_header = reinterpret_cast<LogEntryHeader *>(&m_buffer[offset]);
    // entry_header->timestamp = LogUtils::timestamp();
    struct timeval tp = ink_gettimeofday();

    entry_header->timestamp      = tp.tv_sec;
    entry_header->timestamp_usec = tp.tv_usec;
    entry_header->entry_len      = actual_write_size;

    *write_offset = offset + sizeof(LogEntryHeader);
  }
  //    Dbg(dbg_ctl_log_logbuffer,"[%p] %s for buffer %u (%s) returning %d",
  //        this_ethread(),
  //        (write_offset ? "checkout_write" : "force_new_buffer"),
  //        m_id, m_owner->get_base_filename(), ret_val);

  return ret_val;
}

/*-------------------------------------------------------------------------
  LogBuffer::checkin_write
  -------------------------------------------------------------------------*/

LogBuffer::LB_ResultCode
LogBuffer::checkin_write(size_t write_offset)
{
  // checkin_write should not be called if m_unaligned_buffer was
  // not allocated, which means that the actual buffer data was given
  // to the buffer upon construction. Or, in other words, that
  // LogBuffer::LogBuffer(LogObject *owner, LogBufferHeader *header)
  // was used to construct the object
  //
  ink_assert(m_unaligned_buffer);

  LB_ResultCode ret_val = LB_OK;
  LB_State      old_s, new_s;

  do {
    new_s = old_s = m_state;

    ink_assert(write_offset < old_s.s.offset);
    ink_assert(old_s.s.num_writers > 0);

    if (--new_s.s.num_writers == 0) {
      ret_val = (old_s.s.full ? LB_ALL_WRITERS_DONE : LB_OK);
    }
  } while (!switch_state(old_s, new_s));

  //    Dbg(dbg_ctl_log_logbuffer,"[%p] checkin_write for buffer %u (%s) "
  //        "returning %d (%u writers left)", this_ethread(),
  //        m_id, m_owner->get_base_filename(), ret_val, writers_left);

  return ret_val;
}

unsigned
LogBuffer::add_header_str(const char *str, char *buf_ptr, unsigned buf_len)
{
  unsigned len = 0;
  // This was ambiguous - should it be the real strlen or the
  // rounded up value? Given the +1, presumably it's the real length
  // plus the terminating nul.
  if (likely(str && (len = (unsigned)(::strlen(str) + 1)) < buf_len)) {
    ink_strlcpy(buf_ptr, str, buf_len);
  }
  return len;
}

size_t
LogBuffer::_add_buffer_header(const LogConfig *cfg)
{
  size_t header_len;

  //
  // initialize the header
  //
  LogFormat *fmt                 = m_owner->m_format.get();
  m_header                       = reinterpret_cast<LogBufferHeader *>(m_buffer);
  m_header->cookie               = LOG_SEGMENT_COOKIE;
  m_header->version              = LOG_SEGMENT_VERSION;
  m_header->format_type          = fmt->type();
  m_header->entry_count          = 0;
  m_header->low_timestamp        = LogUtils::timestamp();
  m_header->high_timestamp       = 0;
  m_header->log_object_signature = m_owner->get_signature();
  m_header->log_object_flags     = m_owner->get_flags();
#if defined(LOG_BUFFER_TRACKING)
  m_header->id = lrand48();
#endif // defined(LOG_BUFFER_TRACKING)

  //
  // The remaining header fields actually point into the data section of
  // the buffer.  Write the data into the buffer and update the total
  // size of the buffer header.
  //

  header_len = sizeof(LogBufferHeader); // at least ...

  m_header->fmt_name_offset      = 0;
  m_header->fmt_fieldlist_offset = 0;
  m_header->fmt_printf_offset    = 0;
  m_header->src_hostname_offset  = 0;
  m_header->log_filename_offset  = 0;

  if (fmt->name()) {
    m_header->fmt_name_offset  = header_len;
    header_len                += add_header_str(fmt->name(), &m_buffer[header_len], m_size - header_len);
  }
  if (fmt->fieldlist()) {
    m_header->fmt_fieldlist_offset  = header_len;
    header_len                     += add_header_str(fmt->fieldlist(), &m_buffer[header_len], m_size - header_len);
  }
  if (fmt->printf_str()) {
    m_header->fmt_printf_offset  = header_len;
    header_len                  += add_header_str(fmt->printf_str(), &m_buffer[header_len], m_size - header_len);
  }
  if (cfg->hostname) {
    m_header->src_hostname_offset  = header_len;
    header_len                    += add_header_str(cfg->hostname, &m_buffer[header_len], m_size - header_len);
  }
  if (m_owner->get_base_filename()) {
    m_header->log_filename_offset  = header_len;
    header_len                    += add_header_str(m_owner->get_base_filename(), &m_buffer[header_len], m_size - header_len);
  }
  // update the rest of the header fields; make sure the header_len is
  // correctly aligned, so that the first record will start on a legal
  // alignment mark.
  //

  header_len = INK_ALIGN_DEFAULT(header_len);

  m_header->byte_count  = header_len;
  m_header->data_offset = header_len;

  return header_len;
}

void
LogBuffer::update_header_data()
{
  // only update the header if the LogBuffer did not receive its data
  // upon construction (i.e., if m_unaligned_buffer was allocated)
  //

  if (m_unaligned_buffer) {
    m_header->entry_count    = m_state.s.num_entries;
    m_header->byte_count     = m_state.s.offset;
    m_header->high_timestamp = LogUtils::timestamp();
  }
}

/*-------------------------------------------------------------------------
  LogBuffer::max_entry_bytes

  This static function simply returns the greatest number of bytes than an
  entry can be and fit into a LogBuffer.
  -------------------------------------------------------------------------*/
size_t
LogBuffer::max_entry_bytes()
{
  return (Log::config->log_buffer_size - sizeof(LogBufferHeader));
}

/*-------------------------------------------------------------------------
  LogBuffer::resolve_custom_entry
  -------------------------------------------------------------------------*/
int
LogBuffer::resolve_custom_entry(LogFieldList *fieldlist, char *printf_str, char *read_from, char *write_to, int write_to_len,
                                long /* timestamp ATS_UNUSED */, long /* timestamp_usec ATS_UNUSED */,
                                unsigned /* buffer_version ATS_UNUSED */, LogFieldList *alt_fieldlist, char *alt_printf_str,
                                LogEscapeType escape_type)
{
  if (fieldlist == nullptr || printf_str == nullptr) {
    return 0;
  }

  int *readfrom_map = nullptr;

  if (alt_fieldlist && alt_printf_str) {
    LogField *f, *g;
    int       n_alt_fields = alt_fieldlist->count();
    int       i            = 0;

    readfrom_map = static_cast<int *>(ats_malloc(n_alt_fields * sizeof(int)));
    for (f = alt_fieldlist->first(); f; f = alt_fieldlist->next(f)) {
      int  readfrom_pos = 0;
      bool found_match  = false;
      for (g = fieldlist->first(); g; g = fieldlist->next(g)) {
        if (strcmp(f->symbol(), g->symbol()) == 0) {
          found_match       = true;
          readfrom_map[i++] = readfrom_pos;
          break;
        }
        // TODO handle readfrom_pos properly
        // readfrom_pos += g->size();
      }
      if (!found_match) {
        Note("Alternate format contains a field (%s) not in the "
             "format logged",
             f->symbol());
        break;
      }
    }
  }
  //
  // Loop over the printf_str, copying everything to the write_to buffer
  // except the LOG_FIELD_MARKER characters.  When we reach those, we
  // substitute the string from the unmarshal routine of the current
  // LogField object, obtained from the fieldlist.
  //

  LogField *field         = fieldlist->first();
  LogField *lastField     = nullptr;                                // For debug message.
  int       markCount     = 0;                                      // For debug message.
  int       printf_len    = static_cast<int>(::strlen(printf_str)); // OPTIMIZE
  int       bytes_written = 0;
  int       res, i;

  const char *buffer_size_exceeded_msg = "Traffic Server is skipping the current log entry because its size "
                                         "exceeds the maximum line (entry) size for an ascii log buffer";

  for (i = 0; i < printf_len; i++) {
    if (printf_str[i] == LOG_FIELD_MARKER) {
      ++markCount;
      if (field != nullptr) {
        char *to = &write_to[bytes_written];
        res      = field->unmarshal(&read_from, to, write_to_len - bytes_written, escape_type);

        if (res < 0) {
          SiteThrottledNote("%s", buffer_size_exceeded_msg);
          bytes_written = 0;
          break;
        }

        bytes_written += res;
        lastField      = field;
        field          = fieldlist->next(field);
      } else {
        swoc::LocalBufferWriter<10 * 1024> bw;
        if (auto bs = fieldlist->badSymbols(); bs.size() > 0) {
          bw.print(" (likely due to bad symbols \"{}\" in log format)", bs);
        }
        Note("There are more field markers than fields%*s;"
             " cannot process log entry '%.*s'. Last field = '%s' printf_str='%s' pos=%d/%d count=%d alt_printf_str='%s'",
             static_cast<int>(bw.size()), bw.data(), bytes_written, write_to, lastField == nullptr ? "*" : lastField->symbol(),
             printf_str == nullptr ? "*NULL*" : printf_str, i, printf_len, markCount,
             alt_printf_str == nullptr ? "*NULL*" : alt_printf_str);
        bytes_written = 0;
        break;
      }
    } else {
      if (1 + bytes_written < write_to_len) {
        write_to[bytes_written++] = printf_str[i];
      } else {
        SiteThrottledNote("%s", buffer_size_exceeded_msg);
        bytes_written = 0;
        break;
      }
    }
  }

  ats_free(readfrom_map);
  return bytes_written;
}

/*-------------------------------------------------------------------------
  LogBuffer::to_ascii

  This routine converts a log entry into an ascii string in the buffer
  space provided, and returns the length of the new string (not including
  trailing null, like strlen).
  -------------------------------------------------------------------------*/
int
LogBuffer::to_ascii(LogEntryHeader *entry, LogFormatType type, char *buf, int buf_len, const char *symbol_str, char *printf_str,
                    unsigned buffer_version, const char *alt_format, LogEscapeType escape_type)
{
  ink_assert(entry != nullptr);
  ink_assert(type == LOG_FORMAT_CUSTOM || type == LOG_FORMAT_TEXT);
  ink_assert(buf != nullptr);

  char *read_from; // keeps track of where we're reading from entry
  char *write_to;  // keeps track of where we're writing into buf

  read_from = reinterpret_cast<char *>(entry) + sizeof(LogEntryHeader);
  write_to  = buf;

  if (type == LOG_FORMAT_TEXT) {
    //
    // text log entries are just strings, so simply move it into the
    // format buffer.
    //
    return ink_strlcpy(write_to, read_from, buf_len);
  }
  //
  // We no longer make the distinction between custom vs pre-defined
  // logging formats in converting to ASCII.  This way we're sure to
  // always be using the correct printf string and symbols for this
  // buffer since we get it from the buffer header.
  //
  // We want to cache the unmarshaling "plans" so that we don't have to
  // re-create them each time.  We can use the symbol string as a key to
  // these stored plans.
  //

  int           i;
  LogFieldList *fieldlist          = nullptr;
  bool          delete_fieldlist_p = false; // need to free the fieldlist?

  for (i = 0; i < fieldlist_cache_entries; i++) {
    if (strcmp(symbol_str, fieldlist_cache[i].symbol_str) == 0) {
      Dbg(dbg_ctl_log_fieldlist, "Fieldlist for %s found in cache, #%d", symbol_str, i);
      fieldlist = fieldlist_cache[i].fieldlist;
      break;
    }
  }

  if (!fieldlist) {
    Dbg(dbg_ctl_log_fieldlist, "Fieldlist for %s not found; creating ...", symbol_str);
    fieldlist = new LogFieldList;
    ink_assert(fieldlist != nullptr);
    bool contains_aggregates = false;
    LogFormat::parse_symbol_string(symbol_str, fieldlist, &contains_aggregates);

    if (fieldlist_cache_entries < FIELDLIST_CACHE_SIZE) {
      Dbg(dbg_ctl_log_fieldlist, "Fieldlist cached as entry %d", fieldlist_cache_entries);
      fieldlist_cache[fieldlist_cache_entries].fieldlist  = fieldlist;
      fieldlist_cache[fieldlist_cache_entries].symbol_str = ats_strdup(symbol_str);
      fieldlist_cache_entries++;
    } else {
      delete_fieldlist_p = true;
    }
  }

  LogFieldList *alt_fieldlist  = nullptr;
  char         *alt_printf_str = nullptr;
  char         *alt_symbol_str = nullptr;
  bool          bad_alt_format = false;

  if (alt_format) {
    int n_alt_fields = LogFormat::parse_format_string(alt_format, &alt_printf_str, &alt_symbol_str);
    if (n_alt_fields < 0) {
      Note("Error parsing alternate format string: %s", alt_format);
      bad_alt_format = true;
    }

    if (!bad_alt_format) {
      alt_fieldlist      = new LogFieldList;
      bool contains_aggs = false;
      int  n_alt_fields2 = LogFormat::parse_symbol_string(alt_symbol_str, alt_fieldlist, &contains_aggs);
      if (n_alt_fields2 > 0 && contains_aggs) {
        Note("Alternative formats not allowed to contain aggregates");
        bad_alt_format = true;
        ;
      }
    }
  }

  if (bad_alt_format) {
    delete alt_fieldlist;
    ats_free(alt_printf_str);
    ats_free(alt_symbol_str);
    alt_fieldlist  = nullptr;
    alt_printf_str = nullptr;
    alt_symbol_str = nullptr;
  }

  int ret = resolve_custom_entry(fieldlist, printf_str, read_from, write_to, buf_len, entry->timestamp, entry->timestamp_usec,
                                 buffer_version, alt_fieldlist, alt_printf_str, escape_type);

  delete alt_fieldlist;
  ats_free(alt_printf_str);
  ats_free(alt_symbol_str);
  if (delete_fieldlist_p) {
    delete fieldlist;
  }

  return ret;
}

/*-------------------------------------------------------------------------
  LogBufferList

  The operations on this list need to be atomic because the buffers are
  added by client threads and removed by the logging thread.  This is
  accomplished by protecting the operations with a mutex.

  Also, the list must offer FIFO semantics so that a buffers are removed
  from the list in the same order that they are added, so that timestamp
  ordering in the log file is preserved.
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  LogBufferList::LogBufferList
  -------------------------------------------------------------------------*/

LogBufferList::LogBufferList()
{
  m_size = 0;
  ink_mutex_init(&m_mutex);
}

/*-------------------------------------------------------------------------
  LogBufferList::~LogBufferList
  -------------------------------------------------------------------------*/

LogBufferList::~LogBufferList()
{
  LogBuffer *lb;
  while ((lb = get()) != nullptr) {
    delete lb;
  }
  m_size = 0;
  ink_mutex_destroy(&m_mutex);
}

/*-------------------------------------------------------------------------
  LogBufferList::add (or enqueue)
  -------------------------------------------------------------------------*/

void
LogBufferList::add(LogBuffer *lb)
{
  ink_assert(lb != nullptr);

  ink_mutex_acquire(&m_mutex);
  m_buffer_list.enqueue(lb);
  ink_assert(m_size >= 0);
  m_size++;
  ink_mutex_release(&m_mutex);
}

/*-------------------------------------------------------------------------
  LogBufferList::get (or dequeue)
  -------------------------------------------------------------------------*/

LogBuffer *
LogBufferList::get()
{
  LogBuffer *lb;

  ink_mutex_acquire(&m_mutex);
  lb = m_buffer_list.dequeue();
  if (lb != nullptr) {
    m_size--;
    ink_assert(m_size >= 0);
  }
  ink_mutex_release(&m_mutex);
  return lb;
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

LogEntryHeader *
LogBufferIterator::next()
{
  LogEntryHeader *ret_val = nullptr;
  LogEntryHeader *entry   = reinterpret_cast<LogEntryHeader *>(m_next);

  if (entry) {
    if (m_iter_entry_count < m_buffer_entry_count) {
      m_next += entry->entry_len;
      ++m_iter_entry_count;
      ret_val = entry;
    }
  }

  return ret_val;
}
