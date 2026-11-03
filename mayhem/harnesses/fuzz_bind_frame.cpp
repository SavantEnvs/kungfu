// Wraps upstream's framework/core/fuzz/fuzz_bind_frame.cpp unchanged. flatbuffers::Verify() (25.9.23,
// reflection.cpp) reads the 4-byte root offset via GetAnyRoot() before it checks the buffer length, so
// any frame shorter than a uoffset_t is a heap-buffer-overflow in the library, reached through
// kungfu::view::schema_handle::bind_frame/verify_table. Reject those inputs so the fuzzer can reach
// the verify-before-access logic that follows.
#include <cstddef>
#include <cstdint>

#define LLVMFuzzerTestOneInput kungfu_upstream_bind_frame_entry
#include "../../framework/core/fuzz/fuzz_bind_frame.cpp"
#undef LLVMFuzzerTestOneInput

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < sizeof(uint32_t))
    return -1;
  return kungfu_upstream_bind_frame_entry(data, size);
}
