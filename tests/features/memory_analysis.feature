@security @memory @h3x_sentinel
Feature: h3x_sentinel Memory Safety Analysis
  As a security engineer assessing Resource A (h3x_sentinel.c),
  I need to verify that all memory operations are bounded, leak-free, and safe,
  So that the process cannot be exploited via memory corruption primitives.

  Background:
    Given the binary "h3x_sentinel" is compiled with "-O3 -lm"
    And AddressSanitizer (ASan) instrumentation is available for test builds
    And Valgrind or leaks(1) is available for dynamic analysis

  # ─── Heap Allocation & Deallocation ────────────────────────────────────────

  @heap @allocation
  Scenario: PID buffer allocation succeeds and is correctly sized
    Given h3x_sentinel starts in "--watch-system" mode
    When calloc(WS_MAX_PIDS, sizeof(int)) is called
    Then the returned pointer is non-NULL
    And the allocated size is exactly 4096 × 4 = 16384 bytes
    And all bytes are zero-initialized

  @heap @allocation
  Scenario: PID buffer allocation failure is handled
    Given available heap memory is artificially constrained
    When calloc(WS_MAX_PIDS, sizeof(int)) returns NULL
    Then the process prints "OOM allocating pid buffer" to stderr
    And the process exits with code 1
    And no further memory operations are attempted

  @heap @deallocation
  Scenario: PID buffer is freed on clean shutdown
    Given h3x_sentinel is running in "--watch-system" mode
    When SIGTERM is received and the loop exits
    Then free(pids) is called exactly once
    And no double-free occurs
    And Valgrind reports 0 bytes definitely lost

  @heap @kernel-memory
  Scenario: mach_vm_read allocations are correctly deallocated
    Given h3x_sentinel is profiling a target process
    When mach_vm_read succeeds and returns data_ptr with data_cnt bytes
    Then the buffer is used only within the current loop iteration
    And mach_vm_deallocate(mach_task_self(), data_ptr, data_cnt) is called
    And the deallocation uses the exact same size returned by mach_vm_read
    And no reference to data_ptr persists after deallocation

  @heap @kernel-memory
  Scenario: mach_vm_read failure does not trigger spurious deallocation
    Given h3x_sentinel is profiling a target process
    When mach_vm_read fails (kr != KERN_SUCCESS)
    Then mach_vm_deallocate is NOT called for that iteration
    And data_ptr remains at its initialized value (0)
    And no use-after-free is possible

  # ─── Stack Memory Safety ───────────────────────────────────────────────────

  @stack @overflow
  Scenario: Snapshot struct fits within default stack frame limits
    Given Snapshot contains MAX_REGIONS (256) × RegionProfile entries
    And sizeof(RegionProfile) = 32 bytes (5 fields: u64+u64+f32+f32+f32 + padding)
    When snapshot_process is called
    Then the stack-allocated Snapshot occupies ≤ 10240 bytes
    And this is within the default 8MB thread stack limit
    And no stack overflow occurs even with recursive vm_region_recurse calls

  @stack @overflow
  Scenario: Deep scan loop does not accumulate stack frames
    Given h3x_sentinel is in --watch-system mode scanning 4096 PIDs
    When snapshot_process is called sequentially for each PID
    Then each invocation uses its own stack frame (no recursion)
    And the stack depth is constant regardless of PID count
    And maximum stack depth is: main → scan_loop_body → snapshot_process → profile_buffer

  # ─── Buffer Boundaries ─────────────────────────────────────────────────────

  @buffer @bounds
  Scenario: profile_buffer respects SAMPLE_SIZE cap
    Given a VM region of size 1MB is readable
    When mach_vm_read is called with read_size = min(region_size, SAMPLE_SIZE)
    Then at most 4096 bytes are read into the buffer
    And profile_buffer iterates only up to (n - 1) where n = min(data_cnt, SAMPLE_SIZE)
    And no out-of-bounds read occurs on buf[i] or buf[i+1]

  @buffer @bounds
  Scenario: profile_buffer handles minimum-size input
    Given a VM region returns exactly 1 byte (data_cnt == 1)
    When profile_buffer is called with len == 1
    Then the function returns early (len < 2 guard)
    And rp.identity_density == 0 and rp.transition_energy == 0
    And no array access occurs

  @buffer @bounds
  Scenario: profile_buffer handles zero-length input
    Given mach_vm_read returns data_cnt == 0
    When the outer condition checks "data_cnt > 1"
    Then profile_buffer is NOT called
    And no deallocation is attempted (mach_vm_read would not have succeeded)

  @buffer @bounds
  Scenario: Region array never exceeds MAX_REGIONS
    Given a target process has 500+ VM regions
    When snapshot_process iterates with mach_vm_region_recurse
    Then the loop condition "snap.n_regions < MAX_REGIONS" is checked each iteration
    And the 257th region is never written to snap.regions[256]
    And the function returns with exactly 256 profiled regions

  @buffer @bounds
  Scenario: compute_tokens produces values in range [0, 4]
    Given two consecutive bytes a and b from the sample buffer
    When compute_tokens(a, b, tok) is called
    Then each tok[0..7] value is in the range {0, 1, 2, 3, 4}
    And the formula (ec+oc)-(en+on)+2 with binary inputs yields range [0, 4]
    And the formula (ec-oc)-(en-on)+2 with binary inputs yields range [0, 4]
    And no array-index-out-of-bounds is possible downstream

  # ─── Format String & Output Safety ────────────────────────────────────────

  @format @injection
  Scenario: JSON output cannot contain format string attacks
    Given the output uses printf with hardcoded format strings
    And all interpolated values are numeric (pid, addr, size, floats, timestamps)
    When a malicious process name or path could theoretically appear
    Then no user-controlled string is interpolated into format specifiers
    And no %n, %s with attacker-controlled pointer is reachable
    And all output fields are numeric or compile-time constant strings

  @format @injection
  Scenario: stderr diagnostic messages use safe format patterns
    Given task_for_pid failure is reported via fprintf(stderr, ...)
    When the error string comes from mach_error_string(kr)
    Then the string is kernel-provided (not attacker-controlled)
    And the format is "%d (%s)" with controlled positional arguments
    And no injection vector exists

  # ─── Leak Detection Under Stress ───────────────────────────────────────────

  @leak @dynamic
  Scenario: No memory leaks after 1000 snapshot cycles (ASan)
    Given h3x_sentinel is compiled with -fsanitize=address
    And the process is running with "--watch <PID> --interval 10"
    When 1000 snapshot cycles complete
    Then ASan reports 0 memory leaks at exit
    And no "heap-use-after-free" errors are reported
    And no "stack-buffer-overflow" errors are reported

  @leak @dynamic
  Scenario: No kernel memory leaks after repeated mach_vm_read
    Given h3x_sentinel is profiling a target with 100 readable regions
    When 50 consecutive snapshots are taken
    Then mach_vm_deallocate is called exactly (100 × 50) = 5000 times
    And the process virtual memory footprint does not grow
    And vm_stat shows no increase in wired pages attributed to the process

  @leak @ports
  Scenario: Mach task ports do not accumulate
    Given h3x_sentinel is in --watch-system mode
    When 100 successful task_for_pid calls complete
    Then the acquired task_t ports are implicitly released at function scope
    # FINDING: task ports are not explicitly deallocated with mach_port_deallocate
    # RECOMMENDATION: Add mach_port_deallocate(mach_task_self(), task) after use
    And the process mach port count should remain bounded

  # ─── Integer Safety ────────────────────────────────────────────────────────

  @integer @overflow
  Scenario: interval_ms multiplication does not overflow usleep argument
    Given "--interval 2147483" is passed (near INT_MAX / 1000)
    When usleep(interval_ms * 1000) is evaluated
    Then the multiplication may overflow 32-bit int
    And the resulting usleep value is undefined
    # FINDING: interval_ms * 1000 should use (useconds_t) cast or bounds check

  @integer @overflow
  Scenario: proc_listpids byte count to PID count conversion is safe
    Given proc_listpids returns n_bytes as int
    When n_pids = n_bytes / sizeof(int) is computed
    Then the division is exact (sizeof(int) == 4, n_bytes is always a multiple)
    And n_pids cannot exceed WS_MAX_PIDS due to buffer size passed to proc_listpids
