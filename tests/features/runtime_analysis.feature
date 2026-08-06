@security @runtime @h3x_sentinel
Feature: h3x_sentinel Runtime Security Analysis
  As a security engineer assessing Resource A (h3x_sentinel.c),
  I need to verify that the runtime behaviour is safe under adversarial conditions,
  So that the process cannot be weaponized, stalled, or privilege-escalated.

  Background:
    Given the binary "h3x_sentinel" is compiled with "-O3 -lm"
    And the host operating system is macOS with SIP enabled
    And the process is launched under a non-root user unless stated otherwise

  # ─── Signal Handling ────────────────────────────────────────────────────────

  @signal @graceful-shutdown
  Scenario: SIGTERM triggers clean shutdown in watch-system mode
    Given h3x_sentinel is running with "--watch-system"
    When the process receives SIGTERM
    Then the global flag "g_should_exit" is set atomically
    And the scan loop exits within 1 iteration (≤ WS_INTERVAL_MS)
    And the heap-allocated PID buffer is freed
    And the process exits with code 0
    And stderr contains "exiting cleanly"

  @signal @graceful-shutdown
  Scenario: SIGINT triggers clean shutdown in watch-system mode
    Given h3x_sentinel is running with "--watch-system"
    When the process receives SIGINT
    Then the global flag "g_should_exit" is set atomically
    And the process exits with code 0

  @signal @resilience
  Scenario: SIGPIPE does not terminate the daemon
    Given h3x_sentinel is running with "--watch-system"
    And stdout is piped to a consumer that closes its read end
    When the next printf to stdout triggers SIGPIPE
    Then the process does NOT terminate
    And the scan loop continues on the next cycle

  @signal @deficiency
  Scenario: --watch mode lacks signal-driven exit path
    Given h3x_sentinel is running with "--watch <PID>"
    When the process receives SIGTERM
    Then the process is terminated by the default handler
    And there is no opportunity to release mach task ports
    # FINDING: --watch should honour g_should_exit like --watch-system

  # ─── Loop Termination & Liveness ───────────────────────────────────────────

  @liveness @termination
  Scenario: --watch mode exits when target process dies
    Given h3x_sentinel is running with "--watch <PID>"
    And the target process is alive
    When the target process terminates
    Then snapshot_process returns n_regions == 0
    And the watch loop breaks
    And the process exits with code 0

  @liveness @termination
  Scenario: --watch-system scan loop respects interval timing
    Given h3x_sentinel is running with "--watch-system --interval 2000"
    When one full scan cycle completes
    Then the process sleeps in 100ms increments checking g_should_exit
    And the total sleep is approximately 2000ms ± 100ms
    And the process does not busy-wait or consume >1% CPU while sleeping

  @liveness @starvation
  Scenario: Large PID list does not starve the scan loop
    Given the system reports 4096 PIDs (WS_MAX_PIDS)
    When h3x_sentinel performs a full scan cycle
    Then each PID is attempted once
    And task_for_pid failures do not block or retry
    And the total cycle time is bounded by (4096 × avg_snapshot_time) + interval

  # ─── Privilege & Entitlement ───────────────────────────────────────────────

  @privilege @least-privilege
  Scenario: task_for_pid fails gracefully without root
    Given h3x_sentinel is running as a non-root user
    And the target PID is owned by another user
    When snapshot_process calls task_for_pid
    Then kern_return_t is NOT KERN_SUCCESS
    And the failure is logged to stderr with PID and mach error string
    And the function returns an empty Snapshot (n_regions == 0)
    And no crash or undefined behaviour occurs

  @privilege @escalation
  Scenario: No privilege escalation surface exists post-launch
    Given h3x_sentinel is running with elevated privileges (root or entitlement)
    When the process acquires a task port via task_for_pid
    Then the task port is used only for mach_vm_region_recurse and mach_vm_read
    And the task port is never stored beyond the scope of snapshot_process
    And no setuid, execve, or fork calls exist in the binary
    # FINDING: task ports are not explicitly deallocated after use

  @privilege @pid-validation
  Scenario Outline: Invalid PID arguments are handled safely
    Given h3x_sentinel is invoked with "--watch <invalid_pid>"
    When atoi parses the argument "<input>"
    Then the resulting pid_t value is "<parsed>"
    And task_for_pid fails without crash or undefined behaviour

    Examples:
      | input         | parsed      | notes                          |
      | 0             | 0           | kernel_task — access denied    |
      | -1            | -1          | invalid — kern failure         |
      | 99999999      | 99999999    | non-existent — kern failure    |
      | abc           | 0           | non-numeric — atoi returns 0   |
      | 2147483648    | overflow    | exceeds INT_MAX — UB in atoi   |

  # ─── Race Conditions (TOCTOU) ─────────────────────────────────────────────

  @race @toctou
  Scenario: PID reuse between enumeration and profiling
    Given h3x_sentinel is in --watch-system scan cycle
    And proc_listpids returns PID 12345 belonging to process X
    When process X exits and PID 12345 is reassigned to process Y
    And snapshot_process(12345) executes
    Then the snapshot reflects process Y's memory (not X's)
    And no crash occurs
    And the output JSON correctly reports PID 12345
    # ACCEPTED RISK: inherent in PID-based systems; documented not mitigated

  @race @toctou
  Scenario: Target process memory layout changes during snapshot
    Given h3x_sentinel is profiling PID with "--watch"
    And the target process munmap's a region between region enumeration and read
    When mach_vm_read is called on the now-unmapped address
    Then kr != KERN_SUCCESS for that region
    And the region is skipped (no crash, no partial profile)
    And remaining regions continue to be profiled

  # ─── Resource Exhaustion ───────────────────────────────────────────────────

  @dos @resource
  Scenario: Process with thousands of VM regions does not overflow
    Given the target process has 1000 VM regions
    When snapshot_process profiles the target
    Then only MAX_REGIONS (256) regions are captured
    And the loop terminates at the cap
    And no buffer overrun occurs on RegionProfile[MAX_REGIONS]

  @dos @resource
  Scenario: Continuous operation does not leak file descriptors or ports
    Given h3x_sentinel is running with "--watch-system"
    When 100 consecutive scan cycles complete
    Then the number of open mach ports remains constant (±1)
    And the number of open file descriptors remains constant
    And RSS memory growth is < 1% of initial allocation
