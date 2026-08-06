@security @verification @h3x_sentinel
Feature: h3x_sentinel Security Verification & Attack Surface
  As a security engineer completing the assessment of Resource A (h3x_sentinel.c),
  I need to verify the attack surface, standards compliance, and detection fidelity,
  So that deployment risk is quantified and mitigations are documented.

  Background:
    Given h3x_sentinel is a privileged runtime memory profiler
    And it operates on macOS via Mach VM APIs
    And it emits MITRE ATT&CK / NIST-enriched JSON events
    And the linked headers are h3x_format.h and h3x_attack_map.h

  # ─── Attack Surface Enumeration ───────────────────────────────────────────

  @surface @input
  Scenario: All untrusted input vectors are identified
    Given h3x_sentinel accepts input from:
      | vector             | source                  | trust_level |
      | argv               | command line            | untrusted   |
      | proc_listpids      | kernel PID table        | trusted     |
      | mach_vm_read       | target process memory   | untrusted   |
      | mach_vm_region     | kernel region metadata  | trusted     |
    When each vector is assessed for injection potential
    Then argv is parsed with atoi (no injection, but no validation)
    And mach_vm_read data is consumed read-only by profile_buffer
    And no untrusted data is used in control flow decisions beyond numeric thresholds
    And no untrusted data is passed to exec, system, or popen

  @surface @output
  Scenario: Output channels do not leak sensitive process memory
    Given profile_buffer computes statistical summaries of memory regions
    When the output JSON is emitted
    Then only derived metrics are exposed (identity_density, transition_energy)
    And raw memory bytes are never included in output
    And memory addresses are exposed (informational disclosure — accepted risk)
    And no heap contents from the target appear in stdout or stderr

  @surface @network
  Scenario: No network communication exists in the binary
    Given h3x_sentinel source code is statically analyzed
    When searching for socket, connect, bind, send, recv, or curl symbols
    Then zero network-related system calls are present
    And the binary operates in air-gap-safe mode
    And all output is via stdout/stderr file descriptors only

  # ─── Detection Fidelity ────────────────────────────────────────────────────

  @detection @heap-spray
  Scenario: Heap spray detection triggers on identity density drop
    Given a baseline snapshot with region identity_density = 0.65
    When a subsequent snapshot shows identity_density = 0.40
    Then id_delta = -0.25 which is < -0.20 threshold
    And a "HEAP_SPRAY_SUSPECT" event is emitted
    And the event contains baseline_id and delta_id fields
    And MITRE mapping includes T1055 and T1203

  @detection @code-corruption
  Scenario: Code corruption detection triggers on identity density spike
    Given a baseline snapshot with region identity_density = 0.30
    When a subsequent snapshot shows identity_density = 0.65
    Then id_delta = +0.35 which is > +0.30 threshold
    And baseline identity_density 0.30 < 0.50 guard is satisfied
    And a "CODE_CORRUPTION" event is emitted
    And MITRE mapping includes T1055, T1620, and T1211

  @detection @injection
  Scenario: Injection detection triggers on energy spike
    Given a baseline snapshot with region transition_energy = 0.80
    When a subsequent snapshot shows transition_energy = 2.50
    Then energy_delta = 1.70 which is > 1.5 threshold
    And an "INJECTION_SUSPECT" event is emitted
    And MITRE mapping includes T1055 and T1620

  @detection @false-negative
  Scenario: Subtle heap spray below threshold is not detected
    Given a baseline snapshot with region identity_density = 0.65
    When a subsequent snapshot shows identity_density = 0.50
    Then id_delta = -0.15 which is NOT < -0.20 threshold
    And no alert event is emitted
    # RISK: gradual spray across multiple intervals evades single-delta detection
    # RECOMMENDATION: add cumulative drift tracking across N snapshots

  @detection @false-positive
  Scenario: Legitimate memory allocation does not trigger false alert
    Given a baseline snapshot of a process performing normal malloc/free
    When a subsequent snapshot shows identity_density shift of -0.10
    And transition_energy shift of +0.50
    Then neither threshold is breached
    And no alert events are emitted
    And the monitor continues silently

  # ─── Standards Compliance (h3x_attack_map.h) ───────────────────────────────

  @standards @mitre
  Scenario: All sentinel events map to valid MITRE ATT&CK techniques
    Given the H3X_STD_MAP table in h3x_attack_map.h
    When each sentinel event type is looked up
    Then the following mappings are verified:
      | event                | techniques          |
      | HEAP_SPRAY_SUSPECT   | T1055 T1203         |
      | CODE_CORRUPTION      | T1055 T1620 T1211   |
      | INJECTION_SUSPECT    | T1055 T1620         |
      | SYSTEM_SCAN          | T1057               |
    And all technique IDs conform to MITRE ATT&CK Enterprise v14+ format
    And the relationship is "detects" (not "uses")

  @standards @nist-800-53
  Scenario: All sentinel events map to valid NIST SP 800-53 Rev 5 controls
    Given the H3X_STD_MAP table in h3x_attack_map.h
    When each sentinel event type is looked up
    Then the following control mappings are verified:
      | event                | controls        |
      | HEAP_SPRAY_SUSPECT   | SI-4 SI-16      |
      | CODE_CORRUPTION      | SI-4 SI-7 SI-16 |
      | INJECTION_SUSPECT    | SI-4 SI-16      |
      | SYSTEM_SCAN          | SI-4 CA-7       |
    And SI-4 (Information System Monitoring) is present in all events
    And the control families are: SI (System & Information Integrity), CA (Assessment)

  @standards @nist-csf
  Scenario: All sentinel events map to valid NIST CSF subcategories
    Given the H3X_STD_MAP table in h3x_attack_map.h
    When each sentinel event type is looked up
    Then the following CSF mappings are verified:
      | event                | subcategories       |
      | HEAP_SPRAY_SUSPECT   | DE.CM-4 DE.AE-2    |
      | CODE_CORRUPTION      | DE.CM-4 DE.AE-2    |
      | INJECTION_SUSPECT    | DE.CM-4 DE.AE-2    |
      | SYSTEM_SCAN          | DE.CM-1 DE.CM-7    |
    And DE.CM (Security Continuous Monitoring) is the primary function
    And DE.AE (Anomalies and Events) covers correlation capability

  @standards @json-schema
  Scenario: Emitted JSON conforms to expected schema
    Given h3x_sentinel emits a detection event
    When the JSON is parsed
    Then it contains required fields:
      | field          | type    | constraint               |
      | event          | string  | one of 4 sentinel types  |
      | pid            | integer | > 0                      |
      | addr           | string  | hex format "0x..."       |
      | size           | integer | > 0                      |
      | id_density     | float   | [0.0, 1.0]              |
      | energy         | float   | ≥ 0.0                    |
      | ts             | integer | unix epoch               |
      | mitre_attack   | array   | string[] of T-codes      |
      | nist_800_53    | array   | string[] of controls     |
      | nist_csf       | array   | string[] of subcats      |
    And optional fields include: baseline_id, delta_id

  # ─── Deployment Security Posture ───────────────────────────────────────────

  @deployment @hardening
  Scenario: Binary should be compiled with security hardening flags
    Given h3x_sentinel is built for production deployment
    When compiler flags are assessed
    Then the following SHOULD be enabled:
      | flag                        | purpose                        |
      | -fstack-protector-strong    | stack buffer overflow canary   |
      | -D_FORTIFY_SOURCE=2         | runtime buffer overflow checks |
      | -Wformat -Wformat-security  | format string validation       |
      | -pie -fPIE                  | ASLR for the binary itself     |
      | -Wl,-z,relro,-z,now         | GOT hardening (Linux)          |
    And the entitlements.plist restricts com.apple.system-task-ports to this binary

  @deployment @sandboxing
  Scenario: Process should run with minimal filesystem access
    Given h3x_sentinel only needs: stdout, stderr, and Mach VM APIs
    When a sandbox profile is applied
    Then filesystem read access is denied (no files opened)
    And filesystem write access is denied
    And network access is denied
    And only mach-task-ports IPC is permitted
    And signal delivery is permitted

  # ─── Summary: Security Findings ────────────────────────────────────────────

  @summary @findings
  Scenario: Consolidated security findings for Resource A
    Given the complete analysis of h3x_sentinel.c runtime and memory behaviour
    Then the following findings are documented:
      | id   | severity | finding                                              | status     |
      | F-01 | Medium   | --watch mode lacks SIGTERM handling (no cleanup)     | Open       |
      | F-02 | Low      | PID argument parsed with atoi (no bounds validation) | Open       |
      | F-03 | Low      | Mach task ports not explicitly deallocated            | Open       |
      | F-04 | Low      | interval_ms * 1000 may overflow int32                | Open       |
      | F-05 | Info     | TOCTOU on PID reuse (inherent, documented)           | Accepted   |
      | F-06 | Info     | Memory addresses disclosed in JSON output            | Accepted   |
      | F-07 | Info     | Gradual drift below threshold evades detection       | Accepted   |
    And the overall risk posture is: LOW (local privileged tool, no network, no persistence)
    And recommended mitigations are documented for F-01 through F-04
