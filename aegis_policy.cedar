// AEGIS-ZERO Intent-Based Access Control (IBAC) policy lattice, Cedar 3.x / 4.x syntax.
//
// Mirrors aegis_controller.PolicyEngine + AegisController.evaluate exactly. Every request
// from the proxy (Ring 1) or the BPF bridge (Ring 0 events) is mapped to:
//   principal : Aegis::Agent::"<session>"      attrs: tgid, cgroup_id
//   action    : Aegis::Action::"READ" | "WRITE" | "DELETE" | "NET" | "EXEC" | "SIGNAL"
//   resource  : Aegis::Object::"<dev:ino | url>" attrs: canary, protected_daemon, domain,
//                                                     inside_workdir
//   context   : taint ("TRUSTED"|"TAINTED"), risk (decimal R), drift (decimal EWMA),
//               intent_distance (decimal D), domain_granted (bool), chain_match (bool),
//               covert_channel (bool), capability_valid (bool), oob_signature_valid (bool)
// Cedar semantics: deny unless some permit matches and no forbid matches (forbid overrides),
// so the default is exactly the fail-closed DENY ALL of the controller.

// ---------------------------------------------------------------- action lattice
// READ < WRITE, DELETE, NET, EXEC   (Priv enum ordering). "Privileged" groups every action
// that the taint rule and the capability rule govern.
// entity declaration (schema): action "WRITE", "DELETE", "NET", "EXEC" in [Aegis::Action::"Privileged"];

// ---------------------------------------------------------------- 1. canary zero tolerance
@id("F1-canary-zero-tolerance")
@response("freeze+rollback+forensic-snapshot; not approvable")
forbid (principal, action, resource)
when { resource.canary == true };

// ---------------------------------------------------------------- 2. daemon self-protection
@id("F2-daemon-self-protection")
@response("task_kill -EPERM; quarantine")
forbid (principal, action == Aegis::Action::"SIGNAL", resource)
when { resource.protected_daemon == true };

@id("F2b-policy-and-key-material-immutable")
forbid (principal, action in [Aegis::Action::"WRITE", Aegis::Action::"DELETE"], resource)
when { resource.domain == "aegis_control_plane" };

// ---------------------------------------------------------------- 3. Biba / BLP taint block
// tau = TAINTED  and  Priv(A) > READ   =>  deny, unless declassified by an OOB Ed25519 signature
@id("F3-tainted-no-write-up")
@response("freeze; OOB challenge; approvable")
forbid (principal, action in Aegis::Action::"Privileged", resource)
when { context.taint == "TAINTED" }
unless { context.oob_signature_valid == true };

// ---------------------------------------------------------------- 4. composite chain / covert channel
@id("F4-composite-attack-chain")
forbid (principal, action, resource)
when { context.chain_match == true }
unless { context.oob_signature_valid == true };

@id("F4b-covert-channel")
forbid (principal, action == Aegis::Action::"NET", resource)
when { context.covert_channel == true }
unless { context.oob_signature_valid == true };

// ---------------------------------------------------------------- 5. risk and drift thresholds
// R = 0.60*D + 0.15*H + 0.40*I  >= theta (0.45)   or   EWMA >= theta_d (0.35)
@id("F5-risk-threshold")
forbid (principal, action, resource)
when { context.risk.greaterThanOrEqual(decimal("0.4500")) }
unless { context.oob_signature_valid == true };

@id("F5b-slow-drift")
forbid (principal, action, resource)
when { context.drift.greaterThanOrEqual(decimal("0.3500")) }
unless { context.oob_signature_valid == true };

@id("F5c-capability-not-granted-by-intent")
forbid (principal, action, resource)
when { context.domain_granted == false }
unless { context.oob_signature_valid == true };

// ---------------------------------------------------------------- 6. CoW boundary
@id("F6-writes-confined-to-workdir")
forbid (principal, action in [Aegis::Action::"WRITE", Aegis::Action::"DELETE"], resource)
when { resource.inside_workdir == false };

// ---------------------------------------------------------------- permits
@id("P1-read-aligned")
permit (principal, action == Aegis::Action::"READ", resource)
when { context.intent_distance.lessThan(decimal("0.2500")) };

@id("P2-privileged-with-single-use-capability")
@response("mint HMAC token + cap_tokens{tgid,hook,dev,ino}; CoW stage before execution")
permit (principal, action in Aegis::Action::"Privileged", resource)
when {
  context.capability_valid == true &&
  context.intent_distance.lessThan(decimal("0.2500")) &&
  context.risk.lessThan(decimal("0.4500"))
};

@id("P3-oob-declassified")
permit (principal, action in Aegis::Action::"Privileged", resource)
when { context.oob_signature_valid == true && context.capability_valid == true };
