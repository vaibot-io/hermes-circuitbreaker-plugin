// receipt-shape — pure mapping from (raw verdict × enforcing mode × what came
// back) to the governance receipt's `outcome` / `approval.status` / `observe_mode`.
//
// The guard is the enforcing layer, so it — not the server — is authoritative
// for the mode a decision was acted under. The "mode of record" rule keeps three
// facts separate and never merges them:
//
//   policy.decision  — what policy SAID   (allow / approval_required / deny)
//   result.outcome   — what HAPPENED      (allowed / blocked / denied_by_reviewer / …)
//   observe_mode     — the reason the two can differ
//
// PENDING IS CONDITIONAL. `approval.status: "pending"` is a claim that a human
// decision is still outstanding, and it is the only status that belongs in the
// dashboard's approval queue. So it is emitted in exactly one situation: an
// approve verdict with nothing back yet. Everything else carries a terminal
// status:
//
//   * the human answered          → approved / denied
//   * policy honoured a host bypass → bypassed (nobody was asked)
//   * observe mode                → not_required (nothing was gated, so nobody
//                                   was ever asked — see below)
//
// Emitting "pending" for a gate that has already been answered is what parked
// every approved action in the queue forever.
//
// OBSERVE MODE records without gating: the action runs whatever the verdict was.
// It therefore reports what happened, and `not_required` — because no human was
// asked and none is waiting. The alternative, a uniform "pending" flagged with
// observe_mode, is only kept out of the queue by a downstream
// `approval_status = 'pending' AND observe_mode = false` filter; one consumer
// reading approval_status alone re-creates the very bug this module fixes. A
// status that cannot be mistaken for an outstanding decision is excluded by
// construction instead.
//
// Pure and dependency-free, so it unit-tests without booting the daemon.

/**
 * @param {object} a
 * @param {"allow"|"approve"|"deny"|string} a.guardDecision  raw guard verdict (pre-mode)
 * @param {"observe"|"enforce"} a.effectiveMode  the mode the guard actually enforced under
 * @param {null|undefined|{ok?:boolean,code?:number,approval?:string,outcome?:string}} a.result
 *        what came back from the run. null/undefined = nothing yet, which is the
 *        one state that leaves a gate genuinely outstanding.
 * @param {boolean} [a.bypassOverride]  policy honoured the host's approval bypass
 * @param {boolean} [a.floor]  a floor deny (Tier-0 containment, catastrophic floor):
 *        it held regardless of mode, so the action did NOT run
 * @returns {{outcome:string, approvalStatus:string, observeMode:boolean, resolved:boolean}}
 */
export function receiptOutcome({ guardDecision, effectiveMode, result, bypassOverride = false, floor = false }) {
  const observeMode = effectiveMode === "observe";

  // "failed" means the action ran and the command itself errored (non-zero exit
  // / ok:false) — never a governance block.
  const failed = result != null && (result.ok === false || (result.code != null && result.code !== 0));
  const ran = failed ? "blocked" : "allowed";

  // Did anything come back? A result exists only once the run completed, which
  // is also the moment a human's answer can reach us.
  const answered = result != null;
  const humanDenied = result?.approval === "denied" || result?.outcome === "denied_by_reviewer";
  const bypassed = bypassOverride === true && !humanDenied;

  // A FLOOR deny is the exception to everything below: Tier-0 containment and
  // the catastrophic floor hold even in observe, which is what "floor" means.
  // Reporting such an action as having run — which the observe branch would
  // otherwise do — would be a receipt that contradicts what the guard did.
  if (floor && guardDecision === "deny") {
    return { outcome: "blocked", approvalStatus: "not_required", observeMode, resolved: false };
  }

  // Observe: never gated, so the action ran and nobody was asked.
  if (observeMode) {
    return { outcome: ran, approvalStatus: "not_required", observeMode, resolved: false };
  }

  if (guardDecision === "allow") {
    return { outcome: ran, approvalStatus: "not_required", observeMode, resolved: false };
  }

  if (guardDecision === "approve") {
    // Nothing back yet: the only honest "pending", and the only row the queue
    // should hold.
    if (!answered) {
      return { outcome: "blocked_until_approved", approvalStatus: "pending", observeMode, resolved: false };
    }
    if (humanDenied) {
      return { outcome: "denied_by_reviewer", approvalStatus: "denied", observeMode, resolved: true };
    }
    if (bypassed) {
      // Policy granted the escalation; no human decided, so this is not a
      // resolved gate even though it is terminal.
      return { outcome: ran, approvalStatus: "bypassed", observeMode, resolved: false };
    }
    // The run came back without a denial: the action went ahead, which only
    // happens once the human allowed it.
    return { outcome: ran, approvalStatus: "approved", observeMode, resolved: true };
  }

  // deny — and, fail-closed, any unrecognised verdict — blocks.
  return { outcome: "blocked", approvalStatus: "not_required", observeMode, resolved: false };
}

/**
 * Human-facing verb for the receipt summary, derived from what HAPPENED rather
 * than from the verdict — so an observe-mode run reads "executed", not "blocked
 * from executing".
 *
 * @param {object} a
 * @param {"allow"|"approval_required"|"deny"|string} a.mappedDecision
 * @param {string} a.approvalStatus  from receiptOutcome()
 * @param {boolean} a.observeMode
 */
export function actionVerbFor({ mappedDecision, approvalStatus, observeMode }) {
  if (mappedDecision === "deny") return "blocked from executing";
  if (mappedDecision !== "approval_required") return "executed";
  if (observeMode) return "would have paused pending approval for";
  if (approvalStatus === "denied") return "was denied approval to run";
  if (approvalStatus === "bypassed") return "executed under an approval bypass";
  if (approvalStatus === "pending") return "paused pending approval for";
  return "executed after approval";
}
