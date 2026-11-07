// Run state machine. CONTRACTS §4.
export const RUNNING_STATES = ['preparing', 'scanning', 'merging', 'verifying'];
export const TERMINAL_STATES = ['done', 'degraded', 'not_evaluable', 'aborted'];

/** Precedence when more than one terminal outcome applies: worst wins. */
export const TERMINAL_PRECEDENCE = ['done', 'degraded', 'not_evaluable', 'aborted'];

export const EXIT_CODES = {
  done: 0,
  error: 1,
  refused: 2,
  not_evaluable: 3,
  degraded: 4,
  aborted: 5,
};

const LEGAL = {
  preparing: ['scanning', 'merging', ...TERMINAL_STATES],
  scanning: ['merging', ...TERMINAL_STATES],
  merging: ['verifying', ...TERMINAL_STATES],
  verifying: [...TERMINAL_STATES],
};

export function isTerminal(state) {
  return TERMINAL_STATES.includes(state);
}

export function worstOf(...states) {
  return states
    .filter((s) => TERMINAL_PRECEDENCE.includes(s))
    .reduce(
      (a, b) => (TERMINAL_PRECEDENCE.indexOf(b) > TERMINAL_PRECEDENCE.indexOf(a) ? b : a),
      'done',
    );
}

export function exitCodeFor(state) {
  return EXIT_CODES[state] ?? EXIT_CODES.error;
}

export function createState(runId) {
  return {
    schema: 'sec-state/v1',
    run_id: runId,
    state: 'preparing',
    history: [{ state: 'preparing', at: new Date().toISOString() }],
    started_at: new Date().toISOString(),
    finished_at: null,
    reason: null,
  };
}

export function canMove(from, to) {
  if (isTerminal(from)) return false; // a terminal state is written exactly once
  return (LEGAL[from] ?? []).includes(to);
}

export function move(state, to, reason = null) {
  if (!canMove(state.state, to)) {
    throw new Error(`illegal state move: ${state.state} -> ${to}`);
  }
  state.state = to;
  state.history.push({ state: to, at: new Date().toISOString(), ...(reason ? { reason } : {}) });
  if (reason) state.reason = reason;
  if (isTerminal(to)) state.finished_at = new Date().toISOString();
  return state;
}
