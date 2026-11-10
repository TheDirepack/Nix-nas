// Presentation of first-start states reported by `nas-setup prepare-first-start`.
// The CLI decides whether submission may proceed and the API re-checks it;
// these helpers only choose what the wizard shows.

export const RECOVERY_STATUSES = new Set(['manual-recovery-required', 'journal-invalid']);
// Running or pending journals belong to an active worker that resume reports.
const STOPPED_JOURNAL_STATUSES = new Set(['failed', 'reconciled', 'manual-recovery-required']);
const SUBMITTABLE_STATUSES = new Set(['ready', 'complete', 'complete-unverified']);

export const recoveryNotice = (plan) => {
  if (!plan || !RECOVERY_STATUSES.has(plan.status)) return null;
  return {
    title: plan.status === 'journal-invalid' ? 'Setup journal needs repair' : 'Setup needs manual recovery',
    message: plan.message || 'A previous setup attempt stopped at a step that needs manual recovery.',
  };
};

export const interruptedNotice = (plan) => {
  const journal = plan?.status === 'ready' ? plan.setupJournal : null;
  if (!journal || typeof journal !== 'object' || !STOPPED_JOURNAL_STATUSES.has(journal.status)) return null;
  const step = journal.step ? ` at ${journal.step}` : '';
  return {
    title: 'Previous setup attempt did not finish',
    message:
      `The setup journal stopped${step} (${journal.status}). Running setup resumes it; ` +
      'enter the same administrator and KeePassXC passwords as before.',
  };
};

export const planProblem = (plan) => {
  if (!plan) return 'The storage plan has not loaded yet.';
  if (RECOVERY_STATUSES.has(plan.status)) {
    return 'Setup cannot start until the recovery shown above is acknowledged.';
  }
  if (!SUBMITTABLE_STATUSES.has(plan.status)) return plan.message || 'The setup plan is not ready.';
  if (!/^[0-9a-f]{64}$/.test(plan.planDigest || '')) return 'The storage plan has not loaded yet.';
  return '';
};

export const jobRecoveryMessage = (job) =>
  job?.status === 'failed' && job.manualRecovery?.required === true
    ? job.manualRecovery.message || 'Setup stopped at a step that needs manual recovery.'
    : '';
