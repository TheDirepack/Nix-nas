import React from 'react';
import { Alert, Button, Checkbox, useWizardContext } from '@patternfly/react-core';
import { fetchJson } from '../http.js';

const COMPLETE_STATUSES = new Set(['complete', 'complete-unverified']);
const CAPABILITY_HEADER = 'X-NAS-Setup-Capability';

const validate = (administrator, keePassPassword, keePassPasswordConfirm, plan, allowDestructive) => {
  if (!administrator.username || !administrator.name || !administrator.email) {
    return 'Complete the administrator account details.';
  }
  if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(administrator.username)) {
    return 'Use a valid administrator username.';
  }
  if (![administrator.name, administrator.email].every((value) => !/[\r\n]/.test(value))) {
    return 'Administrator details must be single-line values.';
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(administrator.email)) {
    return 'Enter a valid administrator email address.';
  }
  if (!administrator.password || administrator.password !== administrator.confirm) {
    return 'Enter and confirm the administrator password.';
  }
  if (administrator.password.length < 12 || /[\r\n]/.test(administrator.password)) {
    return 'Use an administrator password with at least 12 single-line characters.';
  }
  if (!keePassPassword) {
    return 'Enter the KeePassXC database password.';
  }
  if (/[\r\n]/.test(keePassPassword)) {
    return 'KeePassXC database password must be a single line.';
  }
  if (keePassPassword !== keePassPasswordConfirm) {
    return 'Enter and confirm the KeePassXC database password.';
  }
  if (!plan || !/^[0-9a-f]{64}$/.test(plan.planDigest || '')) {
    return 'The storage plan has not loaded yet.';
  }
  if (plan.requiresDestructiveConfirmation && !allowDestructive) {
    return 'Confirm the destructive storage creation on the Storage step.';
  }
  return '';
};

// Split the server-issued reboot capability out of a job document. The
// capability lives only in component state: it is never rendered, never
// persisted to browser storage, and never placed in URLs.
const splitJobDocument = (value) => {
  if (!value || typeof value !== 'object') return { job: null, capability: null };
  const { capability, ...job } = value;
  return {
    job: typeof job.status === 'string' ? job : null,
    capability: typeof capability === 'string' && capability ? capability : null,
  };
};

const ConfirmStep = ({
  administrator,
  keePassPassword,
  keePassPasswordConfirm,
  allowDestructive,
  encryptStorage,
  plan,
}) => {
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState('');
  const [job, setJob] = React.useState(null);
  const [capability, setCapability] = React.useState(null);
  const [resuming, setResuming] = React.useState(false);
  const [resumeAttempted, setResumeAttempted] = React.useState(false);
  const [rebooting, setRebooting] = React.useState(false);
  const [rebootRequested, setRebootRequested] = React.useState(false);
  const [confirmPasswordReapply, setConfirmPasswordReapply] = React.useState(false);
  const { goToPrevStep } = useWizardContext();

  const jobId = job?.jobId;
  const jobStatus = job?.status;
  const isComplete = COMPLETE_STATUSES.has(jobStatus);
  const rebootAuthorized = Boolean(capability) && isComplete;

  const resume = React.useCallback(async () => {
    setResuming(true);
    setError('');
    try {
      const value = await fetchJson('api/first-start/resume', {
        method: 'POST',
        headers: { Accept: 'application/json' },
      });
      const { job: resumed, capability: resumedCapability } = splitJobDocument(value);
      if (!resumed) throw new Error('The setup service returned an unusable job document.');
      setJob(resumed);
      setCapability(resumedCapability);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setResuming(false);
      setResumeAttempted(true);
    }
  }, []);

  // Recover the authorized active job after a refresh without resubmitting.
  // This effect only resumes; destructive submission stays behind the button.
  React.useEffect(() => {
    if (job || resumeAttempted) return undefined;
    resume();
    return undefined;
  }, [job, resumeAttempted, resume]);

  React.useEffect(() => {
    if (!capability || !jobId || isComplete || jobStatus === 'failed') return undefined;
    const timer = window.setInterval(() => {
      fetchJson('api/first-start/job', {
        headers: { Accept: 'application/json', [CAPABILITY_HEADER]: capability },
      })
        .then((value) => {
          const { job: polled } = splitJobDocument(value);
          if (polled && polled.jobId === jobId) setJob(polled);
        })
        .catch((reason) => setError(`Unable to refresh setup progress: ${reason.message || reason}`));
    }, 2000);
    return () => window.clearInterval(timer);
  }, [capability, jobId, isComplete, jobStatus]);

  const submit = async () => {
    const problem = validate(
      administrator,
      keePassPassword,
      keePassPasswordConfirm,
      plan,
      allowDestructive,
    );
    if (problem) {
      setError(problem);
      return;
    }
    setError('');
    setBusy(true);
    try {
      const value = await fetchJson('api/first-run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          password: keePassPassword,
          administrator: {
            username: administrator.username,
            name: administrator.name,
            email: administrator.email,
            password: administrator.password,
          },
          planDigest: plan.planDigest,
          devices: (plan.storage && plan.storage.devices) || [],
          allowDestructiveStorage: allowDestructive,
          encryptStorage,
          confirmPasswordReapply,
        }),
      });
      const { job: submitted, capability: submittedCapability } = splitJobDocument(value);
      if (!submitted) throw new Error('The setup service returned an unusable job document.');
      setJob(submitted);
      setCapability(submittedCapability);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const reboot = async () => {
    if (!capability) {
      setError('Reboot needs a fresh setup authorization. Request reboot access first.');
      return;
    }
    setRebooting(true);
    setError('');
    try {
      await fetchJson('api/reboot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', [CAPABILITY_HEADER]: capability },
        body: JSON.stringify({}),
      });
      setRebootRequested(true);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setRebooting(false);
    }
  };

  const storage = (plan && plan.storage) || {};
  return (
    <div>
      <p>
        Finishing setup applies the reviewed plan: it creates the storage,
        initializes the KeePassXC database and secrets, creates the configured
        accounts plus your administrator, and verifies the stack. The appliance
        reboots afterwards.
      </p>
      <ul>
        <li>Administrator: {administrator.username || '(unset)'}</li>
        <li>Pool: {storage.pool || '(plan pending)'}</li>
        <li>ZFS encryption: {encryptStorage ? 'Enabled' : 'Disabled'}</li>
        <li>Devices: {Array.isArray(storage.devices) ? storage.devices.join(' ') : ''}</li>
      </ul>
      {error && <Alert variant="danger" isInline title={error} />}
      {!job && resumeAttempted && !error && (
        <Alert variant="info" isInline title="No running setup job">
          No active setup job was found for this session. Starting setup below is the only way to create one.
        </Alert>
      )}
      {job && !isComplete && (
        <Alert
          variant={jobStatus === 'failed' ? 'danger' : 'info'}
          isInline
          title={`Setup job ${jobId || ''}: ${jobStatus || 'starting'}`}
        >
          {job.message || 'The setup job is running. This can take several minutes.'}
        </Alert>
      )}
      {jobStatus === 'failed' && (
        <Checkbox
          id="wizard-password-reapply"
          label="I understand retrying may reapply administrator and account passwords"
          isChecked={confirmPasswordReapply}
          onChange={(_event, checked) => setConfirmPasswordReapply(checked)}
        />
      )}
      {jobStatus === 'complete' && (
        <Alert variant="success" isInline title="Setup completed">
          <p>Reboot the appliance to start the full service stack with the new accounts.</p>
        </Alert>
      )}
      {jobStatus === 'complete-unverified' && (
        <Alert variant="warning" isInline title="Setup completed with unverified state">
          <p>
            The appliance reports completion, but the final state was not fully verified. Before rebooting,
            compare the reviewed plan against the reported result, then run the recovery checks in the operator
            manual. Reboot only when the completed state is confirmed.
          </p>
        </Alert>
      )}
      {isComplete && !rebootAuthorized && !rebootRequested && (
        <Alert variant="warning" isInline title="Reboot needs fresh authorization">
          <p>
            This page load has no reboot authorization for the completed job. Request reboot access to resume the
            authorized job, or reboot from the appliance console if browser authorization is unavailable.
          </p>
        </Alert>
      )}
      {isComplete && (
        <pre id="wizard-job-document" style={{ display: 'none' }}>
          {JSON.stringify(job)}
        </pre>
      )}
      {rebootRequested && (
        <Alert variant="info" isInline title="Reboot requested">
          This page will disconnect while the appliance restarts.
        </Alert>
      )}
      <div className="nas-confirm-actions">
        <Button variant="secondary" onClick={goToPrevStep} isDisabled={busy || rebooting || rebootRequested}>
          Back
        </Button>
        {!job && (
          <Button variant="primary" onClick={submit} isDisabled={busy || resuming} isLoading={busy}>
            {busy ? 'Starting setup' : 'Run setup'}
          </Button>
        )}
        {!job && resumeAttempted && (
          <Button variant="secondary" onClick={resume} isDisabled={busy || resuming} isLoading={resuming}>
            {resuming ? 'Checking for setup' : 'Check for running setup'}
          </Button>
        )}
        {jobStatus === 'failed' && (
          <Button
            variant="primary"
            onClick={submit}
            isDisabled={busy || !confirmPasswordReapply}
            isLoading={busy}
          >
            {busy ? 'Retrying setup' : 'Retry setup'}
          </Button>
        )}
        {isComplete && !rebootAuthorized && !rebootRequested && (
          <Button variant="secondary" onClick={resume} isDisabled={resuming} isLoading={resuming}>
            {resuming ? 'Requesting access' : 'Request reboot access'}
          </Button>
        )}
        {isComplete && rebootAuthorized && (
          <Button
            variant="primary"
            onClick={reboot}
            isDisabled={rebooting || rebootRequested}
            isLoading={rebooting}
          >
            {rebooting ? 'Rebooting' : rebootRequested ? 'Reboot requested' : 'Reboot now'}
          </Button>
        )}
      </div>
    </div>
  );
};

export default ConfirmStep;
