import React from 'react';
import { Alert, Button, Checkbox, useWizardContext } from '@patternfly/react-core';
import { fetchJson } from '../http.js';

const COMPLETE_STATUSES = new Set(['complete', 'complete-unverified']);

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

const ConfirmStep = ({
  administrator,
  keePassPassword,
  keePassPasswordConfirm,
  allowDestructive,
  plan,
}) => {
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState('');
  const [job, setJob] = React.useState(null);
  const [rebooting, setRebooting] = React.useState(false);
  const [rebootRequested, setRebootRequested] = React.useState(false);
  const [confirmPasswordReapply, setConfirmPasswordReapply] = React.useState(false);
  const { goToPrevStep } = useWizardContext();

  const jobId = job?.jobId;
  const jobStatus = job?.status;

  React.useEffect(() => {
    if (!jobId || COMPLETE_STATUSES.has(jobStatus) || jobStatus === 'failed') return undefined;
    const timer = window.setInterval(() => {
      fetchJson(`api/first-start/job/${jobId}`)
        .then((value) => {
          if (value && value.jobId === jobId) setJob(value);
        })
        .catch((reason) => setError(`Unable to refresh setup progress: ${reason.message || reason}`));
    }, 2000);
    return () => window.clearInterval(timer);
  }, [jobId, jobStatus]);

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
          confirmPasswordReapply,
        }),
      });
      if (COMPLETE_STATUSES.has(value.status)) {
        setJob({ jobId: '', status: value.status });
      } else {
        setJob(value);
      }
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const reboot = async () => {
    setRebooting(true);
    setError('');
    try {
      await fetchJson('api/reboot', { method: 'POST' });
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
        <li>Devices: {Array.isArray(storage.devices) ? storage.devices.join(' ') : ''}</li>
      </ul>
      {error && <Alert variant="danger" isInline title={error} />}
      {job && !COMPLETE_STATUSES.has(jobStatus) && (
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
      {COMPLETE_STATUSES.has(jobStatus) && (
        <Alert variant="success" isInline title="Setup completed">
          <p>Reboot the appliance to start the full service stack with the new accounts.</p>
        </Alert>
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
          <Button variant="primary" onClick={submit} isDisabled={busy} isLoading={busy}>
            {busy ? 'Starting setup' : 'Run setup'}
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
        {COMPLETE_STATUSES.has(jobStatus) && (
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
