import React from 'react';
import { Alert, Button } from '@patternfly/react-core';

const validate = (administrator, keePassPassword, plan, allowDestructive) => {
  if (!administrator.username || !administrator.name || !administrator.email) {
    return 'Complete the administrator account details.';
  }
  if (!administrator.password || administrator.password !== administrator.confirm) {
    return 'Enter and confirm the administrator password.';
  }
  if (!keePassPassword) {
    return 'Enter the KeePassXC database password.';
  }
  if (!plan || !/^[0-9a-f]{64}$/.test(plan.planDigest || '')) {
    return 'The storage plan has not loaded yet.';
  }
  if (plan.requiresDestructiveConfirmation && !allowDestructive) {
    return 'Confirm the destructive storage creation on the Storage step.';
  }
  return '';
};

const ConfirmStep = ({ administrator, keePassPassword, allowDestructive, plan }) => {
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState('');
  const [job, setJob] = React.useState(null);
  const [rebooting, setRebooting] = React.useState(false);

  const jobId = job?.jobId;
  const jobStatus = job?.status;

  React.useEffect(() => {
    if (!jobId || ['complete', 'failed'].includes(jobStatus)) return undefined;
    const timer = window.setInterval(() => {
      fetch(`api/first-start/job/${jobId}`)
        .then((response) => response.json())
        .then((value) => {
          if (value && value.jobId === jobId) setJob(value);
        })
        .catch(() => {});
    }, 2000);
    return () => window.clearInterval(timer);
  }, [jobId, jobStatus]);

  const submit = async () => {
    const problem = validate(administrator, keePassPassword, plan, allowDestructive);
    if (problem) {
      setError(problem);
      return;
    }
    setError('');
    setBusy(true);
    try {
      const response = await fetch('api/first-run', {
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
          confirmPasswordReapply: false,
        }),
      });
      const value = await response.json();
      if (value.error) {
        setError(value.error);
      } else if (value.status === 'complete' || value.status === 'complete-unverified') {
        setJob({ jobId: '', status: 'complete' });
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
    try {
      const response = await fetch('api/reboot', { method: 'POST' });
      const value = await response.json();
      if (value.error) setError(value.error);
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
      {job && jobStatus !== 'complete' && (
        <Alert
          variant={jobStatus === 'failed' ? 'danger' : 'info'}
          isInline
          title={`Setup job ${jobId || ''}: ${jobStatus || 'starting'}`}
        >
          {job.message || 'The setup job is running. This can take several minutes.'}
        </Alert>
      )}
      {jobStatus === 'complete' && (
        <Alert variant="success" isInline title="Setup completed">
          <p>Reboot the appliance to start the full service stack with the new accounts.</p>
        </Alert>
      )}
      {!job && (
        <Button variant="primary" onClick={submit} isDisabled={busy} isLoading={busy}>
          {busy ? 'Starting setup' : 'Run setup'}
        </Button>
      )}
      {jobStatus === 'complete' && (
        <Button variant="primary" onClick={reboot} isDisabled={rebooting} isLoading={rebooting}>
          {rebooting ? 'Rebooting' : 'Reboot now'}
        </Button>
      )}
    </div>
  );
};

export default ConfirmStep;
