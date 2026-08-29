import React from 'react';
import { Alert, Button } from '@patternfly/react-core';
import { firstStartJob, rebootAfterSetup, submitFirstStart } from '../api.js';

const validate = (
  administrator,
  keePassPassword,
  keePassPasswordConfirm,
  authentikAdministratorPassword,
  authentikAdministratorPasswordConfirm,
  plan,
  allowDestructive,
) => {
  if (!administrator.username || !administrator.name || !administrator.email) {
    return 'Complete the administrator account details.';
  }
  if (!administrator.password || administrator.password !== administrator.confirm) {
    return 'Enter and confirm the Linux administrator password.';
  }
  if (!keePassPassword || keePassPassword !== keePassPasswordConfirm) {
    return 'Enter and confirm the KeePassXC master password.';
  }
  if (
    !authentikAdministratorPassword ||
    authentikAdministratorPassword !== authentikAdministratorPasswordConfirm
  ) {
    return 'Enter and confirm the Authentik administrator password.';
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
  authentikAdministratorPassword,
  authentikAdministratorPasswordConfirm,
  allowDestructive,
  plan,
  onSecretsSubmitted,
}) => {
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState('');
  const [job, setJob] = React.useState(null);
  const [rebooting, setRebooting] = React.useState(false);

  const jobId = job?.jobId;
  const jobToken = job?.jobToken;
  const jobStatus = job?.status;

  React.useEffect(() => {
    if (!jobId || !jobToken || ['complete', 'failed'].includes(jobStatus)) return undefined;
    const timer = window.setInterval(() => {
      firstStartJob(jobId, jobToken)
        .then((value) => {
          if (value && value.jobId === jobId) {
            setJob((current) => ({ ...value, jobToken: current?.jobToken || jobToken }));
          }
        })
        .catch(() => {});
    }, 2000);
    return () => window.clearInterval(timer);
  }, [jobId, jobToken, jobStatus]);

  const submit = async () => {
    const problem = validate(
      administrator,
      keePassPassword,
      keePassPasswordConfirm,
      authentikAdministratorPassword,
      authentikAdministratorPasswordConfirm,
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
      const value = await submitFirstStart({
        password: keePassPassword,
        authentikAdministratorPassword,
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
      });
      // The API has consumed the secret payload once a response is returned.
      // Drop all password values from React state before polling the long job.
      onSecretsSubmitted?.();
      if (value.status === 'complete' || value.status === 'complete-unverified') {
        setJob({ jobId: '', jobToken: '', status: 'complete' });
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
    if (!jobId || !jobToken) {
      setError('The setup completion capability is unavailable. Reboot from the local console.');
      return;
    }
    setRebooting(true);
    try {
      await rebootAfterSetup(jobId, jobToken);
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
        Finishing setup creates the permanent KeePassXC database and fresh machine secrets, creates
        encrypted storage with the permanent ZFS key, creates the Linux and Authentik administrators,
        retires bootstrap authority, and verifies the resulting stack.
      </p>
      <ul>
        <li>Linux administrator: {administrator.username || '(unset)'}</li>
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
          <p>Reboot the appliance to start the full service stack with the permanent trust domain.</p>
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
