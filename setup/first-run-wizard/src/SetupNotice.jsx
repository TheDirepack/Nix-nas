import React from 'react';
import { Alert, Button } from '@patternfly/react-core';
import { interruptedNotice, recoveryNotice } from './setup-state.js';

// Acknowledgement stays an explicit operator action in Cockpit or the CLI;
// the wizard only links to it and never acknowledges recovery itself.
export const RecoveryAlert = ({ title, message, onRefresh, status }) => (
  <Alert variant="danger" isInline title={title} className="nas-setup-notice" id="wizard-recovery-required">
    <p>{message}</p>
    {status && <p role="status">{status}</p>}
    <div className="nas-storage-links">
      <Button component="a" href="/console/nas#/setup" target="_blank" rel="noreferrer" variant="secondary">
        Open First start in Cockpit
      </Button>
      {onRefresh && (
        <Button variant="link" onClick={onRefresh}>
          Check again
        </Button>
      )}
    </div>
  </Alert>
);

const SetupNotice = ({ plan, onRefresh }) => {
  const recovery = recoveryNotice(plan);
  if (recovery) return <RecoveryAlert {...recovery} onRefresh={onRefresh} />;
  const interrupted = interruptedNotice(plan);
  if (interrupted) {
    return (
      <Alert variant="info" isInline title={interrupted.title} className="nas-setup-notice" id="wizard-setup-resume">
        {interrupted.message}
      </Alert>
    );
  }
  return null;
};

export default SetupNotice;
