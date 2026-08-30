import React from 'react';
import { Alert, Button, FormGroup, Checkbox, Label, HelperText, HelperTextItem } from '@patternfly/react-core';

const StorageStep = ({
  plan,
  planError,
  allowDestructive,
  onAllowDestructive,
  encryptStorage,
  onEncryptStorage,
  onRefresh,
}) => {
  if (planError) {
    return (
      <div className="nas-wizard-step nas-wizard-message">
        <Alert variant="danger" isInline title="Storage plan unavailable">
          {planError}
        </Alert>
        <div className="nas-storage-actions">
          <p>Configure or partition the disks in Cockpit, then return here and refresh the plan.</p>
          <div className="nas-storage-links">
            <Button component="a" href="/console/storage" target="_blank" rel="noreferrer">
              Open Storage
            </Button>
            <Button component="a" href="/console/system/terminal" target="_blank" rel="noreferrer" variant="secondary">
              Open Terminal
            </Button>
            <Button variant="link" onClick={onRefresh}>
              Refresh plan
            </Button>
          </div>
        </div>
      </div>
    );
  }
  if (!plan) {
    return <p className="nas-wizard-step nas-wizard-message">Loading the storage plan...</p>;
  }
  if (plan.status === 'configuration-missing') {
    return (
      <div className="nas-wizard-step nas-wizard-message">
        <Alert variant="info" isInline title="Storage plan not created yet">
          A storage plan is not required until the initial ZFS pool and disk layout have been
          configured. This is expected on a new appliance.
        </Alert>
        <div className="nas-storage-actions">
          <p>Configure or partition the disks in Cockpit, then return here and refresh the plan.</p>
          <div className="nas-storage-links">
            <Button component="a" href="/console/storage" target="_blank" rel="noreferrer">
              Open Storage
            </Button>
            <Button component="a" href="/console/system/terminal" target="_blank" rel="noreferrer" variant="secondary">
              Open Terminal
            </Button>
            <Button variant="link" onClick={onRefresh}>
              Refresh plan
            </Button>
          </div>
        </div>
      </div>
    );
  }
  const storage = plan.storage || {};
  return (
    <div className="nas-wizard-step">
      <p className="nas-wizard-intro">
        Review the storage plan published by the appliance. Pools are created exactly as reviewed;
        disk partitioning and advanced ZFS changes are done in Cockpit before you continue.
      </p>
      <div className="nas-storage-actions">
        <h2>Need to change the disk layout?</h2>
        <p>Use Cockpit to partition disks or import an existing pool, then come back and refresh this plan.</p>
        <div className="nas-storage-links">
          <Button component="a" href="/console/storage" target="_blank" rel="noreferrer">
            Open Storage
          </Button>
          <Button component="a" href="/console/system/terminal" target="_blank" rel="noreferrer" variant="secondary">
            Open Terminal
          </Button>
          <Button variant="link" onClick={onRefresh}>
            Refresh plan
          </Button>
        </div>
      </div>
      <FormGroup label="Status" fieldId="wizard-plan-status">
        <Label color={plan.status === 'ready' ? 'green' : 'orange'}>{plan.status}</Label>
      </FormGroup>
      <FormGroup label="Pool" fieldId="wizard-plan-pool">
        <div id="wizard-plan-pool" className="nas-readonly-value">{storage.pool || 'Not specified'}</div>
      </FormGroup>
      <FormGroup label="Dataset" fieldId="wizard-plan-dataset">
        <div id="wizard-plan-dataset" className="nas-readonly-value">{storage.dataset || 'Not specified'}</div>
      </FormGroup>
      <Checkbox
        id="wizard-encrypt-storage"
        label="Encrypt the ZFS data partition using the key stored in KeePassXC"
        isChecked={encryptStorage}
        onChange={(_event, checked) => onEncryptStorage(checked)}
      />
      <HelperText>
        <HelperTextItem>
          Recommended. KeePassXC stays on the system partition so it can provide the key before the ZFS data partition is unlocked.
        </HelperTextItem>
      </HelperText>
      <FormGroup label="Devices" fieldId="wizard-plan-devices">
        <ul id="wizard-plan-devices" className="nas-device-list">
          {Array.isArray(storage.devices) && storage.devices.length ? (
            storage.devices.map((device) => <li key={device}>{device}</li>)
          ) : (
            <li>No block devices are listed in the current plan.</li>
          )}
        </ul>
        <HelperText>
          <HelperTextItem>These exact devices are used for pool creation. Verify the list before allowing a destructive operation.</HelperTextItem>
        </HelperText>
      </FormGroup>
      {plan.requiresDestructiveConfirmation && (
        <Checkbox
          id="wizard-destructive"
          label="I understand the listed devices will be wiped when the new pool is created"
          isChecked={allowDestructive}
          onChange={(_event, checked) => onAllowDestructive(checked)}
        />
      )}
    </div>
  );
};

export default StorageStep;
