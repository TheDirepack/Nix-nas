import React from 'react';
import { FormGroup, Checkbox, Label, HelperText, HelperTextItem } from '@patternfly/react-core';

const StorageStep = ({ plan, planError, allowDestructive, onAllowDestructive }) => {
  if (planError) {
    return <p className="nas-wizard-step">Unable to load the storage plan: {planError}</p>;
  }
  if (!plan) {
    return <p className="nas-wizard-step">Loading the storage plan...</p>;
  }
  const storage = plan.storage || {};
  return (
    <div className="nas-wizard-step">
      <p className="nas-wizard-intro">Review the storage plan published by the appliance. Pools are created exactly as reviewed.</p>
      <FormGroup label="Status" fieldId="wizard-plan-status">
        <Label color={plan.status === 'ready' ? 'green' : 'orange'}>{plan.status}</Label>
      </FormGroup>
      <FormGroup label="Pool" fieldId="wizard-plan-pool">
        <div id="wizard-plan-pool" className="nas-readonly-value">{storage.pool || 'Not specified'}</div>
      </FormGroup>
      <FormGroup label="Dataset" fieldId="wizard-plan-dataset">
        <div id="wizard-plan-dataset" className="nas-readonly-value">{storage.dataset || 'Not specified'}</div>
      </FormGroup>
      <FormGroup label="Devices" fieldId="wizard-plan-devices">
        <ul id="wizard-plan-devices" className="nas-device-list">
          {(Array.isArray(storage.devices) ? storage.devices : []).map((device) => (
            <li key={device}>{device}</li>
          ))}
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
