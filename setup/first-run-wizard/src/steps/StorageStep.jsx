import React from 'react';
import { FormGroup, Checkbox, Label } from '@patternfly/react-core';

const StorageStep = ({ plan, planError, allowDestructive, onAllowDestructive }) => {
  if (planError) {
    return <p>Unable to load the storage plan: {planError}</p>;
  }
  if (!plan) {
    return <p>Loading the storage plan...</p>;
  }
  const storage = plan.storage || {};
  return (
    <div>
      <p>Review the storage plan published by the appliance. Pools are created exactly as reviewed.</p>
      <FormGroup label="Status" fieldId="wizard-plan-status">
        <Label color={plan.status === 'ready' ? 'green' : 'orange'}>{plan.status}</Label>
      </FormGroup>
      <FormGroup label="Pool" fieldId="wizard-plan-pool">
        <TextInput id="wizard-plan-pool" value={storage.pool || ''} isDisabled />
      </FormGroup>
      <FormGroup label="Dataset" fieldId="wizard-plan-dataset">
        <TextInput id="wizard-plan-dataset" value={storage.dataset || ''} isDisabled />
      </FormGroup>
      <FormGroup label="Devices" fieldId="wizard-plan-devices">
        <TextInput
          id="wizard-plan-devices"
          value={Array.isArray(storage.devices) ? storage.devices.join(' ') : ''}
          isDisabled
        />
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
