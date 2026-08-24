import React from 'react';
import { FormGroup, Label, TextInput } from '@patternfly/react-core';

const StorageStep = () => (
  <div>
    <p>
      ZFS pool creation is handled by the setup tooling after this wizard
      completes. Detected pools are shown read-only below.
    </p>
    <FormGroup label="ZFS pool name" fieldId="wizard-pool-name">
      <TextInput id="wizard-pool-name" placeholder="tank" isDisabled />
    </FormGroup>
    <FormGroup label="Pool devices" fieldId="wizard-pool-devices">
      <TextInput id="wizard-pool-devices" placeholder="/dev/sdb /dev/sdc" isDisabled />
    </FormGroup>
  </div>
);

export default StorageStep;
