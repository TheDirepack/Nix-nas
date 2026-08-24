import React from 'react';
import { FormGroup, Label, TextInput } from '@patternfly/react-core';

const LanguageStep = () => (
  <div>
    <FormGroup label="Language" fieldId="wizard-language" isRequired>
      <TextInput id="wizard-language" placeholder="en" />
    </FormGroup>
    <FormGroup label="Timezone" fieldId="wizard-timezone" isRequired>
      <TextInput id="wizard-timezone" placeholder="UTC" />
    </FormGroup>
  </div>
);

export default LanguageStep;
