import React from 'react';
import { FormGroup, TextInput } from '@patternfly/react-core';

const LanguageStep = ({ language, onLanguage, timezone, onTimezone }) => (
  <div>
    <FormGroup label="Language" fieldId="wizard-language-input" isRequired>
      <TextInput
        id="wizard-language-input"
        value={language}
        onChange={(_event, value) => onLanguage(value)}
        placeholder="en"
      />
    </FormGroup>
    <FormGroup label="Timezone" fieldId="wizard-timezone-input" isRequired>
      <TextInput
        id="wizard-timezone-input"
        value={timezone}
        onChange={(_event, value) => onTimezone(value)}
        placeholder="UTC"
      />
    </FormGroup>
  </div>
);

export default LanguageStep;
