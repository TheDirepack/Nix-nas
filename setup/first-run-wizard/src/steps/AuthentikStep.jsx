import React from 'react';
import { FormGroup, TextInput } from '@patternfly/react-core';

const AuthentikStep = ({ authentikUrl, onAuthentikUrl }) => (
  <div>
    <p>
      Authentik is already running with the embedded proxy outpost. The external
      URL below is recorded for reference; identity applications are reconciled
      by the appliance after setup completes.
    </p>
    <FormGroup label="Authentik external URL" fieldId="wizard-authentik-url">
      <TextInput
        id="wizard-authentik-url"
        type="text"
        value={authentikUrl}
        onChange={(_event, value) => onAuthentikUrl(value)}
        placeholder="https://nas.example.com"
      />
    </FormGroup>
  </div>
);

export default AuthentikStep;
