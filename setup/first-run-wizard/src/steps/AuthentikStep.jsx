import React from 'react';
import { Alert, FormGroup, TextInput } from '@patternfly/react-core';

const AuthentikStep = () => {
  const [authentikExternalUrl, setAuthentikExternalUrl] = React.useState('https://');
  const [authentikPassword, setAuthentikPassword] = React.useState('');
  const [authentikPasswordConfirm, setAuthentikPasswordConfirm] = React.useState('');
  const passwordsMatch = !authentikPasswordConfirm || authentikPassword === authentikPasswordConfirm;

  return (
    <div>
      <Alert isInline variant="info" title="Authentik owns web identity after setup">
        The initial Authentik administrator receives a separate password. Static providers,
        applications, policy bindings, and the embedded proxy outpost are appliance-managed
        rather than optional setup-time objects.
      </Alert>
      <FormGroup label="Authentik external URL" fieldId="wizard-authentik-url" isRequired>
        <TextInput
          id="wizard-authentik-url"
          type="text"
          value={authentikExternalUrl}
          onChange={(_event, value) => setAuthentikExternalUrl(value)}
          placeholder="https://nas.example.com"
        />
      </FormGroup>
      <FormGroup
        label="Authentik administrator password"
        fieldId="wizard-authentik-password"
        isRequired
      >
        <TextInput
          id="wizard-authentik-password"
          type="password"
          value={authentikPassword}
          onChange={(_event, value) => setAuthentikPassword(value)}
          autoComplete="new-password"
        />
      </FormGroup>
      <FormGroup
        label="Confirm Authentik administrator password"
        fieldId="wizard-authentik-password-confirm"
        isRequired
      >
        <TextInput
          id="wizard-authentik-password-confirm"
          type="password"
          value={authentikPasswordConfirm}
          onChange={(_event, value) => setAuthentikPasswordConfirm(value)}
          autoComplete="new-password"
          validated={passwordsMatch ? 'default' : 'error'}
        />
      </FormGroup>
    </div>
  );
};

export default AuthentikStep;
