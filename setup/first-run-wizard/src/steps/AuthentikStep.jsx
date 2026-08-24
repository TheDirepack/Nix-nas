import React from 'react';
import { FormGroup, TextInput, Checkbox } from '@patternfly/react-core';

const AuthentikStep = () => {
  const [authentikExternalUrl, setAuthentikExternalUrl] = React.useState('https://');
  const [createOutpost, setCreateOutpost] = React.useState(true);
  const [createProviderApp, setCreateProviderApp] = React.useState(true);

  return (
    <div>
      <FormGroup label="Authentik external URL" fieldId="wizard-authentik-url" isRequired>
        <TextInput
          id="wizard-authentik-url"
          type="text"
          value={authentikExternalUrl}
          onChange={(_event, value) => setAuthentikExternalUrl(value)}
          placeholder="https://nas.example.com"
        />
      </FormGroup>
      <Checkbox
        id="wizard-outpost"
        label="Configure the embedded proxy outpost"
        isChecked={createOutpost}
        onChange={(_event, checked) => setCreateOutpost(checked)}
      />
      <Checkbox
        id="wizard-provider-app"
        label="Create the initial OAuth2 provider and application"
        isChecked={createProviderApp}
        onChange={(_event, checked) => setCreateProviderApp(checked)}
      />
    </div>
  );
};

export default AuthentikStep;
