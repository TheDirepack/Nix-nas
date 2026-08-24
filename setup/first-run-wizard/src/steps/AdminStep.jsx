import React from 'react';
import { Alert, FormGroup, TextInput } from '@patternfly/react-core';

const AdminStep = () => {
  const [adminUsername, setAdminUsername] = React.useState('');
  const [adminEmail, setAdminEmail] = React.useState('');
  const [adminPassword, setAdminPassword] = React.useState('');
  const [adminPasswordConfirm, setAdminPasswordConfirm] = React.useState('');
  const [keePassMasterPassword, setKeePassMasterPassword] = React.useState('');
  const [keePassMasterPasswordConfirm, setKeePassMasterPasswordConfirm] = React.useState('');

  const linuxPasswordsMatch = !adminPasswordConfirm || adminPassword === adminPasswordConfirm;
  const keepassPasswordsMatch =
    !keePassMasterPasswordConfirm || keePassMasterPassword === keePassMasterPasswordConfirm;

  return (
    <div>
      <Alert
        isInline
        variant="info"
        title="Choose independent recovery credentials"
      >
        The Linux administrator and KeePassXC master passwords are separate. The KeePassXC
        password is never stored by the NAS and is required to recover the permanent secret
        database on replacement hardware.
      </Alert>
      <FormGroup label="Linux administrator username" fieldId="wizard-admin-username" isRequired>
        <TextInput
          id="wizard-admin-username"
          value={adminUsername}
          onChange={(_event, value) => setAdminUsername(value)}
          autoComplete="username"
          placeholder="Choose a new local username"
        />
      </FormGroup>
      <FormGroup label="Administrator email" fieldId="wizard-admin-email" isRequired>
        <TextInput
          id="wizard-admin-email"
          type="email"
          value={adminEmail}
          onChange={(_event, value) => setAdminEmail(value)}
          autoComplete="email"
          placeholder="you@example.com"
        />
      </FormGroup>
      <FormGroup label="Linux administrator password" fieldId="wizard-admin-password" isRequired>
        <TextInput
          id="wizard-admin-password"
          type="password"
          value={adminPassword}
          onChange={(_event, value) => setAdminPassword(value)}
          autoComplete="new-password"
        />
      </FormGroup>
      <FormGroup
        label="Confirm Linux administrator password"
        fieldId="wizard-admin-password-confirm"
        isRequired
      >
        <TextInput
          id="wizard-admin-password-confirm"
          type="password"
          value={adminPasswordConfirm}
          onChange={(_event, value) => setAdminPasswordConfirm(value)}
          autoComplete="new-password"
          validated={linuxPasswordsMatch ? 'default' : 'error'}
        />
      </FormGroup>
      <FormGroup label="KeePassXC master password" fieldId="wizard-keepass-password" isRequired>
        <TextInput
          id="wizard-keepass-password"
          type="password"
          value={keePassMasterPassword}
          onChange={(_event, value) => setKeePassMasterPassword(value)}
          autoComplete="new-password"
        />
      </FormGroup>
      <FormGroup
        label="Confirm KeePassXC master password"
        fieldId="wizard-keepass-confirm"
        isRequired
      >
        <TextInput
          id="wizard-keepass-confirm"
          type="password"
          value={keePassMasterPasswordConfirm}
          onChange={(_event, value) => setKeePassMasterPasswordConfirm(value)}
          autoComplete="new-password"
          validated={keepassPasswordsMatch ? 'default' : 'error'}
        />
      </FormGroup>
    </div>
  );
};

export default AdminStep;
