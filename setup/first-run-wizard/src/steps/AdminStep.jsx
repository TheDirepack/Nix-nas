import React from 'react';
import { FormGroup, Label, TextInput, Checkbox } from '@patternfly/react-core';

const AdminStep = () => {
  const [adminUsername, setAdminUsername] = React.useState('admin');
  const [adminEmail, setAdminEmail] = React.useState('');
  const [adminPassword, setAdminPassword] = React.useState('');
  const [adminPasswordConfirm, setAdminPasswordConfirm] = React.useState('');
  const [useSamePassword, setUseSamePassword] = React.useState(true);
  const [keePassMasterPassword, setKeePassMasterPassword] = React.useState('');
  const [keePassMasterPasswordConfirm, setKeePassMasterPasswordConfirm] = React.useState('');

  return (
    <div>
      <FormGroup label="Username" fieldId="wizard-admin-username" isRequired>
        <TextInput
          id="wizard-admin-username"
          value={adminUsername}
          onChange={(_event, value) => setAdminUsername(value)}
          placeholder="admin"
        />
      </FormGroup>
      <FormGroup label="Email" fieldId="wizard-admin-email" isRequired>
        <TextInput
          id="wizard-admin-email"
          type="email"
          value={adminEmail}
          onChange={(_event, value) => setAdminEmail(value)}
          placeholder="admin@example.com"
        />
      </FormGroup>
      <FormGroup label="Password" fieldId="wizard-admin-password" isRequired>
        <TextInput
          id="wizard-admin-password"
          type="password"
          value={adminPassword}
          onChange={(_event, value) => setAdminPassword(value)}
        />
        <Label htmlFor="wizard-admin-password-confirm">Confirm password</Label>
        <TextInput
          id="wizard-admin-password-confirm"
          type="password"
          value={adminPasswordConfirm}
          onChange={(_event, value) => setAdminPasswordConfirm(value)}
        />
      </FormGroup>
      <Checkbox
        id="wizard-keepass-same"
        label="Use the same password for the KeePassXC master key"
        isChecked={useSamePassword}
        onChange={(_event, checked) => setUseSamePassword(checked)}
      />
      {!useSamePassword && (
        <>
          <FormGroup label="KeePassXC master password" fieldId="wizard-keepass-password" isRequired>
            <TextInput
              id="wizard-keepass-password"
              type="password"
              value={keePassMasterPassword}
              onChange={(_event, value) => setKeePassMasterPassword(value)}
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
            />
          </FormGroup>
        </>
      )}
    </div>
  );
};

export default AdminStep;
