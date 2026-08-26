import React from 'react';
import { FormGroup, TextInput, Checkbox } from '@patternfly/react-core';

const AdminStep = ({
  administrator,
  onAdministrator,
  useSamePassword,
  onUseSamePassword,
  keePassPassword,
  onKeePassPassword,
}) => {
  const update = (field) => (_event, value) => onAdministrator({ ...administrator, [field]: value });

  return (
    <div>
      <FormGroup label="Username" fieldId="wizard-admin-username" isRequired>
        <TextInput id="wizard-admin-username" value={administrator.username} onChange={update('username')} />
      </FormGroup>
      <FormGroup label="Full name" fieldId="wizard-admin-name" isRequired>
        <TextInput id="wizard-admin-name" value={administrator.name} onChange={update('name')} />
      </FormGroup>
      <FormGroup label="Email" fieldId="wizard-admin-email" isRequired>
        <TextInput
          id="wizard-admin-email"
          type="email"
          value={administrator.email}
          onChange={update('email')}
        />
      </FormGroup>
      <FormGroup label="Password" fieldId="wizard-admin-password" isRequired>
        <TextInput
          id="wizard-admin-password"
          type="password"
          value={administrator.password}
          onChange={update('password')}
        />
      </FormGroup>
      <FormGroup label="Confirm password" fieldId="wizard-admin-password-confirm" isRequired>
        <TextInput
          id="wizard-admin-password-confirm"
          type="password"
          value={administrator.confirm}
          onChange={update('confirm')}
        />
      </FormGroup>
      <Checkbox
        id="wizard-keepass-same"
        label="Use the same password for the KeePassXC database"
        isChecked={useSamePassword}
        onChange={(_event, checked) => onUseSamePassword(checked)}
      />
      {!useSamePassword && (
        <FormGroup label="KeePassXC database password" fieldId="wizard-keepass-password" isRequired>
          <TextInput
            id="wizard-keepass-password"
            type="password"
            value={keePassPassword}
            onChange={(_event, value) => onKeePassPassword(value)}
          />
        </FormGroup>
      )}
    </div>
  );
};

export default AdminStep;
