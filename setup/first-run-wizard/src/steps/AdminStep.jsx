import React from 'react';
import { FormGroup, TextInput, Checkbox, HelperText, HelperTextItem } from '@patternfly/react-core';

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
    <div className="nas-wizard-step">
      <p className="nas-wizard-intro">
        This account becomes the first NAS administrator in Authentik and on the local recovery
        plane. Use a unique username and a strong password that you can store safely.
      </p>
      <FormGroup label="Username" fieldId="wizard-admin-username" isRequired>
        <TextInput id="wizard-admin-username" value={administrator.username} onChange={update('username')} />
        <HelperText>
          <HelperTextItem>Use lowercase letters, numbers, underscores, or hyphens. This name is used for sign-in.</HelperTextItem>
        </HelperText>
      </FormGroup>
      <FormGroup label="Full name" fieldId="wizard-admin-name" isRequired>
        <TextInput id="wizard-admin-name" value={administrator.name} onChange={update('name')} />
        <HelperText>
          <HelperTextItem>Shown in Authentik and in operator-facing audit messages.</HelperTextItem>
        </HelperText>
      </FormGroup>
      <FormGroup label="Email" fieldId="wizard-admin-email" isRequired>
        <TextInput
          id="wizard-admin-email"
          type="email"
          value={administrator.email}
          onChange={update('email')}
        />
        <HelperText>
          <HelperTextItem>Used for account recovery and notifications; it is not displayed publicly.</HelperTextItem>
        </HelperText>
      </FormGroup>
      <FormGroup label="Password" fieldId="wizard-admin-password" isRequired>
        <TextInput
          id="wizard-admin-password"
          type="password"
          value={administrator.password}
          onChange={update('password')}
        />
        <HelperText>
          <HelperTextItem>Use at least 12 characters and avoid reusing a password from another service.</HelperTextItem>
        </HelperText>
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
      <HelperText>
        <HelperTextItem>The KeePassXC database protects appliance secrets. A separate password gives it an additional boundary.</HelperTextItem>
      </HelperText>
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
