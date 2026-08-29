import React from 'react';
import { FormGroup, TextInput, Checkbox, HelperText, HelperTextItem } from '@patternfly/react-core';
import { PasswordQualityFeedback, usePasswordQualityCheck } from '../PasswordQuality.jsx';

const AdminStep = ({
  administrator,
  onAdministrator,
  useSamePassword,
  onUseSamePassword,
  keePassPassword,
  onKeePassPassword,
  keePassPasswordConfirm,
  onKeePassPasswordConfirm,
}) => {
  const update = (field) => (_event, value) => onAdministrator({ ...administrator, [field]: value });
  const quality = usePasswordQualityCheck([administrator.username, administrator.name, administrator.email]);

  return (
    <div className="nas-wizard-step">
      <p className="nas-wizard-intro">
        This account becomes the first NAS administrator in Authentik and on the local recovery
        plane. Use a unique username and a strong password that you can store safely.
      </p>
      <FormGroup label="Username" fieldId="wizard-admin-username" isRequired>
        <TextInput
          id="wizard-admin-username"
          value={administrator.username}
          onChange={update('username')}
          autoComplete="username"
          maxLength={32}
          pattern="[a-z_][a-z0-9_-]{0,31}"
        />
        <HelperText>
          <HelperTextItem>Use lowercase letters, numbers, underscores, or hyphens. This name is used for sign-in.</HelperTextItem>
        </HelperText>
      </FormGroup>
      <FormGroup label="Full name" fieldId="wizard-admin-name" isRequired>
        <TextInput id="wizard-admin-name" value={administrator.name} onChange={update('name')} maxLength={256} />
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
          autoComplete="email"
          maxLength={320}
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
          autoComplete="new-password"
          minLength={12}
          onBlur={() => quality.check(administrator.password)}
        />
        <PasswordQualityFeedback label="Administrator" quality={quality.quality} error={quality.error} />
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
          autoComplete="new-password"
          minLength={12}
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
        <>
          <FormGroup label="KeePassXC database password" fieldId="wizard-keepass-password" isRequired>
            <TextInput
              id="wizard-keepass-password"
              type="password"
              value={keePassPassword}
              onChange={(_event, value) => onKeePassPassword(value)}
              autoComplete="new-password"
            />
          </FormGroup>
          <FormGroup
            label="Confirm KeePassXC database password"
            fieldId="wizard-keepass-password-confirm"
            isRequired
          >
            <TextInput
              id="wizard-keepass-password-confirm"
              type="password"
              value={keePassPasswordConfirm}
              onChange={(_event, value) => onKeePassPasswordConfirm(value)}
              autoComplete="new-password"
            />
          </FormGroup>
        </>
      )}
    </div>
  );
};

export default AdminStep;
