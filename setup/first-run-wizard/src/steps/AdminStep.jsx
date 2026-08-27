import React from 'react';
import { Alert, Checkbox, FormGroup, TextInput } from '@patternfly/react-core';
import { PasswordQualityFeedback, usePasswordQualityCheck } from '../PasswordQuality.jsx';

const AdminStep = ({
  administrator,
  onAdministrator,
  reuseLinuxPasswordForKeePass,
  onReuseLinuxPasswordForKeePass,
  keePassPassword,
  onKeePassPassword,
  keePassPasswordConfirm,
  onKeePassPasswordConfirm,
}) => {
  const update = (field) => (_event, value) => onAdministrator({ ...administrator, [field]: value });
  const linuxPasswordsMatch = !administrator.confirm || administrator.password === administrator.confirm;
  const keepassPasswordsMatch = !keePassPasswordConfirm || keePassPassword === keePassPasswordConfirm;
  const context = React.useMemo(
    () => [administrator.username, administrator.name, administrator.email],
    [administrator.username, administrator.name, administrator.email],
  );
  const linux = usePasswordQualityCheck(context);
  const keepass = usePasswordQualityCheck(context);

  return (
    <div>
      <Alert isInline variant="info" title="Choose recovery credentials">
        The KeePassXC master password protects the permanent secret database and is required for
        recovery on replacement hardware. Password reuse is optional and disabled by default.
      </Alert>
      <FormGroup label="Linux administrator username" fieldId="wizard-admin-username" isRequired>
        <TextInput
          id="wizard-admin-username"
          value={administrator.username}
          onChange={update('username')}
          autoComplete="username"
          placeholder="Choose a new local username"
        />
      </FormGroup>
      <FormGroup label="Full name" fieldId="wizard-admin-name" isRequired>
        <TextInput id="wizard-admin-name" value={administrator.name} onChange={update('name')} />
      </FormGroup>
      <FormGroup label="Administrator email" fieldId="wizard-admin-email" isRequired>
        <TextInput
          id="wizard-admin-email"
          type="email"
          value={administrator.email}
          onChange={update('email')}
          autoComplete="email"
        />
      </FormGroup>
      <FormGroup label="Linux administrator password" fieldId="wizard-admin-password" isRequired>
        <TextInput
          id="wizard-admin-password"
          type="password"
          value={administrator.password}
          onChange={update('password')}
          onBlur={() => linux.check(administrator.password)}
          autoComplete="new-password"
        />
      </FormGroup>
      <PasswordQualityFeedback label="Linux administrator password" quality={linux.quality} error={linux.error} />
      <FormGroup label="Confirm Linux administrator password" fieldId="wizard-admin-password-confirm" isRequired>
        <TextInput
          id="wizard-admin-password-confirm"
          type="password"
          value={administrator.confirm}
          onChange={update('confirm')}
          autoComplete="new-password"
          validated={linuxPasswordsMatch ? 'default' : 'error'}
        />
      </FormGroup>
      <Checkbox
        id="wizard-keepass-reuse-linux"
        label="Reuse the Linux administrator password for KeePassXC"
        isChecked={reuseLinuxPasswordForKeePass}
        onChange={(_event, checked) => onReuseLinuxPasswordForKeePass(checked)}
      />
      {reuseLinuxPasswordForKeePass ? (
        <PasswordQualityFeedback label="KeePassXC master password" quality={linux.quality} error={linux.error} />
      ) : (
        <>
          <FormGroup label="KeePassXC master password" fieldId="wizard-keepass-password" isRequired>
            <TextInput
              id="wizard-keepass-password"
              type="password"
              value={keePassPassword}
              onChange={(_event, value) => onKeePassPassword(value)}
              onBlur={() => keepass.check(keePassPassword)}
              autoComplete="new-password"
            />
          </FormGroup>
          <PasswordQualityFeedback label="KeePassXC master password" quality={keepass.quality} error={keepass.error} />
          <FormGroup label="Confirm KeePassXC master password" fieldId="wizard-keepass-password-confirm" isRequired>
            <TextInput
              id="wizard-keepass-password-confirm"
              type="password"
              value={keePassPasswordConfirm}
              onChange={(_event, value) => onKeePassPasswordConfirm(value)}
              autoComplete="new-password"
              validated={keepassPasswordsMatch ? 'default' : 'error'}
            />
          </FormGroup>
        </>
      )}
    </div>
  );
};

export default AdminStep;
