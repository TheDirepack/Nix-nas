import React from 'react';
import { Alert, Checkbox, FormGroup, Progress, TextInput } from '@patternfly/react-core';
import { passwordQuality } from '../api.js';

const qualityVariant = (quality) => {
  if (!quality) return 'info';
  if (quality.breachStatus === 'breached' || !quality.localAccepted) return 'danger';
  if (quality.breachStatus === 'unavailable') return 'warning';
  return 'success';
};

const Quality = ({ label, quality, error }) => {
  if (error) return <Alert isInline variant="warning" title={`${label} strength check unavailable`}>{error}</Alert>;
  if (!quality) return null;
  const score = Number.isInteger(quality.zxcvbnScore) ? quality.zxcvbnScore : 0;
  const detail = [quality.warning, ...(quality.suggestions || [])].filter(Boolean).join(' ');
  return (
    <Alert isInline variant={qualityVariant(quality)} title={`${label} strength: ${score}/4`}>
      <Progress value={score * 25} aria-label={`${label} password strength`} />
      {quality.breachStatus === 'breached' && <p>This password is known to be breached and cannot be used.</p>}
      {quality.breachStatus === 'unavailable' && <p>The online breach check is unavailable; local strength rules still apply.</p>}
      {detail && <p>{detail}</p>}
    </Alert>
  );
};

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
  const [linuxQuality, setLinuxQuality] = React.useState(null);
  const [linuxQualityError, setLinuxQualityError] = React.useState('');
  const [keepassQuality, setKeepassQuality] = React.useState(null);
  const [keepassQualityError, setKeepassQualityError] = React.useState('');
  const context = [administrator.username, administrator.name, administrator.email].filter(Boolean);

  const check = async (password, setQuality, setError) => {
    if (!password) {
      setQuality(null);
      setError('');
      return;
    }
    try {
      setError('');
      setQuality(await passwordQuality(password, context));
    } catch (reason) {
      setQuality(null);
      setError(String(reason));
    }
  };

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
          onBlur={() => check(administrator.password, setLinuxQuality, setLinuxQualityError)}
          autoComplete="new-password"
        />
      </FormGroup>
      <Quality label="Linux administrator password" quality={linuxQuality} error={linuxQualityError} />
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
        <Quality label="KeePassXC master password" quality={linuxQuality} error={linuxQualityError} />
      ) : (
        <>
          <FormGroup label="KeePassXC master password" fieldId="wizard-keepass-password" isRequired>
            <TextInput
              id="wizard-keepass-password"
              type="password"
              value={keePassPassword}
              onChange={(_event, value) => onKeePassPassword(value)}
              onBlur={() => check(keePassPassword, setKeepassQuality, setKeepassQualityError)}
              autoComplete="new-password"
            />
          </FormGroup>
          <Quality label="KeePassXC master password" quality={keepassQuality} error={keepassQualityError} />
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
