import React from 'react';
import { Alert, Checkbox, FormGroup, TextInput } from '@patternfly/react-core';
import { PasswordQualityFeedback, usePasswordQualityCheck } from '../PasswordQuality.jsx';

const AuthentikStep = ({
  authentikUrl,
  onAuthentikUrl,
  reuseLinuxPassword,
  onReuseLinuxPassword,
  administratorPassword,
  onAdministratorPassword,
  administratorPasswordConfirm,
  onAdministratorPasswordConfirm,
  userInputs,
}) => {
  const passwordsMatch = !administratorPasswordConfirm || administratorPassword === administratorPasswordConfirm;
  const context = React.useMemo(() => [...userInputs, authentikUrl], [userInputs, authentikUrl]);
  const quality = usePasswordQualityCheck(context);

  return (
    <div>
      <Alert isInline variant="info" title="Bootstrap identity is temporary">
        The bootstrap Authentik authority only protects first-run setup. Setup creates the permanent
        administrator and then retires bootstrap authority. Password reuse is optional and disabled by default.
      </Alert>
      <p>
        Authentik is already running with the embedded proxy outpost. Identity applications are
        reconciled by the appliance after setup completes.
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
      <Checkbox
        id="wizard-authentik-reuse-linux"
        label="Reuse the Linux administrator password for Authentik"
        isChecked={reuseLinuxPassword}
        onChange={(_event, checked) => onReuseLinuxPassword(checked)}
      />
      {!reuseLinuxPassword && (
        <>
          <FormGroup label="Authentik administrator password" fieldId="wizard-authentik-admin-password" isRequired>
            <TextInput
              id="wizard-authentik-admin-password"
              type="password"
              value={administratorPassword}
              onChange={(_event, value) => onAdministratorPassword(value)}
              onBlur={() => quality.check(administratorPassword)}
              autoComplete="new-password"
            />
          </FormGroup>
          <PasswordQualityFeedback label="Authentik administrator password" quality={quality.quality} error={quality.error} />
          <FormGroup
            label="Confirm Authentik administrator password"
            fieldId="wizard-authentik-admin-password-confirm"
            isRequired
          >
            <TextInput
              id="wizard-authentik-admin-password-confirm"
              type="password"
              value={administratorPasswordConfirm}
              onChange={(_event, value) => onAdministratorPasswordConfirm(value)}
              autoComplete="new-password"
              validated={passwordsMatch ? 'default' : 'error'}
            />
          </FormGroup>
        </>
      )}
    </div>
  );
};

export default AuthentikStep;
