import React from 'react';
import { createRoot } from 'react-dom/client';
import "@patternfly/patternfly/patternfly.css";
import "@patternfly/patternfly/patternfly-addons.css";
import { Wizard, WizardStep } from '@patternfly/react-core';
import LanguageStep from './steps/LanguageStep.jsx';
import AdminStep from './steps/AdminStep.jsx';
import AuthentikStep from './steps/AuthentikStep.jsx';
import StorageStep from './steps/StorageStep.jsx';
import ConfirmStep from './steps/ConfirmStep.jsx';

// @patternfly/react-core 6.1.0 builds wizard steps exclusively from
// WizardStep children; the steps-array prop arrived in a later 6.x.
const emptyAdministrator = { username: '', name: '', email: '', password: '', confirm: '' };

const App = () => {
  const [language, setLanguage] = React.useState('en');
  const [timezone, setTimezone] = React.useState('UTC');
  const [administrator, setAdministrator] = React.useState(emptyAdministrator);
  const [reuseLinuxPasswordForKeePass, setReuseLinuxPasswordForKeePass] = React.useState(false);
  const [keePassPassword, setKeePassPassword] = React.useState('');
  const [keePassPasswordConfirm, setKeePassPasswordConfirm] = React.useState('');
  const [authentikUrl, setAuthentikUrl] = React.useState('');
  const [reuseLinuxPasswordForAuthentik, setReuseLinuxPasswordForAuthentik] = React.useState(false);
  const [authentikAdministratorPassword, setAuthentikAdministratorPassword] = React.useState('');
  const [authentikAdministratorPasswordConfirm, setAuthentikAdministratorPasswordConfirm] = React.useState('');
  const [allowDestructive, setAllowDestructive] = React.useState(false);
  const [plan, setPlan] = React.useState(null);
  const [planError, setPlanError] = React.useState('');

  React.useEffect(() => {
    let cancelled = false;
    fetch('api/first-start', { headers: { Accept: 'application/json' }, cache: 'no-store' })
      .then((response) => response.json())
      .then((value) => {
        if (cancelled) return;
        if (value.error) {
          setPlanError(value.error);
        } else {
          setPlan(value);
        }
      })
      .catch((reason) => {
        if (!cancelled) setPlanError(String(reason));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const effectiveKeePassPassword = reuseLinuxPasswordForKeePass ? administrator.password : keePassPassword;
  const effectiveKeePassPasswordConfirm = reuseLinuxPasswordForKeePass
    ? administrator.confirm
    : keePassPasswordConfirm;
  const effectiveAuthentikPassword = reuseLinuxPasswordForAuthentik
    ? administrator.password
    : authentikAdministratorPassword;
  const effectiveAuthentikPasswordConfirm = reuseLinuxPasswordForAuthentik
    ? administrator.confirm
    : authentikAdministratorPasswordConfirm;

  return (
    <Wizard
      navAriaLabel="First-run setup steps"
      mainAriaLabel="First-run setup content"
    >
      <WizardStep id="wizard-language" step={1} name="Language and Timezone">
        <LanguageStep language={language} onLanguage={setLanguage} timezone={timezone} onTimezone={setTimezone} />
      </WizardStep>
      <WizardStep id="wizard-admin" step={2} name="Administrator and Recovery">
        <AdminStep
          administrator={administrator}
          onAdministrator={setAdministrator}
          reuseLinuxPasswordForKeePass={reuseLinuxPasswordForKeePass}
          onReuseLinuxPasswordForKeePass={setReuseLinuxPasswordForKeePass}
          keePassPassword={keePassPassword}
          onKeePassPassword={setKeePassPassword}
          keePassPasswordConfirm={keePassPasswordConfirm}
          onKeePassPasswordConfirm={setKeePassPasswordConfirm}
        />
      </WizardStep>
      <WizardStep id="wizard-authentik" step={3} name="Authentik Administrator">
        <AuthentikStep
          authentikUrl={authentikUrl}
          onAuthentikUrl={setAuthentikUrl}
          reuseLinuxPassword={reuseLinuxPasswordForAuthentik}
          onReuseLinuxPassword={setReuseLinuxPasswordForAuthentik}
          administratorPassword={authentikAdministratorPassword}
          onAdministratorPassword={setAuthentikAdministratorPassword}
          administratorPasswordConfirm={authentikAdministratorPasswordConfirm}
          onAdministratorPasswordConfirm={setAuthentikAdministratorPasswordConfirm}
        />
      </WizardStep>
      <WizardStep id="wizard-storage" step={4} name="Storage">
        <StorageStep
          plan={plan}
          planError={planError}
          allowDestructive={allowDestructive}
          onAllowDestructive={setAllowDestructive}
        />
      </WizardStep>
      <WizardStep id="wizard-confirm" step={5} name="Confirm and Reboot">
        <ConfirmStep
          administrator={administrator}
          keePassPassword={effectiveKeePassPassword}
          keePassPasswordConfirm={effectiveKeePassPasswordConfirm}
          authentikAdministratorPassword={effectiveAuthentikPassword}
          authentikAdministratorPasswordConfirm={effectiveAuthentikPasswordConfirm}
          allowDestructive={allowDestructive}
          plan={plan}
        />
      </WizardStep>
    </Wizard>
  );
};

createRoot(document.getElementById('root')).render(<App />);
