import React from 'react';
import { createRoot } from 'react-dom/client';
import "@patternfly/patternfly/patternfly.css";
import "@patternfly/patternfly/patternfly-addons.css";
import { Wizard, WizardStep } from '@patternfly/react-core';
import './wizard.css';
import AdminStep from './steps/AdminStep.jsx';
import StorageStep from './steps/StorageStep.jsx';
import ConfirmStep from './steps/ConfirmStep.jsx';
import { fetchJson } from './http.js';

// @patternfly/react-core 6.1.0 builds wizard steps exclusively from
// WizardStep children; the steps-array prop arrived in a later 6.x.
const emptyAdministrator = { username: '', name: '', email: '', password: '', confirm: '' };
const THEME_STORAGE_KEY = 'nas-setup-theme-preference';

const readThemePreference = () => {
  try {
    const value = window.localStorage.getItem(THEME_STORAGE_KEY);
    return ['auto', 'light', 'dark'].includes(value) ? value : 'auto';
  } catch (_error) {
    return 'auto';
  }
};

const App = () => {
  const [administrator, setAdministrator] = React.useState(emptyAdministrator);
  const [useSamePassword, setUseSamePassword] = React.useState(true);
  const [keePassPassword, setKeePassPassword] = React.useState('');
  const [keePassPasswordConfirm, setKeePassPasswordConfirm] = React.useState('');
  const [allowDestructive, setAllowDestructive] = React.useState(false);
  const [theme, setTheme] = React.useState(readThemePreference);
  const [plan, setPlan] = React.useState(null);
  const [planError, setPlanError] = React.useState('');
  const [planRequest, setPlanRequest] = React.useState(0);

  React.useEffect(() => {
    const media = window.matchMedia?.('(prefers-color-scheme: dark)');
    const applyTheme = () => {
      const isDark = theme === 'dark' || (theme === 'auto' && media?.matches);
      document.documentElement.classList.toggle('pf-v6-theme-dark', Boolean(isDark));
      document.documentElement.dataset.nasTheme = theme;
    };
    applyTheme();
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch (_error) {
      // A restricted browser may not permit localStorage; the current page
      // still follows the selected theme for this session.
    }
    media?.addEventListener?.('change', applyTheme);
    return () => media?.removeEventListener?.('change', applyTheme);
  }, [theme]);

  React.useEffect(() => {
    let cancelled = false;
    setPlan(null);
    setPlanError('');
    fetchJson('api/first-start', { headers: { Accept: 'application/json' } })
      .then((value) => {
        if (cancelled) return;
        setPlan(value);
      })
      .catch((reason) => {
        if (!cancelled) setPlanError(String(reason));
      });
    return () => {
      cancelled = true;
    };
  }, [planRequest]);

  const keePassEffective = useSamePassword ? administrator.password : keePassPassword;
  const keePassConfirmation = useSamePassword ? administrator.confirm : keePassPasswordConfirm;
  return (
    <div className="nas-setup-shell">
      <header className="nas-setup-header">
        <div>
          <p className="nas-setup-eyebrow">NAS appliance</p>
          <h1 className="nas-setup-title">First-start setup</h1>
          <p className="nas-setup-subtitle">A guided setup for identity, storage, and recovery.</p>
        </div>
        <label className="nas-theme-control">
          <span>Appearance</span>
          <select
            value={theme}
            onChange={(event) => setTheme(event.target.value)}
            aria-label="Color theme"
          >
            <option value="auto">Browser setting</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>
        </label>
      </header>
      <main className="nas-setup-main">
        <Wizard
          className="nas-setup-wizard"
          navAriaLabel="First-run setup steps"
          mainAriaLabel="First-run setup content"
          footer={{ isCancelHidden: true }}
        >
          <WizardStep id="wizard-admin" step={1} name="Admin Account">
            <AdminStep
              administrator={administrator}
              onAdministrator={setAdministrator}
              useSamePassword={useSamePassword}
              onUseSamePassword={setUseSamePassword}
              keePassPassword={keePassPassword}
              onKeePassPassword={setKeePassPassword}
              keePassPasswordConfirm={keePassPasswordConfirm}
              onKeePassPasswordConfirm={setKeePassPasswordConfirm}
            />
          </WizardStep>
          <WizardStep id="wizard-storage" step={2} name="Storage">
            <StorageStep
              plan={plan}
              planError={planError}
              allowDestructive={allowDestructive}
              onAllowDestructive={setAllowDestructive}
              onRefresh={() => setPlanRequest((value) => value + 1)}
            />
          </WizardStep>
          <WizardStep id="wizard-confirm" step={3} name="Confirm and Reboot" footer={<></>}>
            <ConfirmStep
              administrator={administrator}
              keePassPassword={keePassEffective}
              keePassPasswordConfirm={keePassConfirmation}
              allowDestructive={allowDestructive}
              plan={plan}
            />
          </WizardStep>
        </Wizard>
      </main>
    </div>
  );
};

createRoot(document.getElementById('root')).render(<App />);
