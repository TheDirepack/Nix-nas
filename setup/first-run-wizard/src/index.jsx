import React from 'react';
import { createRoot } from 'react-dom/client';
import "@patternfly/patternfly/patternfly.css";
import "@patternfly/patternfly/patternfly-addons.css";
import { Wizard, WizardStep } from '@patternfly/react-core';
import './wizard.css';
import LanguageStep from './steps/LanguageStep.jsx';
import AdminStep from './steps/AdminStep.jsx';
import AuthentikStep from './steps/AuthentikStep.jsx';
import StorageStep from './steps/StorageStep.jsx';
import ConfirmStep from './steps/ConfirmStep.jsx';

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
  const [language, setLanguage] = React.useState('en');
  const [timezone, setTimezone] = React.useState('UTC');
  const [administrator, setAdministrator] = React.useState(emptyAdministrator);
  const [useSamePassword, setUseSamePassword] = React.useState(true);
  const [keePassPassword, setKeePassPassword] = React.useState('');
  const [allowDestructive, setAllowDestructive] = React.useState(false);
  const [theme, setTheme] = React.useState(readThemePreference);
  const [plan, setPlan] = React.useState(null);
  const [planError, setPlanError] = React.useState('');

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
    fetch('api/first-start', { headers: { Accept: 'application/json' } })
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

  const keePassEffective = useSamePassword ? administrator.password : keePassPassword;
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
        >
          <WizardStep id="wizard-language" step={1} name="Language and Timezone">
            <LanguageStep language={language} onLanguage={setLanguage} timezone={timezone} onTimezone={setTimezone} />
          </WizardStep>
          <WizardStep id="wizard-admin" step={2} name="Admin Account">
            <AdminStep
              administrator={administrator}
              onAdministrator={setAdministrator}
              useSamePassword={useSamePassword}
              onUseSamePassword={setUseSamePassword}
              keePassPassword={keePassPassword}
              onKeePassPassword={setKeePassPassword}
            />
          </WizardStep>
          <WizardStep id="wizard-authentik" step={3} name="Authentik Integration">
            <AuthentikStep />
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
              keePassPassword={keePassEffective}
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
