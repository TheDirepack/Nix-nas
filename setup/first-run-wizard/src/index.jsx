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
const App = () => (
  <Wizard
    navAriaLabel="First-run setup steps"
    mainAriaLabel="First-run setup content"
  >
    <WizardStep id="wizard-language" step={1} name="Language and Timezone">
      <LanguageStep />
    </WizardStep>
    <WizardStep id="wizard-admin" step={2} name="Admin Account">
      <AdminStep />
    </WizardStep>
    <WizardStep id="wizard-authentik" step={3} name="Authentik Integration">
      <AuthentikStep />
    </WizardStep>
    <WizardStep id="wizard-storage" step={4} name="Storage">
      <StorageStep />
    </WizardStep>
    <WizardStep id="wizard-confirm" step={5} name="Confirm and Reboot">
      <ConfirmStep />
    </WizardStep>
  </Wizard>
);

createRoot(document.getElementById('root')).render(
  <App />
);
