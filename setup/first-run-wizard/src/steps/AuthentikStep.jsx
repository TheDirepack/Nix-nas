import React from 'react';
import { Alert, Label } from '@patternfly/react-core';

const AuthentikStep = () => (
  <div className="nas-wizard-step">
    <p className="nas-wizard-intro">
      Authentik is the identity authority for the appliance. The setup wizard is registered there
      as a real <strong>NAS Setup</strong> application, so it appears in the Authentik application
      viewer for authorized administrators instead of being an untracked external link.
    </p>
    <div className="nas-setup-card">
      <h2>NAS Setup application</h2>
      <p>
        Access is limited to the <code>nas_admin</code> group. The embedded proxy outpost protects
        this wizard and the appliance removes the temporary application after setup is complete.
      </p>
      <p>
        <Label color="green">Registered in Authentik</Label>
      </p>
      <a className="nas-setup-link" href="/identity/if/user/" target="_blank" rel="noreferrer">
        Open the Authentik application viewer
      </a>
    </div>
    <Alert variant="info" isInline title="No Authentik URL is required here">
      The appliance publishes its configured hostname and reconciles the provider automatically.
      This prevents a mistyped URL from breaking sign-in or proxy authorization.
    </Alert>
  </div>
);

export default AuthentikStep;
