import React from 'react';
import { Button } from '@patternfly/react-core';

const ConfirmStep = () => (
  <div>
    <p>
      Finishing setup applies the configuration, writes the secrets, and
      reboots the appliance. After reboot the full service stack starts with
      the accounts configured here.
    </p>
    <Button variant="primary">Confirm and reboot</Button>
  </div>
);

export default ConfirmStep;
