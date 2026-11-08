import React from 'react';
import { Alert, Button, Checkbox, FormGroup } from '@patternfly/react-core';
import { fetchJson } from '../http.js';

const StoragePlanForm = ({ onCreated, onRefresh }) => {
  const [options, setOptions] = React.useState(null);
  const [devices, setDevices] = React.useState([]);
  const [topology, setTopology] = React.useState('single');
  const [error, setError] = React.useState('');
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    let cancelled = false;
    fetchJson('api/storage-options').then((value) => {
      if (!cancelled) setOptions(value);
    }).catch((reason) => {
      if (!cancelled) setError(String(reason));
    });
    return () => { cancelled = true; };
  }, []);

  const create = async () => {
    setBusy(true);
    setError('');
    try {
      const storage = options.poolPresent
        ? { createPool: false }
        : { createPool: true, devices, topology, wipeDevices: true };
      const plan = await fetchJson('api/first-start/plan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ storage }),
      });
      onCreated(plan);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  return <div className="nas-wizard-step">
    <h2>Create the storage plan</h2>
    <p>Select the data disks for this appliance. Creating a plan does not format disks.
      You will review the exact devices and confirm erasure before running setup.</p>
    {error && <Alert variant="danger" isInline title="Storage plan unavailable">{error}</Alert>}
    {!options && !error && <p>Inspecting storage devices...</p>}
    {options?.poolPresent && <p>The configured ZFS pool already exists. Setup will use it without recreating it.</p>}
    {options && !options.poolPresent && <>
      <FormGroup label="Data disks" fieldId="wizard-data-disks">
        <div id="wizard-data-disks">
          {(options.devices || []).filter((device) => device.type === 'disk').map((device, index) =>
            <Checkbox key={device.path} id={`wizard-disk-${index}`}
              label={`${device.path}${device.model ? ` — ${device.model}` : ''}${device.serial ? ` (${device.serial})` : ''}${device.size ? ` — ${device.size} bytes` : ''}${device.available ? '' : ' — unavailable (in use or read-only)'}`}
              isDisabled={!device.available || busy} isChecked={devices.includes(device.path)}
              onChange={(_event, checked) => setDevices((current) => checked
                ? [...current, device.path] : current.filter((path) => path !== device.path))} />)}
        </div>
      </FormGroup>
      <FormGroup label="Pool layout" fieldId="wizard-pool-topology">
        <select id="wizard-pool-topology" value={topology} disabled={busy} onChange={(event) => setTopology(event.target.value)}>
          <option value="single">Single disk</option>
          <option value="mirror">Mirror (at least 2 disks)</option>
          <option value="raidz1">RAIDZ1 (at least 3 disks)</option>
          <option value="raidz2">RAIDZ2 (at least 4 disks)</option>
          <option value="raidz3">RAIDZ3 (at least 5 disks)</option>
          <option value="stripe">Stripe without redundancy (at least 2 disks)</option>
        </select>
      </FormGroup>
    </>}
    <Button onClick={create} isLoading={busy} isDisabled={busy || !options || (!options.poolPresent && devices.length === 0)}>
      Review storage plan
    </Button>
    <Button variant="link" onClick={onRefresh} isDisabled={busy}>Refresh plan</Button>
  </div>;
};

export default StoragePlanForm;
