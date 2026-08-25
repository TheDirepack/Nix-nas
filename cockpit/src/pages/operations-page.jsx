import React, {useEffect, useState} from "react";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Form,
  FormSelect,
  FormSelectOption,
  FormGroup,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  TextInput,
  Title,
} from "@patternfly/react-core";
import {api, apiInput} from "../api.js";
import {OutputBlock} from "../components/output-block.jsx";
import {pretty} from "../lib/format.js";
import {visibleOperations} from "../view-model.js";

export function OperationsPage({data, mutate, busy}) {
  const operations = visibleOperations(data || {});
  const confirmationRequired = new Set([
    "health",
    "snapshot",
    "zfs-scrub",
    "backup",
    "replicate",
    "update-sync",
    "update-apply",
    "protected-restart",
  ]);
  const [pending, setPending] = useState(null);
  const [lastResult, setLastResult] = useState(null);
  const remote = data?.backupRemote || {};
  const [remoteDraft, setRemoteDraft] = useState({
    provider: remote.provider || "local",
    scope: remote.scope || "config-only",
    rcloneRemote: remote.rcloneRemote || "",
  });
  useEffect(() => {
    setRemoteDraft({
      provider: remote.provider || "local",
      scope: remote.scope || "config-only",
      rcloneRemote: remote.rcloneRemote || "",
    });
  }, [remote.provider, remote.scope, remote.rcloneRemote]);
  const run = async (id) => {
    try {
      const result = await mutate(() => api(["action", id]));
      setPending(null);
      setLastResult(result);
    } catch (_reason) {
      // The shared mutation hook keeps the failed action visible and reports its error.
    }
  };
  const saveRemote = async () => {
    const result = await mutate(() => apiInput(["backup-remote-set"], remoteDraft));
    setLastResult(result);
  };
  return (
    <>
      <Title headingLevel="h2">Operations</Title>
      <div className="nas-actions nas-actions--wrap">
        {operations.map(([id, label]) => (
          <Button
            key={id}
            variant="secondary"
            onClick={() => (confirmationRequired.has(id) ? setPending({id, label}) : run(id))}
            isDisabled={busy}
          >
            {label}
          </Button>
        ))}
      </div>
      {pending ? (
        <Modal
          isOpen
          variant={ModalVariant.small}
          aria-label="Confirm maintenance action"
          onClose={() => setPending(null)}
        >
          <ModalHeader title="Confirm maintenance action" titleIconVariant="warning" />
          <ModalBody>
            <p>
              Run <strong>{pending.label}</strong>? This action can change appliance state.
            </p>
          </ModalBody>
          <ModalFooter>
            <Button variant="danger" onClick={() => run(pending.id)} isDisabled={busy}>
              Confirm
            </Button>
            <Button variant="link" onClick={() => setPending(null)} isDisabled={busy}>
              Cancel
            </Button>
          </ModalFooter>
        </Modal>
      ) : null}
      <Card>
        <CardHeader>
          <CardTitle>Backup — remote destination</CardTitle>
        </CardHeader>
        <CardBody>
          <p className="nas-muted">
            Remote backups use <code>restic + rclone</code>. Config-only includes boot system,
            Caddy, Authentik DB dump, Keepass database, Syncthing config and firewall/identity
            substrate — the minimum needed to restore the Authentik remote sign-in route. All also
            includes V2 app data emitted via <code>storageResources</code>.
          </p>
          <Form>
            <FormGroup label="Provider">
              <FormSelect
                aria-label="Backup provider"
                value={remoteDraft.provider}
                isDisabled={busy}
                onChange={(_event, value) => setRemoteDraft({...remoteDraft, provider: value})}
              >
                <FormSelectOption value="local" label="local (ZFS restic-system)" />
                <FormSelectOption value="gdrive" label="Google Drive (gdrive)" />
                <FormSelectOption value="icloud" label="iCloud (rclone)" />
                <FormSelectOption value="pcloud" label="pCloud (pcloud)" />
                <FormSelectOption value="s3" label="S3 (s3)" />
                <FormSelectOption value="b2" label="Backblaze B2 (b2)" />
                <FormSelectOption value="rclone" label="Custom rclone remote" />
              </FormSelect>
            </FormGroup>
            <FormGroup label="Scope">
              <FormSelect
                aria-label="Backup scope"
                value={remoteDraft.scope}
                isDisabled={busy}
                onChange={(_event, value) => setRemoteDraft({...remoteDraft, scope: value})}
              >
                <FormSelectOption
                  value="config-only"
                  label="config-only (Caddy + Authentik + Keepass + system)"
                />
                <FormSelectOption value="all" label="all (also app data)" />
              </FormSelect>
            </FormGroup>
            <FormGroup label="rclone remote (empty = auto from provider)">
              <TextInput
                value={remoteDraft.rcloneRemote}
                onChange={(_e, value) => setRemoteDraft({...remoteDraft, rcloneRemote: value})}
                placeholder="gdrive:nas-backup / s3:bucket/prefix"
                isDisabled={busy}
              />
            </FormGroup>
            <Button variant="secondary" onClick={saveRemote} isDisabled={busy}>
              Save remote (stub — wire to V2 authority when backend lands)
            </Button>
          </Form>
          <OutputBlock>{pretty(remote)}</OutputBlock>
        </CardBody>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Operation coordinator</CardTitle>
        </CardHeader>
        <CardBody>
          <OutputBlock>{pretty(data?.operations || {})}</OutputBlock>
        </CardBody>
      </Card>
      {lastResult ? (
        <Card>
          <CardBody>
            <OutputBlock>{pretty(lastResult)}</OutputBlock>
          </CardBody>
        </Card>
      ) : null}
    </>
  );
}
