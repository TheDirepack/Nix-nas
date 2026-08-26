import React, {useState} from "react";
import {
  Alert,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Gallery,
  GalleryItem,
  TextArea,
} from "@patternfly/react-core";
import {
  managedServicesDocument,
  replaceManagedServicesDocument,
  replaceManagedServicesJsonDocument,
  setManagedServiceMode,
} from "../api.js";
import {SchemaEditor} from "../schema-editor.jsx";
import {ServiceCard} from "../components/service-card.jsx";
import {SectionHeader} from "../components/section-header.jsx";
import {message} from "../lib/format.js";
import {managedServiceOperationsBusy, managedServiceRows} from "../view-model.js";

export function ServicesPage({data, mutate, busy}) {
  const services = managedServiceRows(data || {});
  const serviceBusy = managedServiceOperationsBusy(data || {}) || busy;
  const [document, setDocument] = useState(null);
  const [formValue, setFormValue] = useState(null);
  const [yaml, setYaml] = useState("");
  const [editorMode, setEditorMode] = useState("form");
  const [editorError, setEditorError] = useState("");
  const [saving, setSaving] = useState(false);

  const loadDocument = async () => {
    try {
      const value = await managedServicesDocument();
      setDocument(value);
      setFormValue(value.document || null);
      setYaml(value.yaml || "");
      setEditorMode("form");
      setEditorError("");
    } catch (reason) {
      setEditorError(message(reason));
    }
  };

  const saveFormDocument = async () => {
    setSaving(true);
    try {
      await mutate(() => replaceManagedServicesJsonDocument(formValue));
      setEditorError("");
      await loadDocument();
    } catch (reason) {
      setEditorError(message(reason));
    } finally {
      setSaving(false);
    }
  };

  const saveYamlDocument = async () => {
    setSaving(true);
    try {
      await mutate(() => replaceManagedServicesDocument(yaml));
      setEditorError("");
      await loadDocument();
    } catch (reason) {
      setEditorError(message(reason));
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <SectionHeader
        title="Managed Services V2"
        hint="/var/lib/nas-control/services.yaml is the sole mutable lifecycle authority."
        actionLabel="Edit services"
        onAction={loadDocument}
      />
      <Gallery hasGutter>
        {services.map((service) => (
          <GalleryItem key={service.id}>
            <ServiceCard
              service={service}
              disabled={serviceBusy}
              onMode={(serviceId, mode) => mutate(() => setManagedServiceMode(serviceId, mode))}
            />
          </GalleryItem>
        ))}
      </Gallery>
      {document ? (
        <Card className="nas-editor-card">
          <CardHeader>
            <CardTitle>Schema-driven desired state</CardTitle>
          </CardHeader>
          <CardBody>
            <p className="nas-muted">
              The form below is generated from the same JSON Schema used by the V2 compiler. Raw
              YAML remains available for advanced edits.
            </p>
            {editorError ? <Alert variant="danger" isInline title={editorError} /> : null}
            <div className="nas-actions">
              <Button
                variant={editorMode === "form" ? "primary" : "secondary"}
                onClick={() => setEditorMode("form")}
              >
                Schema form
              </Button>
              <Button
                variant={editorMode === "yaml" ? "primary" : "secondary"}
                onClick={() => setEditorMode("yaml")}
              >
                Advanced YAML
              </Button>
            </div>
            {editorMode === "form" && formValue ? (
              <SchemaEditor schema={document.schema} value={formValue} onChange={setFormValue} />
            ) : (
              <TextArea
                value={yaml}
                onChange={(_event, value) => setYaml(value)}
                rows={24}
                resizeOrientation="vertical"
              />
            )}
            <div className="nas-actions">
              <Button
                onClick={editorMode === "form" ? saveFormDocument : saveYamlDocument}
                isLoading={saving}
                isDisabled={saving || (editorMode === "form" && !formValue)}
              >
                Validate, save, and reconcile
              </Button>
              <Button variant="link" onClick={() => setDocument(null)}>
                Close
              </Button>
            </div>
          </CardBody>
        </Card>
      ) : null}
    </>
  );
}
