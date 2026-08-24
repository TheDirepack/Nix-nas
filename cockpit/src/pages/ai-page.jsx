import React, {useState} from "react";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Checkbox,
  Form,
  FormGroup,
  FormSelect,
  FormSelectOption,
  Gallery,
  GalleryItem,
  TextArea,
  TextInput,
  Title,
} from "@patternfly/react-core";
import {apiInput} from "../api.js";
import {OutputBlock} from "../components/output-block.jsx";
import {pretty} from "../lib/format.js";

export function AiPage({data, mutate, busy}) {
  const config = data?.aiConfig && typeof data.aiConfig === "object" ? data.aiConfig : {};
  const [provider, setProvider] = useState({
    id: "",
    url: "",
    models: "",
    apiKey: "",
    keepassPassword: "",
  });
  const [providerDelete, setProviderDelete] = useState({id: "", keepassPassword: ""});
  const [local, setLocal] = useState({
    id: "",
    path: "",
    context: "4096",
    ttl: "-1",
    tools: false,
    extraArgs: "",
  });
  const [role, setRole] = useState({
    role: "default",
    targets: "",
    strategy: "fallback",
    spillover: "1",
  });
  const [advanced, setAdvanced] = useState("{}");
  const [result, setResult] = useState(null);

  const submit = async (call) => setResult(await mutate(call));
  return (
    <>
      <Title headingLevel="h2">AI configuration</Title>
      <Gallery hasGutter>
        <GalleryItem>
          <Card>
            <CardHeader>
              <CardTitle>Current llama-swap configuration</CardTitle>
            </CardHeader>
            <CardBody>
              <OutputBlock>{pretty(config)}</OutputBlock>
            </CardBody>
          </Card>
        </GalleryItem>
        <GalleryItem>
          <Card>
            <CardHeader>
              <CardTitle>Set remote provider</CardTitle>
            </CardHeader>
            <CardBody>
              <Form>
                <FormGroup label="Provider ID">
                  <TextInput
                    value={provider.id}
                    onChange={(_e, value) => setProvider({...provider, id: value})}
                  />
                </FormGroup>
                <FormGroup label="OpenAI-compatible URL">
                  <TextInput
                    value={provider.url}
                    onChange={(_e, value) => setProvider({...provider, url: value})}
                  />
                </FormGroup>
                <FormGroup label="Models (comma-separated)">
                  <TextInput
                    value={provider.models}
                    onChange={(_e, value) => setProvider({...provider, models: value})}
                  />
                </FormGroup>
                <FormGroup label="API key">
                  <TextInput
                    type="password"
                    value={provider.apiKey}
                    onChange={(_e, value) => setProvider({...provider, apiKey: value})}
                  />
                </FormGroup>
                <FormGroup label="KeePassXC password">
                  <TextInput
                    type="password"
                    value={provider.keepassPassword}
                    onChange={(_e, value) => setProvider({...provider, keepassPassword: value})}
                  />
                </FormGroup>
                <Button
                  isDisabled={busy}
                  onClick={() =>
                    submit(() =>
                      apiInput(["ai-provider-set"], {
                        ...provider,
                        models: provider.models
                          .split(",")
                          .map((v) => v.trim())
                          .filter(Boolean),
                      }),
                    )
                  }
                >
                  Save provider
                </Button>
              </Form>
            </CardBody>
          </Card>
        </GalleryItem>
        <GalleryItem>
          <Card>
            <CardHeader>
              <CardTitle>Delete remote provider</CardTitle>
            </CardHeader>
            <CardBody>
              <Form>
                <FormGroup label="Provider ID">
                  <TextInput
                    value={providerDelete.id}
                    onChange={(_e, value) => setProviderDelete({...providerDelete, id: value})}
                  />
                </FormGroup>
                <FormGroup label="KeePassXC password">
                  <TextInput
                    type="password"
                    value={providerDelete.keepassPassword}
                    onChange={(_e, value) =>
                      setProviderDelete({...providerDelete, keepassPassword: value})
                    }
                  />
                </FormGroup>
                <Button
                  variant="danger"
                  isDisabled={busy}
                  onClick={() => submit(() => apiInput(["ai-provider-delete"], providerDelete))}
                >
                  Delete provider
                </Button>
              </Form>
            </CardBody>
          </Card>
        </GalleryItem>
        <GalleryItem>
          <Card>
            <CardHeader>
              <CardTitle>Local model</CardTitle>
            </CardHeader>
            <CardBody>
              <Form>
                <FormGroup label="Model ID">
                  <TextInput
                    value={local.id}
                    onChange={(_e, value) => setLocal({...local, id: value})}
                  />
                </FormGroup>
                <FormGroup label="GGUF path">
                  <TextInput
                    value={local.path}
                    onChange={(_e, value) => setLocal({...local, path: value})}
                  />
                </FormGroup>
                <FormGroup label="Context">
                  <TextInput
                    value={local.context}
                    onChange={(_e, value) => setLocal({...local, context: value})}
                  />
                </FormGroup>
                <FormGroup label="TTL">
                  <TextInput
                    value={local.ttl}
                    onChange={(_e, value) => setLocal({...local, ttl: value})}
                  />
                </FormGroup>
                <FormGroup label="Extra args (one per line)">
                  <TextArea
                    rows={4}
                    value={local.extraArgs}
                    onChange={(_e, value) => setLocal({...local, extraArgs: value})}
                  />
                </FormGroup>
                <Checkbox
                  id="ai-local-model-tools"
                  label="Tool-capable model"
                  isChecked={local.tools}
                  onChange={(_event, checked) => setLocal({...local, tools: checked})}
                />
                <div className="nas-actions">
                  <Button
                    isDisabled={busy}
                    onClick={() =>
                      submit(() =>
                        apiInput(["ai-local-model-set"], {
                          id: local.id,
                          path: local.path,
                          context: Number(local.context),
                          ttl: Number(local.ttl),
                          tools: local.tools,
                          extraArgs: local.extraArgs
                            .split("\n")
                            .map((v) => v.trim())
                            .filter(Boolean),
                        }),
                      )
                    }
                  >
                    Save local model
                  </Button>
                  <Button
                    variant="danger"
                    isDisabled={busy}
                    onClick={() =>
                      submit(() => apiInput(["ai-local-model-delete"], {id: local.id}))
                    }
                  >
                    Delete local model
                  </Button>
                </div>
              </Form>
            </CardBody>
          </Card>
        </GalleryItem>
        <GalleryItem>
          <Card>
            <CardHeader>
              <CardTitle>Model role</CardTitle>
            </CardHeader>
            <CardBody>
              <Form>
                <FormGroup label="Role">
                  <TextInput
                    value={role.role}
                    onChange={(_e, value) => setRole({...role, role: value})}
                  />
                </FormGroup>
                <FormGroup label="Targets (comma-separated)">
                  <TextInput
                    value={role.targets}
                    onChange={(_e, value) => setRole({...role, targets: value})}
                  />
                </FormGroup>
                <FormGroup label="Strategy">
                  <FormSelect
                    aria-label="Role strategy"
                    value={role.strategy}
                    onChange={(_event, value) => setRole({...role, strategy: value})}
                  >
                    <FormSelectOption value="fallback" label="fallback" />
                    <FormSelectOption value="round-robin" label="round-robin" />
                    <FormSelectOption value="least-busy" label="least-busy" />
                  </FormSelect>
                </FormGroup>
                <FormGroup label="Spillover">
                  <TextInput
                    value={role.spillover}
                    onChange={(_e, value) => setRole({...role, spillover: value})}
                  />
                </FormGroup>
                <Button
                  isDisabled={busy}
                  onClick={() =>
                    submit(() =>
                      apiInput(["ai-role-set"], {
                        role: role.role,
                        targets: role.targets
                          .split(",")
                          .map((v) => v.trim())
                          .filter(Boolean),
                        strategy: role.strategy,
                        spillover: Number(role.spillover),
                      }),
                    )
                  }
                >
                  Save role
                </Button>
              </Form>
            </CardBody>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Advanced AI settings</CardTitle>
            </CardHeader>
            <CardBody>
              <p>Submit only supported llama-swap advanced keys.</p>
              <TextArea rows={10} value={advanced} onChange={(_e, value) => setAdvanced(value)} />
              <Button
                isDisabled={busy}
                onClick={() => submit(() => apiInput(["ai-advanced-set"], JSON.parse(advanced)))}
              >
                Apply advanced settings
              </Button>
            </CardBody>
          </Card>
        </GalleryItem>
      </Gallery>
      {result ? (
        <Card>
          <CardHeader>
            <CardTitle>Last AI mutation</CardTitle>
          </CardHeader>
          <CardBody>
            <OutputBlock>{pretty(result)}</OutputBlock>
          </CardBody>
        </Card>
      ) : null}
    </>
  );
}
