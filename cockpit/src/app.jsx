import React, {useEffect, useState} from "react";
import {
  Alert,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Flex,
  Form,
  FormGroup,
  Nav,
  NavItem,
  NavList,
  Page,
  PageSection,
  Spinner,
  Stack,
  StackItem,
  TextInput,
  Title,
} from "@patternfly/react-core";
import {activateSecrets} from "./api.js";
import {useOverview} from "./hooks/use-overview.js";
import {useMutation} from "./hooks/use-mutation.js";
import {OverviewPage} from "./pages/overview-page.jsx";
import {ServicesPage} from "./pages/services-page.jsx";
import {ApplicationsPage} from "./pages/applications-page.jsx";
import {OperationsPage} from "./pages/operations-page.jsx";
import {AiPage} from "./pages/ai-page.jsx";
import {SourcePage} from "./pages/source-page.jsx";
import {SetupPage} from "./pages/setup-page.jsx";

const PAGES = [
  ["overview", "Overview", OverviewPage],
  ["services", "Managed services", ServicesPage],
  ["applications", "Applications", ApplicationsPage],
  ["operations", "Operations", OperationsPage],
  ["ai", "AI configuration", AiPage],
  ["source", "Source & updates", SourcePage],
  ["setup", "First start", SetupPage],
];

function pageFromHash(hash) {
  const id = String(hash || "").replace(/^#\/?/, "");
  return PAGES.some(([known]) => known === id) ? id : "overview";
}

export default function App() {
  const {data, loading, error, refresh} = useOverview();
  const [page, setPage] = useState(() => pageFromHash(window.location.hash));
  const [unlockPassword, setUnlockPassword] = useState("");
  const {busy, error: mutationError, notice, setError, setNotice, mutate} = useMutation(refresh);

  useEffect(() => {
    const syncFromHash = () => setPage(pageFromHash(window.location.hash));
    window.addEventListener("hashchange", syncFromHash);
    return () => window.removeEventListener("hashchange", syncFromHash);
  }, []);

  const unlock = async () => {
    try {
      await mutate(() => activateSecrets(unlockPassword));
      setUnlockPassword("");
      setNotice("Runtime secrets activated.");
    } catch (_reason) {
      // The mutation hook already surfaced the failure message.
    }
  };

  const active = PAGES.find(([id]) => id === page) || PAGES[0];
  const ActivePage = active[2];

  return (
    <Page className="nas-page">
      <PageSection>
        <Flex justifyContent={{default: "justifyContentSpaceBetween"}} alignItems={{default: "alignItemsCenter"}}>
          <div>
          <Title headingLevel="h1">NixOS NAS</Title>
          <span className="nas-muted">Managed Services V2</span>
          </div>
          <Button variant="secondary" onClick={refresh} isDisabled={busy}>
            Refresh
          </Button>
        </Flex>
      </PageSection>
      <PageSection>
        <Nav variant="tertiary" aria-label="NAS sections">
          <NavList>
          {PAGES.map(([id, label]) => (
            <NavItem
              key={id}
              itemId={id}
              href={`#/${id}`}
              isActive={page === id}
              onClick={() => setPage(id)}
            >
              {label}
            </NavItem>
          ))}
          </NavList>
        </Nav>
      </PageSection>
      <PageSection>
        <Stack hasGutter>
          {error ? (
            <Alert variant="danger" isInline title="Unable to load appliance status">
              {error}
            </Alert>
          ) : null}
          {mutationError ? (
            <Alert variant="danger" isInline title="Operation failed">
              {mutationError}
            </Alert>
          ) : null}
          {notice ? <Alert variant="success" isInline title={notice} /> : null}
          {data && data.protectedReady === false ? (
            <Card>
              <CardHeader>
                <CardTitle>Protected services are locked</CardTitle>
              </CardHeader>
              <CardBody>
                <Form>
                  <FormGroup label="KeePassXC database password">
                    <TextInput
                      type="password"
                      value={unlockPassword}
                      onChange={(_e, value) => setUnlockPassword(value)}
                    />
                  </FormGroup>
                  <Button onClick={unlock} isDisabled={busy || !unlockPassword}>
                    Activate secrets
                  </Button>
                </Form>
              </CardBody>
            </Card>
          ) : null}
          <StackItem>
            {loading && !data ? (
              <Spinner size="xl" aria-label="Loading NAS state" />
            ) : (
              <ActivePage data={data} refresh={refresh} mutate={mutate} busy={busy} />
            )}
          </StackItem>
        </Stack>
      </PageSection>
    </Page>
  );
}
