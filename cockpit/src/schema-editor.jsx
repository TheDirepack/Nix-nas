import React, {useMemo, useState} from "react";
import {
  Button,
  Checkbox,
  FormSelect,
  FormSelectOption,
  Label,
  TextArea,
  TextInput,
} from "@patternfly/react-core";
import {
  defaultValue,
  migrateVariantValue,
  propertyNamePattern,
  resolveSchema,
  schemaType,
  selectedSchema,
  selectVariantIndex,
  variantOptions,
} from "./schema-model.js";

function hasOwn(value, key) {
  return value !== null && typeof value === "object" && Object.hasOwn(value, key);
}

function titleFor(schema, fallback) {
  return typeof schema.title === "string" && schema.title ? schema.title : fallback;
}

function description(schema) {
  return typeof schema.description === "string" && schema.description ? (
    <div className="nas-schema-description">{schema.description}</div>
  ) : null;
}

function replaceObjectKey(value, oldKey, newKey) {
  const result = {};
  for (const [key, entry] of Object.entries(value || {})) {
    result[key === oldKey ? newKey : key] = entry;
  }
  return result;
}

function ScalarEditor({root, schema, value, onChange, id}) {
  const resolved = resolveSchema(root, schema);
  if (Object.hasOwn(resolved, "const")) return <code>{String(resolved.const)}</code>;
  if (Array.isArray(resolved.enum)) {
    return (
      <FormSelect
        id={id}
        value={value ?? ""}
        onChange={(event) => {
          const option = resolved.enum.find((entry) => String(entry) === event.target.value);
          onChange(option);
        }}
      >
        {resolved.enum.map((entry) => (
          <FormSelectOption key={String(entry)} value={String(entry)} label={String(entry)} />
        ))}
      </FormSelect>
    );
  }

  const type = schemaType(root, resolved);
  if (type === "boolean") {
    return (
      <Checkbox
        id={id}
        isChecked={value === true}
        onChange={(_event, checked) => onChange(checked)}
      />
    );
  }
  if (type === "integer" || type === "number") {
    return (
      <TextInput
        id={id}
        type="number"
        value={value ?? ""}
        min={resolved.minimum}
        max={resolved.maximum}
        step={type === "integer" ? 1 : "any"}
        onChange={(_event, next) => {
          if (next === "") return onChange(undefined);
          const parsed =
            type === "integer"
              ? Number.parseInt(next, 10)
              : Number(next);
          onChange(Number.isFinite(parsed) ? parsed : value);
        }}
      />
    );
  }
  const text = typeof value === "string" ? value : "";
  if ((resolved.maxLength || 0) > 256 || resolved.format === "textarea") {
    return <TextArea id={id} value={text} onChange={(_event, next) => onChange(next)} rows={4} />;
  }
  return (
    <TextInput
      id={id}
      value={text}
      onChange={(_event, next) => onChange(next)}
      type="text"
      pattern={resolved.pattern}
    />
  );
}

function ArrayEditor({root, schema, value, onChange, path}) {
  const resolved = resolveSchema(root, schema);
  const items = Array.isArray(value) ? value : [];
  const itemSchema = resolved.items || {};
  return (
    <div className="nas-schema-list">
      {items.map((entry, index) => (
        <div className="nas-schema-list-item" key={`${path}-${index}`}>
          <SchemaNode
            root={root}
            schema={itemSchema}
            value={entry}
            onChange={(next) => {
              const copy = [...items];
              copy[index] = next;
              onChange(copy);
            }}
            path={`${path}.${index}`}
            label={`Item ${index + 1}`}
            required
          />
          <Button
            variant="danger"
            size="sm"
            onClick={() => onChange(items.filter((_item, itemIndex) => itemIndex !== index))}
          >
            Remove item
          </Button>
        </div>
      ))}
      <Button
        variant="secondary"
        size="sm"
        onClick={() => onChange([...items, defaultValue(root, itemSchema)])}
      >
        Add item
      </Button>
    </div>
  );
}

function ObjectEditor({root, schema, value, onChange, path}) {
  const resolved = resolveSchema(root, schema);
  const object = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const properties = resolved.properties || {};
  const required = new Set(resolved.required || []);
  const knownNames = new Set(Object.keys(properties));
  const dynamicSchema =
    resolved.additionalProperties && typeof resolved.additionalProperties === "object"
      ? resolved.additionalProperties
      : null;
  const dynamicEntries = Object.entries(object).filter(([name]) => !knownNames.has(name));
  const absentOptional = Object.keys(properties).filter(
    (name) => !required.has(name) && !hasOwn(object, name),
  );
  const [fieldToAdd, setFieldToAdd] = useState("");
  const [newKey, setNewKey] = useState("");
  const [keyError, setKeyError] = useState("");
  const namePattern = propertyNamePattern(root, resolved);

  const setProperty = (name, next) => {
    const copy = {...object};
    if (next === undefined) delete copy[name];
    else copy[name] = next;
    onChange(copy);
  };

  const addDynamic = () => {
    const key = newKey.trim();
    if (!key) return setKeyError("Enter a key.");
    if (hasOwn(object, key)) return setKeyError("That key already exists.");
    if (namePattern && !new RegExp(namePattern).test(key)) {
      return setKeyError(`Key must match ${namePattern}.`);
    }
    setProperty(key, defaultValue(root, dynamicSchema));
    setNewKey("");
    setKeyError("");
  };

  return (
    <div className="nas-schema-object">
      {Object.entries(properties).map(([name, childSchema]) => {
        const present = hasOwn(object, name);
        if (!present && !required.has(name)) return null;
        return (
          <div className="nas-schema-property" key={`${path}.${name}`}>
            <SchemaNode
              root={root}
              schema={childSchema}
              value={present ? object[name] : defaultValue(root, childSchema)}
              onChange={(next) => setProperty(name, next)}
              path={`${path}.${name}`}
              label={name}
              required={required.has(name)}
            />
            {!required.has(name) ? (
              <Button variant="link" size="sm" onClick={() => setProperty(name, undefined)}>
                Remove field
              </Button>
            ) : null}
          </div>
        );
      })}

      {absentOptional.length ? (
        <div className="nas-schema-add-row">
          <FormSelect value={fieldToAdd} onChange={(event) => setFieldToAdd(event.target.value)}>
            <FormSelectOption value="" label="Add optional field…" />
            {absentOptional.map((name) => (
              <FormSelectOption
                key={name}
                value={name}
                label={titleFor(resolveSchema(root, properties[name]), name)}
              />
            ))}
          </FormSelect>
          <Button
            variant="secondary"
            size="sm"
            isDisabled={!fieldToAdd}
            onClick={() => {
              if (!fieldToAdd) return;
              setProperty(fieldToAdd, defaultValue(root, properties[fieldToAdd]));
              setFieldToAdd("");
            }}
          >
            Add field
          </Button>
        </div>
      ) : null}

      {dynamicEntries.map(([name, entry]) => (
        <div className="nas-schema-map-entry" key={`${path}.${name}`}>
          <div className="nas-schema-map-key">
            <TextInput
              value={name}
              aria-label={`Key for ${name}`}
              onChange={(_event, next) => {
                if (
                  !next ||
                  hasOwn(object, next) ||
                  (namePattern && !new RegExp(namePattern).test(next))
                ) {
                  return;
                }
                onChange(replaceObjectKey(object, name, next));
              }}
            />
            <Button variant="danger" size="sm" onClick={() => setProperty(name, undefined)}>
              Remove
            </Button>
          </div>
          <SchemaNode
            root={root}
            schema={dynamicSchema}
            value={entry}
            onChange={(next) => setProperty(name, next)}
            path={`${path}.${name}`}
            label={name}
            required
          />
        </div>
      ))}

      {dynamicSchema ? (
        <div className="nas-schema-add-row">
          <TextInput
            value={newKey}
            aria-label={`New key at ${path}`}
            placeholder="New key"
            onChange={(_event, next) => {
              setNewKey(next);
              setKeyError("");
            }}
          />
          <Button variant="secondary" size="sm" onClick={addDynamic}>
            Add entry
          </Button>
          {keyError ? <span className="nas-schema-error">{keyError}</span> : null}
        </div>
      ) : null}
    </div>
  );
}

function SchemaNode({root, schema, value, onChange, path, label, required = false}) {
  const resolved = resolveSchema(root, schema);
  const options = variantOptions(root, resolved);
  const selected = options.length ? selectVariantIndex(root, resolved, value) : -1;
  const active = options.length ? selectedSchema(root, resolved, value, selected) : resolved;
  const type = schemaType(root, active);
  const id = `nas-schema-${path.replaceAll(/[^A-Za-z0-9_-]/g, "-")}`;

  return (
    <fieldset className={`nas-schema-node nas-schema-node--${type}`}>
      <legend>
        {titleFor(active, label)} {required ? <Label isCompact>required</Label> : null}
      </legend>
      {description(active)}
      {options.length ? (
        <label className="nas-schema-variant" htmlFor={`${id}-variant`}>
          <span>Shape</span>
          <FormSelect
            id={`${id}-variant`}
            value={selected}
            onChange={(event) => {
              const index = Number.parseInt(event.target.value, 10);
              onChange(migrateVariantValue(root, resolved, value, index));
            }}
          >
            {options.map((option) => (
              <FormSelectOption key={option.index} value={option.index} label={option.label} />
            ))}
          </FormSelect>
        </label>
      ) : null}
      {type === "object" ? (
        <ObjectEditor root={root} schema={active} value={value} onChange={onChange} path={path} />
      ) : type === "array" ? (
        <ArrayEditor root={root} schema={active} value={value} onChange={onChange} path={path} />
      ) : (
        <ScalarEditor root={root} schema={active} value={value} onChange={onChange} id={id} />
      )}
    </fieldset>
  );
}

export function SchemaEditor({schema, value, onChange}) {
  const root = useMemo(() => schema || {}, [schema]);
  if (!schema || typeof schema !== "object") {
    return <div>Managed Services V2 schema is unavailable.</div>;
  }
  return (
    <div className="nas-schema-editor">
      <SchemaNode
        root={root}
        schema={root}
        value={value}
        onChange={onChange}
        path="root"
        label="Desired state"
        required
      />
    </div>
  );
}
