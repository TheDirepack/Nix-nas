function clone(value) {
  if (value === undefined) return undefined;
  return JSON.parse(JSON.stringify(value));
}

function mergeSchemas(left, right) {
  const merged = {...left, ...right};
  if (left.properties || right.properties) {
    merged.properties = {...(left.properties || {}), ...(right.properties || {})};
  }
  if (left.required || right.required) {
    merged.required = [...new Set([...(left.required || []), ...(right.required || [])])];
  }
  return merged;
}

export function resolveSchema(root, schema, seen = new Set()) {
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) return {};
  let resolved = {...schema};
  const reference = resolved.$ref;
  if (typeof reference === "string") {
    if (!reference.startsWith("#/") || seen.has(reference)) return resolved;
    const target = reference
      .slice(2)
      .split("/")
      .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"))
      .reduce(
        (value, part) => (value && typeof value === "object" ? value[part] : undefined),
        root,
      );
    if (target && typeof target === "object") {
      const nextSeen = new Set(seen);
      nextSeen.add(reference);
      const siblings = {...resolved};
      delete siblings.$ref;
      resolved = mergeSchemas(resolveSchema(root, target, nextSeen), siblings);
    }
  }
  if (Array.isArray(resolved.allOf)) {
    const allOf = resolved.allOf;
    delete resolved.allOf;
    for (const branch of allOf) resolved = mergeSchemas(resolved, resolveSchema(root, branch, seen));
  }
  return resolved;
}

export function schemaType(root, schema) {
  const resolved = resolveSchema(root, schema);
  if (typeof resolved.type === "string") return resolved.type;
  if (Object.hasOwn(resolved, "const")) {
    if (Array.isArray(resolved.const)) return "array";
    if (resolved.const === null) return "null";
    return typeof resolved.const === "number" && Number.isInteger(resolved.const)
      ? "integer"
      : typeof resolved.const;
  }
  if (Array.isArray(resolved.enum) && resolved.enum.length) {
    const first = resolved.enum[0];
    if (Array.isArray(first)) return "array";
    if (first === null) return "null";
    return typeof first === "number" && Number.isInteger(first) ? "integer" : typeof first;
  }
  if (resolved.properties || resolved.additionalProperties) return "object";
  if (resolved.items) return "array";
  return "string";
}

function typeMatches(type, value) {
  if (type === "object") {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }
  if (type === "array") return Array.isArray(value);
  if (type === "integer") return Number.isInteger(value);
  if (type === "number") return typeof value === "number" && Number.isFinite(value);
  if (type === "null") return value === null;
  return typeof value === type;
}

function branchScore(root, branch, value) {
  const schema = resolveSchema(root, branch);
  let score = 0;
  const type = schemaType(root, schema);
  if (typeMatches(type, value)) score += 2;
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const [name, property] of Object.entries(schema.properties || {})) {
      const resolved = resolveSchema(root, property);
      if (Object.hasOwn(resolved, "const")) {
        score += value[name] === resolved.const ? 20 : -20;
      } else if (Object.hasOwn(value, name)) {
        score += 1;
      }
    }
    for (const name of schema.required || []) score += Object.hasOwn(value, name) ? 3 : -3;
  }
  if (Object.hasOwn(schema, "const")) score += value === schema.const ? 20 : -20;
  return score;
}

export function selectVariantIndex(root, schema, value) {
  const resolved = resolveSchema(root, schema);
  if (!Array.isArray(resolved.oneOf) || resolved.oneOf.length === 0) return -1;
  let best = 0;
  let bestScore = Number.NEGATIVE_INFINITY;
  resolved.oneOf.forEach((branch, index) => {
    const score = branchScore(root, branch, value);
    if (score > bestScore) {
      best = index;
      bestScore = score;
    }
  });
  return best;
}

export function selectedSchema(root, schema, value, variantIndex = null) {
  const resolved = resolveSchema(root, schema);
  if (!Array.isArray(resolved.oneOf) || resolved.oneOf.length === 0) return resolved;
  const base = {...resolved};
  delete base.oneOf;
  const index = variantIndex ?? selectVariantIndex(root, resolved, value);
  const branch = resolveSchema(root, resolved.oneOf[Math.max(0, index)]);
  return mergeSchemas(base, branch);
}

function discriminatorLabel(root, branch, index) {
  const schema = resolveSchema(root, branch);
  if (typeof schema.title === "string" && schema.title) return schema.title;
  if (Object.hasOwn(schema, "const")) return String(schema.const);
  for (const [name, property] of Object.entries(schema.properties || {})) {
    const resolved = resolveSchema(root, property);
    if (Object.hasOwn(resolved, "const")) return `${name}: ${resolved.const}`;
    if (Array.isArray(resolved.enum) && resolved.enum.length === 1) {
      return `${name}: ${resolved.enum[0]}`;
    }
  }
  const required = schema.required || [];
  if (required.length) return `requires ${required.join(", ")}`;
  return `Option ${index + 1}`;
}

export function variantOptions(root, schema) {
  const resolved = resolveSchema(root, schema);
  if (!Array.isArray(resolved.oneOf)) return [];
  return resolved.oneOf.map((branch, index) => ({
    index,
    label: discriminatorLabel(root, branch, index),
  }));
}

export function defaultValue(root, schema) {
  const resolved = resolveSchema(root, schema);
  if (Object.hasOwn(resolved, "default")) return clone(resolved.default);
  if (Object.hasOwn(resolved, "const")) return clone(resolved.const);
  if (Array.isArray(resolved.enum) && resolved.enum.length) return clone(resolved.enum[0]);
  if (Array.isArray(resolved.oneOf) && resolved.oneOf.length) {
    return defaultValue(root, selectedSchema(root, resolved, undefined, 0));
  }
  const type = schemaType(root, resolved);
  if (type === "object") {
    const value = {};
    const required = new Set(resolved.required || []);
    for (const [name, property] of Object.entries(resolved.properties || {})) {
      const child = resolveSchema(root, property);
      if (
        required.has(name) ||
        Object.hasOwn(child, "default") ||
        Object.hasOwn(child, "const")
      ) {
        value[name] = defaultValue(root, child);
      }
    }
    return value;
  }
  if (type === "array") return [];
  if (type === "boolean") return false;
  if (type === "integer" || type === "number") return resolved.minimum ?? 0;
  if (type === "null") return null;
  return "";
}

export function propertySchema(root, schema, name) {
  const resolved = selectedSchema(root, schema, undefined);
  if (resolved.properties && Object.hasOwn(resolved.properties, name)) {
    return resolved.properties[name];
  }
  if (resolved.additionalProperties && typeof resolved.additionalProperties === "object") {
    return resolved.additionalProperties;
  }
  return {};
}

export function propertyNamePattern(root, schema) {
  const resolved = resolveSchema(root, schema);
  const pattern = resolved.propertyNames?.pattern;
  return typeof pattern === "string" ? pattern : null;
}
