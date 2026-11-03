import {html, render} from "lit-html/lit-html.js";
import {styleMap} from "lit-html/directives/style-map.js";

const original = document.documentElement.dataset.original === "true";
const violations = [];
const attributeWrites = [];
document.addEventListener("securitypolicyviolation", (event) => {
  violations.push(event.effectiveDirective);
});
const setAttribute = Element.prototype.setAttribute;
Element.prototype.setAttribute = function (name, value) {
  if (name === "style") attributeWrites.push(this.id);
  return setAttribute.call(this, name, value);
};
const settle = () =>
  new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
const nextViolation = () =>
  new Promise((resolve) => {
    document.addEventListener("securitypolicyviolation", resolve, {once: true});
  });

const hostile = document.createElement("div");
hostile.id = "hostile";
document.body.append(hostile);
const blocked = nextViolation();
hostile.setAttribute("style", "color: rgb(11, 22, 33); width: 41px;");
await blocked;

const host = document.createElement("section");
document.body.append(host);
const template = (styles) => html`<div id="styled" style=${styleMap(styles)}></div>`;
const firstViolation = original ? nextViolation() : settle();
render(
  template({
    color: "rgb(11, 22, 33)",
    width: "41px",
    marginTop: "5px",
    "--_floating-content-translate": "14px -25px",
    "background-color": "rgb(40, 50, 60) !important",
  }),
  host,
);
await firstViolation;
const element = host.querySelector("div");
const snapshot = () => ({
  color: getComputedStyle(element).color,
  width: getComputedStyle(element).width,
  marginTop: getComputedStyle(element).marginTop,
  custom: element.style.getPropertyValue("--_floating-content-translate"),
  background: getComputedStyle(element).backgroundColor,
  priority: element.style.getPropertyPriority("background-color"),
});
const initial = snapshot();
render(
  template({
    color: "rgb(44, 55, 66)",
    width: "42px",
    marginTop: null,
    "--_floating-content-translate": "15px -26px",
  }),
  host,
);
await settle();
const updated = snapshot();
render(template({}), host);
await settle();
globalThis.cspResult = {
  initial,
  updated,
  removed: snapshot(),
  emptyStyle: element.style.length === 0,
  hostileColor: getComputedStyle(hostile).color,
  violations,
  attributeWrites,
};
