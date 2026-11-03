import {execFileSync} from "node:child_process";
import {fileURLToPath} from "node:url";
import {test, expect} from "@playwright/test";

const source = fileURLToPath(new URL("../../tests/browser/authz.py", import.meta.url));
const script = execFileSync(
  "python3",
  [
    "-c",
    `
import ast, pathlib, sys
tree = ast.parse(pathlib.Path(sys.argv[1]).read_text())
function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "search_roots")
call = next(node for node in ast.walk(function) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "execute_script")
print(ast.literal_eval(call.args[0]))
`,
    source,
  ],
  {encoding: "utf8"},
);

test("authorization discovery traverses fresh open shadow roots breadth first", async ({page}) => {
  await page.setContent('<main id="a"></main><main id="b"></main><main id="closed"></main>');
  await page.evaluate(() => {
    for (let index = 0; index < 300; index++) document.body.append(document.createElement("div"));
    const a = document.querySelector("#a").attachShadow({mode: "open"});
    a.innerHTML = '<section id="nested"></section><input hidden>';
    a.querySelector("section").attachShadow({mode: "open"}).innerHTML = "<input>";
    document.querySelector("#b").attachShadow({mode: "open"}).innerHTML = "<button>Submit</button>";
    document.querySelector("#closed").attachShadow({mode: "closed"}).innerHTML = "<input>";
  });
  const discover = () =>
    page.evaluate((code) => new Function(code)().map((root) => root.host.id), script);
  expect(await discover()).toEqual(["a", "b", "nested"]);
  await page.evaluate(() => {
    document.querySelector("#a").remove();
    const replacement = document.createElement("section");
    replacement.id = "replacement";
    document.body.append(replacement);
    replacement.attachShadow({mode: "open"}).innerHTML = "<input>";
  });
  expect(await discover()).toEqual(["b", "replacement"]);
});
