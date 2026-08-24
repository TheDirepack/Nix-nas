// Test double for the "cockpit" host module, used only by systemd.test.mjs.
const makeClient = () =>
  globalThis.systemdTestClient ?? {
    call() {
      return Promise.resolve([[]]);
    },
    close() {},
  };

export default {
  dbus() {
    return makeClient();
  },
};
