/**
 * first-run-wizard API functions
 * Collects wizard form data and writes configuration.
 * Authentik API calls are stubbed for future implementation;
 * the collected values are written to temp Nix config that nas_setup.py applies.
 */

const fs = require('fs');
const path = require('path');

// Resolve schema.json path relative to this file
const schemaPath = path.resolve(__dirname, 'forms', 'schema.json');
const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));

// Export the form defaults from schema
const formDefaults = {
  adminUsername: schema.properties.adminUsername.default || 'admin',
  adminEmail: schema.properties.adminEmail.default || 'admin@example.com',
  adminPassword: schema.properties.adminPassword.default || '',
  useSamePassword: schema.properties.useSamePassword.default !== undefined ? schema.properties.useSamePassword.default : true,
  keePassMasterPassword: schema.properties.keePassMasterPassword.default || '',
  keePassMasterPasswordConfirm: schema.properties.keePassMasterPasswordConfirm.default || '',
  authentikExternalUrl: schema.properties.authentikExternalUrl.default || 'https://',
  createOutpost: schema.properties.createOutpost.default !== undefined ? schema.properties.createOutpost.default : true,
  createProviderApp: schema.properties.createProviderApp.default !== undefined ? schema.properties.createProviderApp.default : true,
  zfsPoolName: schema.properties.zfsPoolName.default || 'tank',
  zfsPoolDevices: schema.properties.zfsPoolDevices.default || '/dev/sdb /dev/sdc'
};

// Write temp NixOS config for the admin user.
// This file is applied by nas_setup.py via nixos-rebuild switch before reboot.
const writeTempNixConfig = () => {
  const config =`
{ config, pkgs, ... }:

{
  imports = [
    ./hardware-configuration.nix
  ];

  users.users.admin = {
    isNormalUser = false;
    description = "NAS Administrator";
    extraGroups = [ "wheel" ];
    # openssh.authorizedKeys.keys = [ /* SSH key from operator, optional */ ];
  };

  # Store the admin password via agenix/sops-nix for Linux password setup.
  # The actual secret management is handled by nas_setup.py after reboot.
  # ${formDefaults.adminUsername} password: ${formDefaults.adminPassword}

  # Store the KeePassXC master password via the same mechanism.
  # ${formDefaults.useSamePassword ? 'same as admin password' : formDefaults.keePassMasterPassword}
};

exports.writeTempNixConfig = writeTempNixConfig;

/**
 * Authentik API function stubs.
 * These would be called during the Authentik Integration step (Step 3)
 * if Authentik is running during first-start. For now, they are defined
 * so the UI structure exists for future connection.
 */

/**
 * Create an Authentik user via the REST API.
 * POST /api/v3/core/users/
 * @param {Object} user - { username, email, password, active }
 * @returns {Promise} - resolves with user ID
 */
const createAuthentikUser = async (user) => {
  // TODO: Implement real API call when Authentik is available
  console.log('Authentik API: create user', user);
  return new Promise((resolve) => {
    setTimeout(() => resolve({ id: 'stub-user-id', username: user.username }), 100);
  });
};

/**
 * Assign groups to an Authentik user.
 * POST /api/v3/core/users/{id}/groups/
 * @param {string} userId - Authentik user ID
 * @param {Array} groups - e.g. ['nas_admin', 'application.nas.manage']
 * @returns {Promise}
 */
const assignAuthentikGroups = async (userId, groups) => {
  // TODO: Implement real API call
  console.log('Authentik API: assign groups', userId, groups);
  return new Promise((resolve) => setTimeout(resolve, 100));
};

/**
 * Configure the embedded outpost.
 * PATCH /api/v3/core/outposts/
 * @param {Object} outpost - { name, type, authentik_host, applications }
 * @returns {Promise}
 */
const configureEmbeddedOutpost = async (outpost) => {
  // TODO: Implement real API call
  console.log('Authentik API: configure outpost', outpost);
  return new Promise((resolve) => setTimeout(resolve, 100));
};

/**
 * Create an OAuth2 provider.
 * POST /api/v3/core/providers/
 * @param {Object} provider - { name, type, authorization_flow }
 * @returns {Promise} - resolves with provider ID
 */
const createOAuth2Provider = async (provider) => {
  // TODO: Implement real API call
  console.log('Authentik API: create provider', provider);
  return new Promise((resolve) => setTimeout(() => resolve({ id: 'stub-provider-id' }), 100));
};

/**
 * Create an Application linked to a Provider.
 * POST /api/v3/core/applications/
 * @param {Object} application - { name, provider, launch_url }
 * @returns {Promise} - resolves with application ID
 */
const createApplication = async (application) => {
  // TODO: Implement real API call
  console.log('Authentik API: create application', application);
  return new Promise((resolve) => setTimeout(() => resolve({ id: 'stub-app-id' }), 100));
};

exports.writeTempNixConfig = writeTempNixConfig;
exports.createAuthentikUser = createAuthentikUser;
exports.assignAuthentikGroups = assignAuthentikGroups;
exports.configureEmbeddedOutpost = configureEmbeddedOutpost;
exports.createOAuth2Provider = createOAuth2Provider;
exports.createApplication = createApplication;
exports.formDefaults = formDefaults;