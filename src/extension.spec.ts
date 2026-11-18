/**********************************************************************
 * Copyright (C) 2024-2026 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 ***********************************************************************/
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/explicit-function-return-type */

import type { AuthenticationSession, ExtensionContext, ProviderContainerConnection } from '@podman-desktop/api';
import { authentication, commands, env, navigation, registry, window } from '@podman-desktop/api';
import { afterEach, beforeEach, describe, expect, suite, test, vi } from 'vitest';

import { RedHatAuthenticationService } from './authentication-service';
import * as extension from './extension';
import * as podmanCli from './podman-cli';
import { AccountManagementV1 } from './rh-api/rhaccm-client';
import { SubscriptionManagerClient } from './rh-api/subscription';
import { ExtensionTelemetryLogger } from './telemetry';
import * as util from './util';

vi.mock('@podman-desktop/api');
// The real service runs an OIDC flow, so its static factory is replaced with a
// stub. The factory body executes at import time (the declaration is only
// hoisted), so vi.fn() can be created there without vi.hoisted.
vi.mock(import('./authentication-service'), async importOriginal => {
  const actual = await importOriginal();
  return {
    ...actual,
    RedHatAuthenticationService: { build: vi.fn() } as unknown as typeof actual.RedHatAuthenticationService,
  };
});
vi.mock(import('./rh-api/rhaccm-client'));
vi.mock(import('./rh-api/subscription'));

function createExtContext(): ExtensionContext {
  return {
    subscriptions: [],
    secrets: {
      delete: vi.fn(),
      get: vi.fn(),
      onDidChange: vi.fn(),
      store: vi.fn(),
    },
  } as unknown as ExtensionContext;
}

const fakeConnection: ProviderContainerConnection = {
  providerId: 'podman',
  connection: {
    name: 'test-machine',
    type: 'podman',
    status: () => 'started',
    endpoint: {
      socketPath: '/home/user/.local/share/containers/podman/test.sock',
    },
  },
} as unknown as ProviderContainerConnection;

function createFakeJwt(payload: object): string {
  const header = btoa(JSON.stringify({ alg: 'none' }));
  const body = btoa(JSON.stringify(payload));
  return `${header}.${body}.signature`;
}

const fakeSession: AuthenticationSession = {
  id: '1',
  accessToken: createFakeJwt({ organization: { id: 'org-123' } }),
  scopes: ['scope1', 'scope2'],
  account: {
    id: 'accountId',
    label: 'user@redhat.com',
  },
};

type CommandHandler = (...args: any[]) => Promise<any>;
interface CapturedProvider {
  createSession: (scopes: string[]) => Promise<AuthenticationSession>;
  getSessions: (scopes: string[]) => Promise<AuthenticationSession[]>;
  removeSession: (sessionId: string) => Promise<void>;
}
let capturedCommands: Record<string, CommandHandler> = {};
let capturedProvider: CapturedProvider | undefined;
let fakeService: RedHatAuthenticationService;

function setupBasicMocks(options?: {
  sessionAvailable?: boolean;
  registryConfigured?: boolean;
  isLinux?: boolean;
  connection?: ProviderContainerConnection;
}) {
  const {
    sessionAvailable = true,
    registryConfigured = false,
    isLinux = false,
    connection = undefined,
  } = options ?? {};

  vi.spyOn(util, 'isLinux').mockReturnValue(isLinux);
  vi.spyOn(util, 'isRedHatRegistryConfigured').mockReturnValue(registryConfigured);
  vi.spyOn(podmanCli, 'getConnectionForRunningPodmanMachine').mockReturnValue(connection);
  vi.spyOn(ExtensionTelemetryLogger, 'logUsage').mockImplementation(() => {});
  vi.spyOn(ExtensionTelemetryLogger, 'logError').mockImplementation(() => {});
  // Activation kicks off registry/subscription work in the background when a
  // stored session exists; keep those helpers inert so nothing leaks out.
  vi.spyOn(podmanCli, 'runSubscriptionManager').mockResolvedValue(0);
  vi.spyOn(podmanCli, 'runSubscriptionManagerActivationStatus').mockResolvedValue(0);
  vi.spyOn(podmanCli, 'runSubscriptionManagerUnregister').mockResolvedValue(undefined);
  vi.spyOn(podmanCli, 'runCreateFactsFile').mockResolvedValue(undefined);
  vi.spyOn(podmanCli, 'runSubscriptionManagerRegister').mockResolvedValue(undefined);

  vi.mocked(authentication.getSession).mockResolvedValue(sessionAvailable ? fakeSession : undefined);

  fakeService = {
    initialize: vi.fn().mockResolvedValue(undefined),
    getSessions: vi.fn().mockResolvedValue(sessionAvailable ? [fakeSession] : []),
    createSession: vi.fn().mockResolvedValue(fakeSession),
    removeSession: vi.fn().mockResolvedValue(fakeSession),
    dispose: vi.fn(),
  } as unknown as RedHatAuthenticationService;
  vi.mocked(RedHatAuthenticationService.build).mockResolvedValue(fakeService);

  vi.mocked(commands.registerCommand).mockImplementation((commandId: string, commandFunction: CommandHandler) => {
    capturedCommands[commandId] = commandFunction;
    return { dispose: vi.fn() };
  });

  capturedProvider = undefined;
  vi.mocked(authentication.registerAuthenticationProvider).mockImplementation((_id, _label, provider: any) => {
    capturedProvider = provider;
    return { dispose: vi.fn() };
  });
}

// Let the fire-and-forget registry/subscription work triggered by sign-in finish.
async function flushPromises(): Promise<void> {
  for (let i = 0; i < 20; i++) {
    await new Promise(resolve => setTimeout(resolve, 0));
  }
}

// Activate the extension and sign in the same way the host does: through the
// authentication provider, then wait for the background activation workflow.
async function activateAndSignIn(): Promise<void> {
  await extension.activate(createExtContext());
  await flushPromises();
  await capturedProvider!.createSession([]);
  await flushPromises();
}

beforeEach(() => {
  vi.resetAllMocks();
  capturedCommands = {};
  capturedProvider = undefined;
  // Safe default: any build() left over from a previous test still resolves.
  vi.mocked(RedHatAuthenticationService.build).mockResolvedValue({
    initialize: vi.fn().mockResolvedValue(undefined),
    getSessions: vi.fn().mockResolvedValue([]),
    dispose: vi.fn(),
  } as unknown as RedHatAuthenticationService);
});

afterEach(() => {
  extension.deactivate();
});

suite('extension activation', () => {
  test('register commands declared in package.json', async () => {
    await extension.activate(createExtContext());
    await flushPromises();
    expect(commands.registerCommand).toHaveBeenCalledTimes(5);
    expect(commands.registerCommand).toHaveBeenCalledWith('redhat.authentication.signin', expect.anything());
    expect(commands.registerCommand).toHaveBeenCalledWith('redhat.authentication.navigate.settings', expect.anything());
    expect(commands.registerCommand).toHaveBeenCalledWith('redhat.authentication.signout', expect.anything());
    expect(commands.registerCommand).toHaveBeenCalledWith('redhat.authentication.signup', expect.anything());
    expect(commands.registerCommand).toHaveBeenCalledWith('redhat.authentication.isSignedIn', expect.anything());
  });
});

suite('deactivate', () => {
  test('logs stop message and clears session', () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    extension.deactivate();
    expect(consoleSpy).toHaveBeenCalledWith('stopping redhat-authentication extension');
  });
});

suite('signin command telemetry reports', () => {
  test('unsuccessful login when podman machine is not running on windows or darwin', async () => {
    setupBasicMocks({ isLinux: false, registryConfigured: true });
    const logSpy = vi.spyOn(ExtensionTelemetryLogger, 'logUsage').mockImplementation(() => {});
    vi.spyOn(podmanCli, 'getConnectionForRunningPodmanMachine').mockReturnValue(undefined);

    await activateAndSignIn();

    expect(logSpy).toHaveBeenCalledWith('signin', {
      successful: false,
      error: 'Error: No running podman',
      errorIn: 'subscription-activation',
    });
  });

  test('unsuccessful login shows Linux-specific message on Linux', async () => {
    setupBasicMocks({ isLinux: true, connection: undefined, registryConfigured: true });

    await activateAndSignIn();

    expect(window.showInformationMessage).toHaveBeenCalledWith(
      expect.stringContaining('not supported on a Linux host'),
    );
  });

  test('successful sign-in configures registry when not already configured', async () => {
    const mockGetAccessToken = vi.fn().mockResolvedValue({
      username: 'svc-user',
      password: 'svc-pass',
    });
    vi.mocked(AccountManagementV1).mockImplementation(function () {
      return { getAccessToken: mockGetAccessToken } as any;
    });

    setupBasicMocks({ registryConfigured: false, connection: fakeConnection });
    vi.spyOn(podmanCli, 'runSubscriptionManager').mockResolvedValue(0);
    vi.spyOn(podmanCli, 'runSubscriptionManagerActivationStatus').mockResolvedValue(0);

    await activateAndSignIn();

    expect(mockGetAccessToken).toHaveBeenCalled();
    expect(registry.registerRegistry).toHaveBeenCalledWith(
      expect.objectContaining({
        serverUrl: 'registry.redhat.io',
        username: 'svc-user',
        secret: 'svc-pass',
      }),
    );
  });

  test('skips registry configuration when already configured', async () => {
    setupBasicMocks({ registryConfigured: true, connection: fakeConnection });
    vi.spyOn(podmanCli, 'runSubscriptionManager').mockResolvedValue(0);
    vi.spyOn(podmanCli, 'runSubscriptionManagerActivationStatus').mockResolvedValue(0);

    await activateAndSignIn();

    expect(AccountManagementV1).not.toHaveBeenCalled();
  });

  test('installs subscription manager and restarts machine when not installed', async () => {
    setupBasicMocks({ registryConfigured: true, connection: fakeConnection });
    vi.spyOn(podmanCli, 'runSubscriptionManager').mockResolvedValue(1);
    vi.spyOn(podmanCli, 'runRpmInstallSubscriptionManager').mockResolvedValue(undefined);
    vi.spyOn(podmanCli, 'runStopPodmanMachine').mockResolvedValue(undefined);
    vi.spyOn(podmanCli, 'runStartPodmanMachine').mockResolvedValue(undefined);
    vi.spyOn(podmanCli, 'runSubscriptionManagerActivationStatus').mockResolvedValue(0);

    await activateAndSignIn();

    expect(podmanCli.runRpmInstallSubscriptionManager).toHaveBeenCalledWith(fakeConnection);
    expect(podmanCli.runStopPodmanMachine).toHaveBeenCalledWith(fakeConnection);
    expect(podmanCli.runStartPodmanMachine).toHaveBeenCalledWith(fakeConnection);
  });

  test('creates activation key when subscription is not activated', async () => {
    setupBasicMocks({ registryConfigured: true, connection: fakeConnection });
    vi.spyOn(podmanCli, 'runSubscriptionManager').mockResolvedValue(0);
    vi.spyOn(podmanCli, 'runSubscriptionManagerActivationStatus').mockResolvedValue(1);
    vi.spyOn(podmanCli, 'runCreateFactsFile').mockResolvedValue(undefined);
    vi.spyOn(podmanCli, 'runSubscriptionManagerRegister').mockResolvedValue(undefined);
    vi.spyOn(podmanCli, 'runSubscriptionManagerUnregister').mockResolvedValue(undefined);

    const mockShowActivationKey = vi.fn().mockResolvedValue({ error: { message: 'not found' } });
    const mockCreateActivationKeys = vi.fn().mockResolvedValue({ error: undefined });
    vi.mocked(SubscriptionManagerClient).mockImplementation(function () {
      return {
        activationKey: {
          showActivationKey: mockShowActivationKey,
          createActivationKeys: mockCreateActivationKeys,
        },
      } as any;
    });

    await activateAndSignIn();

    expect(podmanCli.runCreateFactsFile).toHaveBeenCalledWith(fakeConnection, expect.stringContaining('aarch64'));
    expect(mockCreateActivationKeys).toHaveBeenCalledWith(expect.objectContaining({ name: 'podman-desktop' }));
    expect(podmanCli.runSubscriptionManagerRegister).toHaveBeenCalledWith(fakeConnection, 'podman-desktop', 'org-123');
  });

  test('reuses existing activation key when show succeeds', async () => {
    setupBasicMocks({ registryConfigured: true, connection: fakeConnection });
    vi.spyOn(podmanCli, 'runSubscriptionManager').mockResolvedValue(0);
    vi.spyOn(podmanCli, 'runSubscriptionManagerActivationStatus').mockResolvedValue(1);
    vi.spyOn(podmanCli, 'runCreateFactsFile').mockResolvedValue(undefined);
    vi.spyOn(podmanCli, 'runSubscriptionManagerRegister').mockResolvedValue(undefined);
    vi.spyOn(podmanCli, 'runSubscriptionManagerUnregister').mockResolvedValue(undefined);

    const mockShowActivationKey = vi.fn().mockResolvedValue({ error: undefined });
    const mockCreateActivationKeys = vi.fn();
    vi.mocked(SubscriptionManagerClient).mockImplementation(function () {
      return {
        activationKey: {
          showActivationKey: mockShowActivationKey,
          createActivationKeys: mockCreateActivationKeys,
        },
      } as any;
    });

    await activateAndSignIn();

    expect(mockCreateActivationKeys).not.toHaveBeenCalled();
    expect(podmanCli.runSubscriptionManagerRegister).toHaveBeenCalled();
  });

  test('reports sign-in telemetry error when creating the session throws', async () => {
    setupBasicMocks({ sessionAvailable: false });
    vi.mocked(fakeService.createSession).mockRejectedValue(new Error('SSO failure'));

    await extension.activate(createExtContext());
    await flushPromises();
    await capturedCommands['redhat.authentication.signin']();

    expect(ExtensionTelemetryLogger.logUsage).toHaveBeenCalledWith(
      'signin',
      expect.objectContaining({
        errorIn: 'sign-in',
        error: expect.stringContaining('SSO failure'),
      }),
    );
  });
});

describe('signout command', () => {
  test('fires session removed event and sends telemetry', async () => {
    setupBasicMocks({ connection: fakeConnection });
    vi.spyOn(podmanCli, 'runSubscriptionManager').mockResolvedValue(0);
    vi.spyOn(podmanCli, 'runSubscriptionManagerActivationStatus').mockResolvedValue(0);
    vi.spyOn(util, 'isRedHatRegistryConfigured').mockReturnValue(true);

    await activateAndSignIn();
    await capturedCommands['redhat.authentication.signout']();

    expect(ExtensionTelemetryLogger.logUsage).toHaveBeenCalledWith('signout');
  });
});

describe('signup command', () => {
  test('opens Red Hat developer sign-up page', async () => {
    setupBasicMocks();

    await extension.activate(createExtContext());
    await flushPromises();
    await capturedCommands['redhat.authentication.signup']();

    expect(env.openExternal).toHaveBeenCalled();
  });
});

describe('isSignedIn command', () => {
  test('sets signedInToSSO context when sessions exist', async () => {
    setupBasicMocks();

    await extension.activate(createExtContext());
    await flushPromises();
    await capturedCommands['redhat.authentication.isSignedIn']();

    expect(commands.registerCommand).toHaveBeenCalledWith('redhat.authentication.isSignedIn', expect.anything());
  });
});

describe('navigate to settings command', () => {
  test('calls navigateToAuthentication', async () => {
    setupBasicMocks();

    await extension.activate(createExtContext());
    await flushPromises();
    await capturedCommands['redhat.authentication.navigate.settings']();

    expect(navigation.navigateToAuthentication).toHaveBeenCalled();
  });
});
