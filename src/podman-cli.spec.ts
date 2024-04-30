/**********************************************************************
 * Copyright (C) 2024 Red Hat, Inc.
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

import { ProgressLocation, TelemetryLogger, commands, process as podmanProcess } from '@podman-desktop/api';
import { beforeEach, expect, suite, test, vi } from 'vitest';
import {
  PODMAN_COMMANDS,
  getPodmanCli,
  runCreateFactsFile,
  runRpmInstallSubscriptionManager,
  runStartPodmanMachine,
  runStopPodmanMachine,
  runSubscriptionManager,
  runSubscriptionManagerActivationStatus,
  runSubscriptionManagerRegister,
} from './podman-cli';
import { ExtensionTelemetryLogger } from './telemetry';

vi.mock('@podman-desktop/api', async () => {
  return {
    env: {
      createTelemetryLogger: vi.fn().mockImplementation(
        () =>
          ({
            logUsage: vi.fn(),
            logError: vi.fn(),
          }) as unknown as TelemetryLogger,
      ),
    },
    ProgressLocation: {
      TASK_WIDGET: 2,
    },
    process: {
      exec: vi.fn(),
    },
    configuration: {
      getConfiguration: () => {
        return {
          get: vi.fn(),
        };
      },
    },
  };
});

const runResult = { command: 'command line', stdout: 'stdout output', stderr: 'stderr output' };
const runError = { exitCode: 1, stdout: 'stdout output', stderr: 'stderr output', toString: () => 'error message' };

beforeEach(() => {
  vi.resetAllMocks();
});

test('runSubscriptionManager returns 0 when it is installed', async () => {
  vi.mocked(podmanProcess.exec).mockResolvedValue(runResult);
  const result = await runSubscriptionManager();
  expect(result).toBe(0);
});

test('runSubscriptionManager returns 1 when it is not installed', async () => {
  vi.mocked(podmanProcess.exec).mockRejectedValue({
    exitCode: 1,
    stdout: 'stdout output',
    stderr: 'stderr output',
    toString: () => 'error message',
  });
  const result = await runSubscriptionManager();
  expect(result).toBe(1);
});

test('runRpmInstallSubscription manager returns 0 when successful', async () => {
  vi.mocked(podmanProcess.exec).mockResolvedValue(runResult);
  const result = await runRpmInstallSubscriptionManager();
  expect(result).toBe(runResult);
  expect(podmanProcess.exec).toBeCalledWith(getPodmanCli(), PODMAN_COMMANDS.RPM_INSTALL_SM());
});

test('runRpmInstallSubscription manager returns none 0 error code when failed and send telemetry', async () => {
  vi.mocked(podmanProcess.exec).mockRejectedValue(runError);
  const logErrorSpy = vi.spyOn(ExtensionTelemetryLogger, 'logError').mockImplementation(() => {
    return;
  });
  const consoleError = vi.spyOn(console, 'error');
  let error: Error | undefined;
  const result = await runRpmInstallSubscriptionManager().catch(err => {
    error = err;
  });
  expect(String(error)).toBe(String(runError));
  expect(logErrorSpy).toBeCalledWith('subscriptionManagerInstallationError', { error: 'error message' });
  expect(consoleError).toBeCalledWith(
    'Subscription manager installation failed.',
    runError.toString(),
    `stdout: ${runError.stdout}`,
    `stderr: ${runError.stderr}`,
  );
});

test('runSubscriptionManagerActivationStatus returns 0 when it has subscription activated', async () => {
  vi.mocked(podmanProcess.exec).mockResolvedValue(runResult);
  const result = await runSubscriptionManagerActivationStatus();
  expect(result).toBe(0);
});

test('runSubscriptionManagerActivationStatus returns 1 when it has no active subscription', async () => {
  vi.mocked(podmanProcess.exec).mockRejectedValue({
    exitCode: 1,
    stdout: 'stdout output',
    stderr: 'stderr output',
    toString: () => 'error message',
  });
  const result = await runSubscriptionManagerActivationStatus();
  expect(result).toBe(1);
});

test('runSubscriptionManagerRegister returns 0 when successful', async () => {
  vi.mocked(podmanProcess.exec).mockResolvedValue(runResult);
  const result = await runSubscriptionManagerRegister('activation-key-name', 'orgId');
  expect(result).toBe(runResult);
  expect(podmanProcess.exec).toBeCalledWith(
    getPodmanCli(),
    PODMAN_COMMANDS.SM_ACTIVATE_SUBS('activation-key-name', 'orgId'),
  );
});

test('runSubscriptionManagerRegister manager returns none 0 error code when failed and send telemetry', async () => {
  vi.mocked(podmanProcess.exec).mockRejectedValue(runError);
  const logErrorSpy = vi.spyOn(ExtensionTelemetryLogger, 'logError').mockImplementation(() => {
    return;
  });
  const consoleError = vi.spyOn(console, 'error');
  let error: Error | undefined;
  const result = await runSubscriptionManagerRegister('activation-key-name', 'orgId').catch(err => {
    error = err;
  });
  expect(String(error)).toBe(String(runError));
  expect(logErrorSpy).toBeCalledWith('subscriptionManagerRegisterError', { error: 'error message' });
  expect(consoleError).toBeCalledWith(
    'Subscription manager registration failed.',
    runError.toString(),
    `stdout: ${runError.stdout}`,
    `stderr: ${runError.stderr}`,
  );
});

test('runCreateFactsFile returns 0 when successful', async () => {
  vi.mocked(podmanProcess.exec).mockResolvedValue(runResult);
  const result = await runCreateFactsFile('{"field":"value"}');
  expect(result).toBe(runResult);
  expect(podmanProcess.exec).toBeCalledWith(getPodmanCli(), PODMAN_COMMANDS.CREATE_FACTS_FILE('{"field":"value"}'));
});

test('runCreateFactsFile manager returns none 0 error code when failed and send telemetry', async () => {
  vi.mocked(podmanProcess.exec).mockRejectedValue(runError);
  const logErrorSpy = vi.spyOn(ExtensionTelemetryLogger, 'logError').mockImplementation(() => {
    return;
  });
  const consoleError = vi.spyOn(console, 'error');
  let error: Error | undefined;
  const result = await runCreateFactsFile('{"field":"value"}').catch(err => {
    error = err;
  });
  expect(String(error)).toBe(String(runError));
  expect(logErrorSpy).toBeCalledWith('subscriptionManagerCreateFactsFileError', { error: 'error message' });
  expect(consoleError).toBeCalledWith(
    'Writing /etc/rhsm/facts/podman-desktop-redhat-account-ext.facts failed.',
    runError.toString(),
    `stdout: ${runError.stdout}`,
    `stderr: ${runError.stderr}`,
  );
});

test('runStopPodmanMachine returns 0 when successful', async () => {
  vi.mocked(podmanProcess.exec).mockResolvedValue(runResult);
  const result = await runStopPodmanMachine();
  expect(result).toBe(runResult);
  expect(podmanProcess.exec).toBeCalledWith(getPodmanCli(), PODMAN_COMMANDS.MACHINE_STOP());
});

test('runStopPodmanMachine manager returns none 0 error code when failed and send telemetry', async () => {
  vi.mocked(podmanProcess.exec).mockRejectedValue(runError);
  const logErrorSpy = vi.spyOn(ExtensionTelemetryLogger, 'logError').mockImplementation(() => {
    return;
  });
  const consoleError = vi.spyOn(console, 'error');
  let error: Error | undefined;
  const result = await runStopPodmanMachine().catch(err => {
    error = err;
  });
  expect(String(error)).toBe(String(runError));
  expect(logErrorSpy).toBeCalledWith('stopPodmanMachineError', { error: 'error message' });
  expect(consoleError).toBeCalledWith(
    'Podman machine stop failed.',
    runError.toString(),
    `stdout: ${runError.stdout}`,
    `stderr: ${runError.stderr}`,
  );
});

test('runStartPodmanMachine returns 0 when successful', async () => {
  vi.mocked(podmanProcess.exec).mockResolvedValue(runResult);
  const result = await runStartPodmanMachine();
  expect(result).toBe(runResult);
  expect(podmanProcess.exec).toBeCalledWith(getPodmanCli(), PODMAN_COMMANDS.MACHINE_START());
});

test('runStartPodmanMachine manager returns none 0 error code when failed and send telemetry', async () => {
  vi.mocked(podmanProcess.exec).mockRejectedValue(runError);
  const logErrorSpy = vi.spyOn(ExtensionTelemetryLogger, 'logError').mockImplementation(() => {
    return;
  });
  const consoleError = vi.spyOn(console, 'error');
  let error: Error | undefined;
  const result = await runStartPodmanMachine().catch(err => {
    error = err;
  });
  expect(String(error)).toBe(String(runError));
  expect(logErrorSpy).toBeCalledWith('startPodmanMachineError', { error: 'error message' });
  expect(consoleError).toBeCalledWith(
    'Podman machine start failed.',
    runError.toString(),
    `stdout: ${runError.stdout}`,
    `stderr: ${runError.stderr}`,
  );
});