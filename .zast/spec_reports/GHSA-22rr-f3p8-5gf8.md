---
id: "GHSA-22rr-f3p8-5gf8"
category: "code-injection"
severity: "high"
refs:
  - url: "https://github.com/directus/directus/security/advisories/GHSA-22rr-f3p8-5gf8"
    type: ADVISORY
    conclusion: |-
      Directus 受 VM2 沙箱逃逸漏洞影响：vm2 3.9.19 及以下版本的 Promise handler 清洗可被绕过，攻击者可逃逸沙箱并在主 Node.js 上下文执行任意代码；在 Directus 中适用于 Flows 的 "Run Script"（exec）操作。v10.6.0 已通过以 isolated-vm 替换 vm2 修复（CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H，OSV database_specific.severity: HIGH）。
---

# 代码注入（Code Injection） — POST /flows/trigger/:pk([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})

## 漏洞描述

In Directus's POST /flows/trigger/:pk, the full request (body, query, headers, method) is captured as the $trigger data in runWebhookFlow and rendered into every flow operation's options by applyOptionsData, so the 'Run Script' (exec) operation whose code option references {{$trigger...}} has attacker-supplied strings spliced into the JavaScript that new VMScript(code).compile() compiles and vm.run executes in a NodeVM. The only guard is micromustache's HTML-entity escaping, a character-level escaper that does not stop plain JS code (semicolons, newlines, brace/paren structure pass through, and unabbreviated {{...}} substitutions can be emitted verbatim), so a caller can turn a template-slot in the executable code into arbitrary executed JavaScript.

## 影响范围

- 端点: `POST /flows/trigger/:pk([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`

## 审计路径

1. `api/src/controllers/flows.ts:25` — req.body (along with query and headers) is packed into the data object handed to runWebhookFlow, so the whole request becomes the flow's attacker-controlled payload.

   ```javascript
   path: req.path,
   ```
2. `api/src/flows.ts:308` — executeFlow stores that request data as the $trigger (and $last) variable in keyedData, exposing it to every operation in the flow.

   ```javascript
   [TRIGGER_KEY]: data,
   ```
3. `api/src/flows.ts:410` — applyOptionsData renders mustache templates in each operation's options against keyedData, so a {{$trigger.body.x}} slot in the exec operation's code becomes the raw request value.

   ```javascript
   const options = applyOptionsData(operation.options, keyedData);
   ```
4. `api/src/operations/exec/index.ts:44` — The interpolated code string is compiled via new VMScript(code).compile() and executed with vm.run inside a NodeVM, so request-supplied text is evaluated as JavaScript.

   ```javascript
   const script = new VMScript(code).compile();
   const fn = await vm.run(script);
   ```

## 证据代码

```javascript
// api/src/controllers/flows.ts#L19C41-L43C2
const webhookFlowHandler = asyncHandler(async (req, res, next) => {
	const flowManager = getFlowManager();

	const { result, cacheEnabled } = await flowManager.runWebhookFlow(
		`${req.method}-${req.params['pk']}`,
		{
			path: req.path,
			query: req.query,
			body: req.body,
			method: req.method,
			headers: req.headers,
		},
		{
			accountability: req.accountability,
			schema: req.schema,
		}
	);

	if (!cacheEnabled) {
		res.locals['cache'] = false;
	}

	res.locals['payload'] = result;
	return next();
});
```

```javascript
// api/src/flows.ts#L303C2-L391C3
	private async executeFlow(flow: Flow, data: unknown = null, context: Record<string, unknown> = {}): Promise<unknown> {
		const database = (context['database'] as Knex) ?? getDatabase();
		const schema = (context['schema'] as SchemaOverview) ?? (await getSchema({ database }));

		const keyedData: Record<string, unknown> = {
			[TRIGGER_KEY]: data,
			[LAST_KEY]: data,
			[ACCOUNTABILITY_KEY]: context?.['accountability'] ?? null,
			[ENV_KEY]: pick(env, env['FLOWS_ENV_ALLOW_LIST'] ? toArray(env['FLOWS_ENV_ALLOW_LIST']) : []),
		};

		let nextOperation = flow.operation;
		let lastOperationStatus: 'resolve' | 'reject' | 'unknown' = 'unknown';

		const steps: {
			operation: string;
			key: string;
			status: 'resolve' | 'reject' | 'unknown';
			options: Record<string, any> | null;
		}[] = [];

		while (nextOperation !== null) {
			const { successor, data, status, options } = await this.executeOperation(nextOperation, keyedData, context);

			keyedData[nextOperation.key] = data;
			keyedData[LAST_KEY] = data;
			lastOperationStatus = status;
			steps.push({ operation: nextOperation!.id, key: nextOperation.key, status, options });

			nextOperation = successor;
		}

		if (flow.accountability !== null) {
			const activityService = new ActivityService({
				knex: database,
				schema: schema,
			});

			const accountability = context?.['accountability'] as Accountability | undefined;

			const activity = await activityService.createOne({
				action: Action.RUN,
				user: accountability?.user ?? null,
				collection: 'directus_flows',
				ip: accountability?.ip ?? null,
				user_agent: accountability?.userAgent ?? null,
				origin: accountability?.origin ?? null,
				item: flow.id,
			});

			if (flow.accountability === 'all') {
				const revisionsService = new RevisionsService({
					knex: database,
					schema: schema,
				});

				await revisionsService.createOne({
					activity: activity,
					collection: 'directus_flows',
					item: flow.id,
					data: {
						steps: steps,
						data: redact(
							omit(keyedData, '$accountability.permissions'), // Permissions is a ton of data, and is just a copy of what's in the directus_permissions table
							[
								['**', 'headers', 'authorization'],
								['**', 'headers', 'cookie'],
								['**', 'query', 'access_token'],
								['**', 'payload', 'password'],
							],
							REDACTED_TEXT
						),
					},
				});
			}
		}

		if (flow.trigger === 'event' && flow.options['type'] === 'filter' && lastOperationStatus === 'reject') {
			throw keyedData[LAST_KEY];
		}

		if (flow.options['return'] === '$all') {
			return keyedData;
		} else if (flow.options['return']) {
			return get(keyedData, flow.options['return']);
		}

		return undefined;
	}
```

```javascript
// api/src/flows.ts#L393C2-L455C3
	private async executeOperation(
		operation: Operation,
		keyedData: Record<string, unknown>,
		context: Record<string, unknown> = {}
	): Promise<{
		successor: Operation | null;
		status: 'resolve' | 'reject' | 'unknown';
		data: unknown;
		options: Record<string, any> | null;
	}> {
		if (!(operation.type in this.operations)) {
			logger.warn(`Couldn't find operation ${operation.type}`);
			return { successor: null, status: 'unknown', data: null, options: null };
		}

		const handler = this.operations[operation.type]!;

		const options = applyOptionsData(operation.options, keyedData);

		try {
			let result = await handler(options, {
				services,
				env,
				database: getDatabase(),
				logger,
				getSchema,
				data: keyedData,
				accountability: null,
				...context,
			});

			// Validate that the operations result is serializable and thus catching the error inside the flow execution
			JSON.stringify(result ?? null);

			// JSON structures don't allow for undefined values, so we need to replace them with null
			// Otherwise the applyOptionsData function will not work correctly on the next operation
			if (typeof result === 'object' && result !== null) {
				result = mapValuesDeep(result, (_, value) => (value === undefined ? null : value));
			}

			return { successor: operation.resolve, status: 'resolve', data: result ?? null, options };
		} catch (error) {
			let data;

			if (error instanceof Error) {
				// make sure we don't expose the stack trace
				data = sanitizeError(error);
			} else if (typeof error === 'string') {
				// If the error is a JSON string, parse it and use that as the error data
				data = isValidJSON(error) ? parseJSON(error) : error;
			} else {
				// If error is plain object, use this as the error data and otherwise fallback to null
				data = error ?? null;
			}

			return {
				successor: operation.reject,
				status: 'reject',
				data,
				options,
			};
		}
	}
```

```javascript
// api/src/operations/exec/index.ts#L12C11-L48C3
	handler: async ({ code }, { data, env }) => {
		const allowedModules = env['FLOWS_EXEC_ALLOWED_MODULES'] ? toArray(env['FLOWS_EXEC_ALLOWED_MODULES']) : [];
		const allowedModulesBuiltIn: string[] = [];
		const allowedModulesExternal: string[] = [];
		const allowedEnv = data['$env'] ?? {};

		const opts: NodeVMOptions = {
			eval: false,
			wasm: false,
			env: allowedEnv,
		};

		for (const module of allowedModules) {
			if (isBuiltin(module)) {
				allowedModulesBuiltIn.push(module);
			} else {
				allowedModulesExternal.push(module);
			}
		}

		if (allowedModules.length > 0) {
			opts.require = {
				builtin: allowedModulesBuiltIn,
				external: {
					modules: allowedModulesExternal,
					transitive: false,
				},
			};
		}

		const vm = new NodeVM(opts);

		const script = new VMScript(code).compile();
		const fn = await vm.run(script);

		return await fn(data);
	},
```

## 根本原因

`injection` — `api/src/operations/exec/index.ts:44`

## 利用步骤

body with a field wired into an exec operation code slot via {{$trigger.body.<field>}} containing injected JS (e.g. `;return 'pwned';`) to run inside the flow's NodeVM
