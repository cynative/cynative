package sandbox

// preludeJS is the pure-JS prelude buildRuntime (sandbox_shell.go) evaluates
// once per runtime. The single %d verb receives the semaphore capacity, which
// becomes mapConcurrent's default concurrency limit, so the helper's logical
// fan-out (spawned worker goroutines, pending promises) is bounded even when
// the script omits the limit. mapConcurrent is installed non-writable and
// non-configurable on globalThis because the runtime — and globalThis —
// persists across Runs: a script cannot replace the binding for a later Run.
// The guard is binding-level only — like anything in the shared runtime, the
// helper's behavior can still drift if a script rewrites the writable builtins
// it uses (Promise.all, Array.isArray, Math); that never widens capability,
// because it is plain JS over the already-registered async tool functions, so
// every call still flows through the Go semaphore and the full auth chain.
const preludeJS = `(function (defaultLimit) {
	async function mapConcurrent(items, fn, limit) {
		if (!Array.isArray(items)) {
			throw new TypeError("mapConcurrent: items must be an array");
		}
		let n = Number(limit);
		if (!Number.isFinite(n) || n < 1) {
			n = defaultLimit;
		}
		// Clamp the worker count to the host cap as well as the item count. A
		// worker spawns its Go tool goroutine before that goroutine parks on the
		// semaphore (loop.go), so a mistaken high limit (e.g. 10000) would queue
		// thousands of goroutines and pending promises for no extra real
		// parallelism — the semaphore already bounds actual I/O at defaultLimit.
		n = Math.max(1, Math.min(Math.floor(n), items.length, defaultLimit));
		const results = new Array(items.length);
		let next = 0;
		let failed = false;
		let firstErr;
		async function worker() {
			while (!failed && next < items.length) {
				const i = next++;
				try {
					results[i] = await fn(items[i], i);
				} catch (e) {
					if (!failed) {
						failed = true;
						firstErr = e;
					}
				}
			}
		}
		const workers = [];
		for (let w = 0; w < n; w++) {
			workers.push(worker());
		}
		await Promise.all(workers);
		if (failed) {
			throw firstErr;
		}
		return results;
	}
	Object.defineProperty(globalThis, "mapConcurrent", {
		value: mapConcurrent,
		writable: false,
		enumerable: false,
		configurable: false,
	});
})(%d);`
