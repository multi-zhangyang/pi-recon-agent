import { uniqueNonEmpty } from "./text.ts";

export type RepiWorkerProviderChildProcessProbeV1 = {
	kind: "WorkerProviderChildProcessProbeV1";
	schemaVersion: 1;
	probeId: string;
	providerName: string;
	modelId: string;
	command: string;
	args: string[];
	cwd: string;
	isolatedHome: string;
	modelsJsonPath: string;
	requestLogPath: string;
	transcriptPath: string;
	stdoutPath: string;
	stderrPath: string;
	stdoutSha256: string;
	stderrSha256: string;
	requestLogSha256: string;
	transcriptSha256: string;
	startedAt: string;
	endedAt: string;
	elapsedMs: number;
	exitCode: number | null;
	signal: string | null;
	status: "pass" | "blocked";
	assertions: {
		openAICompatibleRequestSeen: boolean;
		modelMatched: boolean;
		stdoutMarkerObserved: boolean;
		apiKeyEnvRefOnly: boolean;
		authorizationFromEnv: boolean;
		transcriptCaptured: boolean;
		noPiHomeImport: boolean;
		noUpdateBanner: boolean;
		noLiteralSecrets: boolean;
	};
	request: {
		method?: string;
		path?: string;
		model?: string;
		stream?: boolean;
		authorizationHeaderSha256?: string;
		bodySha256?: string;
	};
	errors: string[];
};

export type RepiProviderRuntimeMatrixCaseV1 = {
	kind: "ProviderRuntimeMatrixCaseV1";
	schemaVersion: 1;
	caseId: string;
	providerName: string;
	api: "openai-completions" | "openai-responses" | "anthropic-messages";
	modelId: string;
	expectedPath: "/v1/chat/completions" | "/v1/responses" | "/v1/messages";
	diagnostic?: string;
	authHeader: "authorization" | "x-api-key";
	status: "pass" | "blocked";
	exitCode: number | null;
	signal: string | null;
	elapsedMs: number;
	stdoutPath: string;
	stderrPath: string;
	stdoutSha256: string;
	stderrSha256: string;
	request: {
		method?: string;
		path?: string;
		model?: string;
		stream?: boolean;
		authHeaderSha256?: string;
		bodySha256?: string;
	};
	assertions: {
		exitOk: boolean;
		requestSeen: boolean;
		modelMatched: boolean;
		streamingUsed: boolean;
		stdoutMarkerObserved: boolean;
		apiKeyEnvRefOnly: boolean;
		authorizationFromEnv: boolean;
		noPiHomeImport: boolean;
		noUpdateBanner: boolean;
		noLiteralSecrets: boolean;
		transcriptCaptured: boolean;
		requestLogCaptured: boolean;
	};
	errors: string[];
};

export type RepiProviderRuntimeMatrixV1 = {
	kind: "ProviderRuntimeMatrixV1";
	schemaVersion: 1;
	generatedAt: string;
	modelsJsonPath: string;
	requestLogPath: string;
	isolatedHome: string;
	workspace: string;
	listModels: {
		status: "pass" | "blocked";
		providers: string[];
		stdoutSha256: string;
		stderrSha256: string;
	};
	cases: RepiProviderRuntimeMatrixCaseV1[];
};

export type RepiProviderFailureInjectionReportV1 = {
	kind: "ProviderFailureInjectionReportV1";
	schemaVersion: 1;
	generatedAt: string;
	isolatedHome: string;
	workspace: string;
	cases: Array<{
		kind: "ProviderFailureInjectionCaseV1";
		schemaVersion: 1;
		caseId: string;
		providerName: string;
		api: "openai-completions" | "anthropic-messages";
		modelId: string;
		failureMode: "http_500" | "malformed_sse" | "anthropic_error_event" | "timeout" | "connection_reset";
		status: "pass" | "blocked";
		exitCode: number | null;
		signal: string | null;
		request: {
			method?: string;
			path?: string;
			model?: string;
			stream?: boolean;
			bodySha256?: string;
		};
		stdoutSha256: string;
		stderrSha256: string;
		requestLogSha256: string;
		transcriptSha256: string;
		failureId: string;
		repairId: string;
		assertions: {
			requestSeen: boolean;
			exitNonZero: boolean;
			failureTextCaptured: boolean;
			failureRepairLinked: boolean;
			noLiteralSecrets: boolean;
			noPiHomeImport: boolean;
			noUpdateBanner: boolean;
		};
	}>;
	failureLedgerEvents: Array<{
		id: string;
		status: string;
		retryBudget: { remainingAttempts: number };
	}>;
	repairQueue: Array<{
		repairId: string;
		fromFailureId: string;
		action: string;
		paused: boolean;
	}>;
	failureRepairValidation: {
		ok: boolean;
		failureCount: number;
		repairCount: number;
	};
	writebackProbe: {
		status: "pass" | "blocked";
		validation: { ok: boolean };
	};
};

export type RepiRepairRollbackPolicyV1 = {
	kind: "RepairRollbackPolicyV1";
	schemaVersion: 1;
	baseline: { treeSha256: string; files: unknown[] };
	allowlist: string[];
	repair: { changedFiles: string[] };
	rollback: { required: boolean; restored: boolean; restoredTreeSha256: string };
	regression: {
		after: string;
		restored: string;
		checkpoints: Array<{ checkId: string; status: string }>;
	};
	failureLedgerEvents: unknown[];
	repairQueue: Array<{ action: string; rollbackCriteria: { mustRestore: string[] } }>;
	failureRepairValidation: { ok: boolean };
	assertions: {
		baselineCaptured: boolean;
		allowlistEnforced: boolean;
		rollbackRestored: boolean;
		regressionChecksPassed: boolean;
		noUnrelatedFileChanges: boolean;
		failureRepairLinked: boolean;
	};
};

export type RepiParallelProviderWorkerMatrixV1 = {
	kind: "ParallelProviderWorkerMatrixV1";
	schemaVersion: 1;
	poolId: string;
	isolatedHome: string;
	maxConcurrency: number;
	peakConcurrency: number;
	listModels: { status: "pass" | "blocked" };
	workers: Array<{
		workerId: string;
		providerName: string;
		api: "openai-completions" | "anthropic-messages";
		modelId: string;
		mode: "pass" | "failure" | "timeout";
		status: "pass" | "repair_queued" | "cancelled" | "blocked";
		mergeKey: string;
		failureId?: string;
		repairId?: string;
		timedOut: boolean;
		cancelledAt?: string;
		assertions: {
			childProcessLaunched: boolean;
			requestSeen: boolean;
			endpointMatched: boolean;
			modelMatched: boolean;
			streamingUsed: boolean;
			successMarkerObserved: boolean;
			exitOkWhenExpected: boolean;
			exitFailedWhenExpected: boolean;
			timeoutCancelled: boolean;
			apiKeyEnvRefOnly: boolean;
			authorizationFromEnv: boolean;
			requestLogCaptured: boolean;
			transcriptCaptured: boolean;
			noLiteralSecrets: boolean;
			noPiHomeImport: boolean;
			noUpdateBanner: boolean;
			providerWorkerFailureRepairLinked?: boolean;
		};
	}>;
	claimMerge: {
		strategy: string;
		claimAwareProviderWorkerMerge: boolean;
		conflicts: Array<{ mergeKey: string; status: "resolved" | "open"; winner?: string; evidenceRefs: string[] }>;
	};
	failureLedgerEvents: Array<{ status: string; retryBudget: { remainingAttempts: number } }>;
	repairQueue: Array<{ action: string; paused: boolean }>;
	failureRepairValidation: { ok: boolean };
	writebackProbe: { status: "pass" | "blocked"; validation: { ok: boolean } };
};

export type RepiRemoteProviderLongRunV1 = {
	kind: "RemoteProviderLongRunV1";
	mode: "skipped" | "live";
	skipReason: string;
	providerName?: string;
	api?: "openai-completions" | "openai-responses" | "anthropic-messages";
	modelIdSha256?: string;
	baseUrlSha256?: string;
	apiKeyEnv?: string;
	attemptsPlanned: number;
	listModels: { status: "pass" | "blocked" | "skipped" };
	cases: Array<{
		caseId: string;
		status: "pass" | "blocked";
		assertions: {
			exitOk: boolean;
			stdoutNonEmpty: boolean;
			markerObserved: boolean;
			apiKeyEnvRefOnly: boolean;
			boundedTimeout: boolean;
			isolatedRepiHome: boolean;
			noLiteralSecrets: boolean;
			noPiHomeImport: boolean;
			noUpdateBanner: boolean;
			transcriptCaptured: boolean;
		};
	}>;
	failureLedgerEvents: unknown[];
	repairQueue: unknown[];
	failureRepairValidation: { ok: boolean };
	writebackProbe: { status: "pass" | "blocked" | "skipped"; validation: { ok: boolean } };
};

export function verifyWorkerProviderChildProcessProbe(probe: RepiWorkerProviderChildProcessProbeV1): string[] {
	const errors: string[] = [];
	if (probe.kind !== "WorkerProviderChildProcessProbeV1" || probe.status !== "pass")
		errors.push("provider_child_process_probe_not_pass");
	if (!probe.assertions.openAICompatibleRequestSeen) errors.push("provider_child_process_request_missing");
	if (!probe.assertions.modelMatched) errors.push("provider_child_process_model_mismatch");
	if (!probe.assertions.stdoutMarkerObserved) errors.push("provider_child_process_stdout_marker_missing");
	if (!probe.assertions.apiKeyEnvRefOnly) errors.push("provider_child_process_api_key_not_env_ref");
	if (!probe.assertions.authorizationFromEnv) errors.push("provider_child_process_authorization_not_env");
	if (!probe.assertions.transcriptCaptured || !probe.transcriptSha256)
		errors.push("provider_child_process_transcript_missing");
	if (!probe.assertions.noPiHomeImport) errors.push("provider_child_process_imported_pi_home");
	if (!probe.assertions.noUpdateBanner) errors.push("provider_child_process_update_banner");
	if (!probe.assertions.noLiteralSecrets) errors.push("provider_child_process_literal_secret");
	if (!probe.isolatedHome.includes(".repi") || probe.isolatedHome.includes("/.pi/"))
		errors.push("provider_child_process_isolated_home_invalid");
	if (probe.request.path !== "/v1/chat/completions") errors.push("provider_child_process_endpoint_invalid");
	if (probe.request.model !== probe.modelId) errors.push("provider_child_process_request_model_invalid");
	return errors;
}

export function verifyProviderRuntimeMatrixV1(matrix: RepiProviderRuntimeMatrixV1): { ok: boolean; errors: string[] } {
	const errors: string[] = [];
	if (matrix.kind !== "ProviderRuntimeMatrixV1") errors.push("provider_matrix_kind_invalid");
	if (!matrix.isolatedHome.includes(".repi") || matrix.isolatedHome.includes("/.pi/"))
		errors.push("provider_matrix_isolated_home_invalid");
	const requiredApis = new Set<RepiProviderRuntimeMatrixCaseV1["api"]>([
		"openai-completions",
		"openai-responses",
		"anthropic-messages",
	]);
	for (const row of matrix.cases) {
		requiredApis.delete(row.api);
		if (row.status !== "pass") errors.push(`provider_matrix_case_not_pass:${row.caseId}`);
		if (!row.assertions.exitOk) errors.push(`provider_matrix_exit_not_ok:${row.caseId}`);
		if (!row.assertions.requestSeen) errors.push(`provider_matrix_request_missing:${row.caseId}`);
		if (!row.assertions.modelMatched) errors.push(`provider_matrix_model_mismatch:${row.caseId}`);
		if (!row.assertions.streamingUsed) errors.push(`provider_matrix_stream_missing:${row.caseId}`);
		if (!row.assertions.stdoutMarkerObserved) errors.push(`provider_matrix_stdout_marker_missing:${row.caseId}`);
		if (!row.assertions.apiKeyEnvRefOnly) errors.push(`provider_matrix_api_key_not_env_ref:${row.caseId}`);
		if (!row.assertions.authorizationFromEnv) errors.push(`provider_matrix_authorization_not_env:${row.caseId}`);
		if (!row.assertions.noPiHomeImport) errors.push(`provider_matrix_pi_home_leak:${row.caseId}`);
		if (!row.assertions.noUpdateBanner) errors.push(`provider_matrix_update_banner_leak:${row.caseId}`);
		if (!row.assertions.noLiteralSecrets) errors.push(`provider_matrix_literal_secret:${row.caseId}`);
		if (!row.assertions.transcriptCaptured || !row.assertions.requestLogCaptured)
			errors.push(`provider_matrix_artifact_missing:${row.caseId}`);
		if (row.api === "openai-completions" && row.request.path !== "/v1/chat/completions")
			errors.push(`provider_matrix_openai_endpoint_invalid:${row.caseId}`);
		if (row.api === "openai-responses" && row.request.path !== "/v1/responses")
			errors.push(`provider_matrix_responses_endpoint_invalid:${row.caseId}`);
		if (row.api === "anthropic-messages" && row.request.path !== "/v1/messages")
			errors.push(`provider_matrix_anthropic_endpoint_invalid:${row.caseId}`);
	}
	for (const api of requiredApis) errors.push(`provider_matrix_missing_api:${api}`);
	if (matrix.listModels.status !== "pass") errors.push("provider_matrix_list_models_not_pass");
	for (const row of matrix.cases) {
		if (!matrix.listModels.providers.includes(row.providerName))
			errors.push(`provider_matrix_list_models_missing:${row.providerName}`);
	}
	return { ok: errors.length === 0, errors: uniqueNonEmpty(errors, 80) };
}

export function verifyProviderFailureInjectionReportV1(report: RepiProviderFailureInjectionReportV1): {
	ok: boolean;
	errors: string[];
} {
	const errors: string[] = [];
	if (report.kind !== "ProviderFailureInjectionReportV1") errors.push("provider_failure_report_kind_invalid");
	if (!report.isolatedHome.includes(".repi") || report.isolatedHome.includes("/.pi/"))
		errors.push("provider_failure_isolated_home_invalid");
	if (report.cases.length < 3) errors.push("provider_failure_case_count_lt_3");
	for (const row of report.cases) {
		if (row.status !== "pass") errors.push(`provider_failure_case_not_pass:${row.caseId}`);
		if (!row.assertions.requestSeen) errors.push(`provider_failure_request_missing:${row.caseId}`);
		if (!row.assertions.exitNonZero) errors.push(`provider_failure_exit_not_failed:${row.caseId}`);
		if (!row.assertions.failureTextCaptured) errors.push(`provider_failure_text_missing:${row.caseId}`);
		if (!row.assertions.failureRepairLinked) errors.push(`provider_failure_repair_not_linked:${row.caseId}`);
		if (!row.assertions.noLiteralSecrets) errors.push(`provider_failure_literal_secret:${row.caseId}`);
		if (!row.assertions.noPiHomeImport) errors.push(`provider_failure_pi_home_leak:${row.caseId}`);
		if (!row.assertions.noUpdateBanner) errors.push(`provider_failure_update_banner_leak:${row.caseId}`);
		if (!report.failureLedgerEvents.some((failure) => failure.id === row.failureId))
			errors.push(`provider_failure_missing_failure_row:${row.caseId}`);
		if (
			!report.repairQueue.some(
				(repair) => repair.repairId === row.repairId && repair.fromFailureId === row.failureId,
			)
		)
			errors.push(`provider_failure_missing_repair_row:${row.caseId}`);
	}
	if (!report.failureRepairValidation.ok) errors.push("provider_failure_repair_validation_not_ok");
	if (report.failureRepairValidation.failureCount !== report.cases.length)
		errors.push("provider_failure_failure_count_mismatch");
	if (report.failureRepairValidation.repairCount < report.failureRepairValidation.failureCount)
		errors.push("provider_failure_repair_count_lt_failure_count");
	if (report.writebackProbe.status !== "pass" || !report.writebackProbe.validation.ok)
		errors.push("provider_failure_writeback_probe_not_pass");
	if (
		!report.failureLedgerEvents.some(
			(failure) => failure.status === "exhausted" && failure.retryBudget.remainingAttempts === 0,
		)
	)
		errors.push("provider_failure_exhausted_budget_missing");
	if (!report.repairQueue.some((repair) => repair.action === "escalate" && repair.paused))
		errors.push("provider_failure_exhausted_escalation_missing");
	return { ok: errors.length === 0, errors: uniqueNonEmpty(errors, 80) };
}

export function verifyRepairRollbackPolicyV1(report: RepiRepairRollbackPolicyV1): { ok: boolean; errors: string[] } {
	const errors: string[] = [];
	if (report.kind !== "RepairRollbackPolicyV1") errors.push("repair_rollback_kind_invalid");
	if (report.schemaVersion !== 1) errors.push("repair_rollback_schema_version_invalid");
	if (!report.baseline.treeSha256 || report.baseline.files.length === 0)
		errors.push("repair_rollback_baseline_missing");
	if (report.allowlist.length === 0) errors.push("repair_rollback_allowlist_missing");
	const allowlist = new Set(report.allowlist);
	for (const path of report.repair.changedFiles) {
		if (!allowlist.has(path)) errors.push(`repair_rollback_allowlist_violation:${path}`);
	}
	if (report.rollback.required !== true) errors.push("repair_rollback_required_missing");
	if (!report.rollback.restored) errors.push("repair_rollback_not_restored");
	if (report.rollback.restoredTreeSha256 !== report.baseline.treeSha256)
		errors.push("repair_rollback_tree_hash_mismatch");
	if (report.regression.checkpoints.length === 0) errors.push("repair_rollback_regression_check_missing");
	for (const checkpoint of report.regression.checkpoints) {
		if (checkpoint.status !== "pass") errors.push(`repair_rollback_regression_check_failed:${checkpoint.checkId}`);
	}
	if (report.regression.after !== "pass") errors.push("repair_rollback_after_regression_not_pass");
	if (report.regression.restored !== "pass") errors.push("repair_rollback_restored_regression_not_pass");
	if (!report.failureRepairValidation.ok) errors.push("repair_rollback_failure_repair_validation_not_ok");
	if (report.failureLedgerEvents.length < 1) errors.push("repair_rollback_failure_ledger_missing");
	if (
		!report.repairQueue.some(
			(repair) => repair.action === "rollback" && repair.rollbackCriteria.mustRestore.length > 0,
		)
	)
		errors.push("repair_rollback_queue_missing");
	if (!report.assertions.baselineCaptured) errors.push("repair_rollback_assertion_baseline_not_captured");
	if (!report.assertions.allowlistEnforced) errors.push("repair_rollback_assertion_allowlist_not_enforced");
	if (!report.assertions.rollbackRestored) errors.push("repair_rollback_assertion_not_restored");
	if (!report.assertions.regressionChecksPassed) errors.push("repair_rollback_assertion_regression_not_passed");
	if (!report.assertions.noUnrelatedFileChanges) errors.push("repair_rollback_assertion_unrelated_file_changes");
	if (!report.assertions.failureRepairLinked) errors.push("repair_rollback_assertion_failure_repair_not_linked");
	return { ok: errors.length === 0, errors: uniqueNonEmpty(errors, 80) };
}

export function verifyParallelProviderWorkerMatrixV1(report: RepiParallelProviderWorkerMatrixV1): {
	ok: boolean;
	errors: string[];
} {
	const errors: string[] = [];
	if (report.kind !== "ParallelProviderWorkerMatrixV1") errors.push("parallel_provider_worker_matrix_kind_invalid");
	if (!report.isolatedHome.includes(".repi") || report.isolatedHome.includes("/.pi/"))
		errors.push("parallel_provider_worker_matrix_isolated_home_invalid");
	if (report.workers.length < 4) errors.push("parallel_provider_worker_matrix_worker_count_lt_4");
	if (report.peakConcurrency < 2) errors.push("parallel_provider_worker_matrix_peak_concurrency_lt_2");
	if (report.peakConcurrency > report.maxConcurrency)
		errors.push("parallel_provider_worker_matrix_max_concurrency_exceeded");
	if (report.listModels.status !== "pass") errors.push("parallel_provider_worker_matrix_list_models_not_pass");
	const passingApis = new Set(report.workers.filter((worker) => worker.status === "pass").map((worker) => worker.api));
	if (!passingApis.has("openai-completions")) errors.push("parallel_provider_worker_matrix_openai_pass_missing");
	if (!passingApis.has("anthropic-messages")) errors.push("parallel_provider_worker_matrix_anthropic_pass_missing");
	for (const worker of report.workers) {
		if (!worker.providerName.startsWith("parallel-"))
			errors.push(`parallel_provider_worker_fixture_invalid:${worker.workerId}`);
		if (!worker.modelId.startsWith("parallel/"))
			errors.push(`parallel_provider_worker_model_invalid:${worker.workerId}`);
		if (!worker.assertions.childProcessLaunched)
			errors.push(`parallel_provider_worker_not_launched:${worker.workerId}`);
		if (!worker.assertions.requestSeen) errors.push(`parallel_provider_worker_request_missing:${worker.workerId}`);
		if (!worker.assertions.endpointMatched)
			errors.push(`parallel_provider_worker_endpoint_mismatch:${worker.workerId}`);
		if (!worker.assertions.modelMatched) errors.push(`parallel_provider_worker_model_mismatch:${worker.workerId}`);
		if (!worker.assertions.streamingUsed) errors.push(`parallel_provider_worker_stream_missing:${worker.workerId}`);
		if (!worker.assertions.successMarkerObserved)
			errors.push(`parallel_provider_worker_success_marker_missing:${worker.workerId}`);
		if (!worker.assertions.exitOkWhenExpected) errors.push(`parallel_provider_worker_exit_not_ok:${worker.workerId}`);
		if (!worker.assertions.exitFailedWhenExpected)
			errors.push(`parallel_provider_worker_exit_not_failed:${worker.workerId}`);
		if (!worker.assertions.timeoutCancelled)
			errors.push(`parallel_provider_worker_timeout_without_cancel:${worker.workerId}`);
		if (!worker.assertions.apiKeyEnvRefOnly)
			errors.push(`parallel_provider_worker_api_key_not_env_ref:${worker.workerId}`);
		if (!worker.assertions.authorizationFromEnv)
			errors.push(`parallel_provider_worker_authorization_not_env:${worker.workerId}`);
		if (!worker.assertions.requestLogCaptured || !worker.assertions.transcriptCaptured)
			errors.push(`parallel_provider_worker_artifact_missing:${worker.workerId}`);
		if (!worker.assertions.noLiteralSecrets)
			errors.push(`parallel_provider_worker_literal_secret:${worker.workerId}`);
		if (!worker.assertions.noPiHomeImport) errors.push(`parallel_provider_worker_pi_home_leak:${worker.workerId}`);
		if (!worker.assertions.noUpdateBanner) errors.push(`parallel_provider_worker_update_banner:${worker.workerId}`);
		if (
			worker.mode === "failure" &&
			(worker.status !== "repair_queued" ||
				!worker.failureId ||
				!worker.repairId ||
				!worker.assertions.providerWorkerFailureRepairLinked)
		)
			errors.push(`parallel_provider_worker_failure_repair_not_linked:${worker.workerId}`);
		if (worker.mode === "timeout" && (worker.status !== "cancelled" || !worker.timedOut || !worker.cancelledAt))
			errors.push(`parallel_provider_worker_cancelledWorker_missing:${worker.workerId}`);
	}
	const mergeKeyCounts = new Map<string, number>();
	for (const worker of report.workers)
		mergeKeyCounts.set(worker.mergeKey, (mergeKeyCounts.get(worker.mergeKey) ?? 0) + 1);
	const resolvedMergeKeys = new Set(
		report.claimMerge.conflicts
			.filter(
				(conflict) =>
					conflict.status === "resolved" && Boolean(conflict.winner) && conflict.evidenceRefs.length > 0,
			)
			.map((conflict) => conflict.mergeKey),
	);
	for (const [mergeKey, count] of mergeKeyCounts) {
		if (count > 1 && !resolvedMergeKeys.has(mergeKey))
			errors.push(`parallel_provider_worker_duplicate_mergeKey_unresolved:${mergeKey}`);
	}
	if (
		report.claimMerge.strategy !== "claim-aware provider worker merge" ||
		!report.claimMerge.claimAwareProviderWorkerMerge
	)
		errors.push("parallel_provider_worker_claimAwareProviderWorkerMerge_missing");
	if (!report.failureRepairValidation.ok) errors.push("parallel_provider_worker_failure_repair_validation_not_ok");
	if (report.writebackProbe.status !== "pass" || !report.writebackProbe.validation.ok)
		errors.push("parallel_provider_worker_writeback_probe_not_pass");
	if (
		!report.failureLedgerEvents.some(
			(failure) => failure.status === "exhausted" && failure.retryBudget.remainingAttempts === 0,
		)
	)
		errors.push("parallel_provider_worker_timeout_exhausted_failure_missing");
	if (!report.repairQueue.some((repair) => repair.action === "escalate" && repair.paused))
		errors.push("parallel_provider_worker_timeout_escalation_missing");
	return { ok: errors.length === 0, errors: uniqueNonEmpty(errors, 100) };
}

export function verifyRemoteProviderLongRunV1(report: RepiRemoteProviderLongRunV1): { ok: boolean; errors: string[] } {
	const errors: string[] = [];
	if (report.kind !== "RemoteProviderLongRunV1") errors.push("remote_provider_longrun_kind_invalid");
	if (report.mode === "skipped") {
		if (!report.skipReason) errors.push("remote_provider_longrun_skipped_without_reason");
		if (report.cases.length > 0) errors.push("remote_provider_longrun_skipped_with_cases");
		// remote_provider_longrun_optional_live_skip: no env in CI is a pass, not a false failure.
		return { ok: errors.length === 0, errors: uniqueNonEmpty(errors, 40) };
	}
	if (report.mode !== "live") errors.push("remote_provider_longrun_mode_invalid");
	if (!report.providerName) errors.push("remote_provider_longrun_provider_missing");
	if (!report.api || !["openai-completions", "openai-responses", "anthropic-messages"].includes(report.api))
		errors.push("remote_provider_longrun_api_invalid");
	if (!report.modelIdSha256 || !/^[a-f0-9]{64}$/.test(report.modelIdSha256))
		errors.push("remote_provider_longrun_model_hash_missing");
	if (!report.baseUrlSha256 || !/^[a-f0-9]{64}$/.test(report.baseUrlSha256))
		errors.push("remote_provider_longrun_base_url_hash_missing");
	if (!report.apiKeyEnv || !/^[A-Z_][A-Z0-9_]*$/.test(report.apiKeyEnv))
		errors.push("remote_provider_longrun_api_key_env_invalid");
	if (report.listModels.status !== "pass") errors.push("remote_provider_longrun_list_models_not_pass");
	if (report.cases.length < Math.max(1, report.attemptsPlanned))
		errors.push("remote_provider_longrun_case_count_lt_attempts");
	for (const row of report.cases) {
		if (row.status !== "pass") errors.push(`remote_provider_longrun_case_not_pass:${row.caseId}`);
		if (!row.assertions.exitOk) errors.push(`remote_provider_longrun_exit_not_ok:${row.caseId}`);
		if (!row.assertions.stdoutNonEmpty) errors.push(`remote_provider_longrun_stdout_empty:${row.caseId}`);
		if (!row.assertions.markerObserved) errors.push(`remote_provider_longrun_marker_missing:${row.caseId}`);
		if (!row.assertions.apiKeyEnvRefOnly) errors.push(`remote_provider_longrun_api_key_not_env_ref:${row.caseId}`);
		if (!row.assertions.boundedTimeout) errors.push(`remote_provider_longrun_unbounded_timeout:${row.caseId}`);
		if (!row.assertions.isolatedRepiHome) errors.push(`remote_provider_longrun_home_not_isolated:${row.caseId}`);
		if (!row.assertions.noLiteralSecrets) errors.push(`remote_provider_longrun_literal_secret:${row.caseId}`);
		if (!row.assertions.noPiHomeImport) errors.push(`remote_provider_longrun_pi_home_leak:${row.caseId}`);
		if (!row.assertions.noUpdateBanner) errors.push(`remote_provider_longrun_update_banner:${row.caseId}`);
		if (!row.assertions.transcriptCaptured) errors.push(`remote_provider_longrun_transcript_missing:${row.caseId}`);
	}
	if (report.failureLedgerEvents.length > 0 || report.repairQueue.length > 0) {
		if (!report.failureRepairValidation.ok) errors.push("remote_provider_longrun_failure_repair_validation_not_ok");
		if (report.writebackProbe.status !== "pass" || !report.writebackProbe.validation.ok)
			errors.push("remote_provider_longrun_writeback_probe_not_pass");
	}
	return { ok: errors.length === 0, errors: uniqueNonEmpty(errors, 100) };
}
