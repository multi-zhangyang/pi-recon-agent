import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

let root;
let redact;
let shortHash;
let shellQuote;
let noWrite;
let writePrivate;
let httpSecretHash;
let readSmallText;
let readJsonArtifact;
let collectDirectoryFiles;
let textLikeCloudFile;
let bufferSha256;

function configureCloudIdentityRuntime(runtime) {
	({ root, redact, shortHash, shellQuote, noWrite, writePrivate, httpSecretHash, readSmallText, readJsonArtifact, collectDirectoryFiles, textLikeCloudFile, bufferSha256 } = runtime);
}

function cloudIdentityPatterns() {
	return [
		{ category: "terraform-provider", pattern: /\bprovider\s+"(?:aws|azurerm|google|kubernetes|helm)"|\bterraform\s*\{/gi },
		{ category: "iam-surface", pattern: /\b(?:aws_iam_(?:role|policy|user|access_key|role_policy|policy_attachment)|azurerm_role_assignment|google_(?:service_account|project_iam)|serviceAccountName|ClusterRoleBinding|RoleBinding)\b/gi },
		{ category: "secret-surface", pattern: /\b(?:aws_access_key_id|aws_secret_access_key|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|client_secret|private_key|secretKeyRef|envFrom|kind:\s*Secret|data:|stringData:|secrets\.)\b/gi },
		{ category: "public-exposure", pattern: /\b(?:0\.0\.0\.0\/0|public-read|public_access|ingress|LoadBalancer|hostPort|NodePort|EXPOSE\s+\d+|--privileged)\b/gi },
		{ category: "container-risk", pattern: /\b(?:privileged:\s*true|hostNetwork:\s*true|hostPID:\s*true|hostPath:|runAsUser:\s*0|allowPrivilegeEscalation:\s*true|USER\s+root|curl\s+.*\|\s*(?:sh|bash)|wget\s+.*\|\s*(?:sh|bash))\b/gi },
		{ category: "ci-oidc", pattern: /\b(?:permissions:\s*id-token|id-token:\s*write|aws-actions\/configure-aws-credentials|azure\/login|google-github-actions\/auth|pull_request_target|GITHUB_TOKEN)\b/gi },
		{ category: "registry-image", pattern: /\b(?:image:\s*[^ \n]+|FROM\s+[^ \n]+|ECR|ACR|GCR|GHCR|imagePullSecrets)\b/gi },
	];
}

function lineNumberAt(text, index) {
	if (!Number.isFinite(index) || index <= 0) return 1;
	let line = 1;
	for (let cursor = 0; cursor < index && cursor < text.length; cursor++) {
		if (text.charCodeAt(cursor) === 10) line += 1;
	}
	return line;
}

function cloudPushUnique(list, row, keyFn, limit = 120) {
	const key = keyFn(row);
	if (!key || list.some((existing) => keyFn(existing) === key)) return;
	if (list.length < limit) list.push(row);
}

function cloudIdentityTrustChains(files) {
	const githubOidc = [];
	const terraformIam = [];
	const kubernetes = [];
	const containers = [];
	for (const entry of files.slice(0, 420)) {
		const text = readSmallText(entry.path, 240_000);
		if (!text) continue;
		const file = entry.name;
		const lower = file.toLowerCase();
		if (/\.github\/workflows\/|workflow|\.ya?ml$/i.test(file)) {
			const idToken = /id-token\s*:\s*write/i.test(text) || /permissions\s*:\s*id-token/i.test(text);
			const pullRequestTarget = /\bpull_request_target\b/i.test(text);
			for (const match of text.matchAll(/role-to-assume\s*:\s*["']?([^\s"'#]+)/gi)) {
				cloudPushUnique(
					githubOidc,
					{
						file,
						line: lineNumberAt(text, match.index ?? 0),
						provider: "github-actions",
						role: redact(match[1]),
						idToken,
						pullRequestTarget,
						risk: idToken && pullRequestTarget ? "oidc-from-pull-request-target" : idToken ? "oidc-role-assumption" : "workflow-role-reference",
					},
					(row) => `${row.file}:${row.role}:${row.risk}`,
				);
			}
			if (idToken && !githubOidc.some((row) => row.file === file)) {
				cloudPushUnique(
					githubOidc,
					{ file, line: lineNumberAt(text, text.search(/id-token/i)), provider: "github-actions", role: null, idToken, pullRequestTarget, risk: pullRequestTarget ? "oidc-from-pull-request-target" : "oidc-token-permission" },
					(row) => `${row.file}:${row.risk}`,
				);
			}
		}
		if (/\.tf$|terraform|terragrunt/i.test(lower)) {
			for (const match of text.matchAll(/resource\s+"aws_iam_(role|policy|role_policy|user|access_key)"\s+"([^"]+)"/gi)) {
				const blockStart = match.index ?? 0;
				const block = text.slice(blockStart, Math.min(text.length, blockStart + 3000));
				const wildcard = /Action["'\s:=]+["']?\*["']?|Resource["'\s:=]+["']?\*["']?|\bAction\s*=\s*"\*"|\bResource\s*=\s*"\*"/i.test(block);
				cloudPushUnique(
					terraformIam,
					{
						file,
						line: lineNumberAt(text, blockStart),
						resourceType: `aws_iam_${match[1]}`,
						name: redact(match[2]),
						wildcard,
						snippet: redact(block.split(/\r?\n/).slice(0, 5).join(" ").replace(/\s+/g, " ").slice(0, 260)),
					},
					(row) => `${row.file}:${row.resourceType}:${row.name}`,
				);
			}
		}
		if (/\.(?:ya?ml|json)$/i.test(file) || /k8s|kubernetes|helm/i.test(file)) {
			const serviceAccount = text.match(/\bserviceAccountName\s*:\s*([A-Za-z0-9._-]+)/i)?.[1];
			const image = text.match(/\bimage\s*:\s*([^\s#]+)/i)?.[1];
			const privileged = /\bprivileged\s*:\s*true\b/i.test(text);
			const hostNetwork = /\bhostNetwork\s*:\s*true\b/i.test(text);
			const hostPath = /\bhostPath\s*:/i.test(text);
			if (/kind\s*:\s*(?:Deployment|Pod|DaemonSet|StatefulSet|Job|CronJob)\b/i.test(text) && (serviceAccount || privileged || hostNetwork || hostPath || image)) {
				cloudPushUnique(
					kubernetes,
					{
						file,
						line: lineNumberAt(text, text.search(/kind\s*:/i)),
						kind: text.match(/kind\s*:\s*([A-Za-z]+)/i)?.[1] ?? "Workload",
						serviceAccount: serviceAccount ? redact(serviceAccount) : null,
						image: image ? redact(image) : null,
						privileged,
						hostNetwork,
						hostPath,
					},
					(row) => `${row.file}:${row.kind}:${row.serviceAccount ?? ""}:${row.image ?? ""}`,
				);
			}
			for (const match of text.matchAll(/kind\s*:\s*(ClusterRoleBinding|RoleBinding)\b/gi)) {
				const cursor = match.index ?? 0;
				const block = text.slice(cursor, Math.min(text.length, cursor + 1600));
				const name = block.match(/\bname\s*:\s*([A-Za-z0-9._-]+)/i)?.[1];
				cloudPushUnique(
					kubernetes,
					{
						file,
						line: lineNumberAt(text, cursor),
						kind: match[1],
						name: name ? redact(name) : null,
						clusterAdmin: /cluster-admin|system:masters|admin/i.test(block),
						privileged: false,
						hostNetwork: false,
						hostPath: false,
					},
					(row) => `${row.file}:${row.kind}:${row.name ?? ""}`,
				);
			}
		}
		if (/dockerfile|compose|\.ya?ml$/i.test(file)) {
			const rootUser = /\bUSER\s+root\b|user:\s*["']?0\b|user:\s*["']?root\b/i.test(text);
			const curlPipe = /\b(?:curl|wget)\b[^\n|]{0,160}\|\s*(?:sh|bash)\b/i.test(text);
			const privileged = /\bprivileged\s*:\s*true\b/i.test(text);
			const exposed = Array.from(text.matchAll(/\b(?:EXPOSE|ports:\s*-\s*)\s*["']?([0-9:./-]+)/gi)).map((match) => redact(match[1])).slice(0, 20);
			if (rootUser || curlPipe || privileged || exposed.length) {
				cloudPushUnique(
					containers,
					{
						file,
						line: lineNumberAt(text, text.search(/\b(?:USER|curl|wget|privileged|EXPOSE|ports:)/i)),
						rootUser,
						curlPipe,
						privileged,
						exposed,
					},
					(row) => `${row.file}:${row.rootUser}:${row.curlPipe}:${row.privileged}:${row.exposed.join(",")}`,
				);
			}
		}
	}
	const risks = [];
	if (githubOidc.some((row) => row.idToken && row.role)) risks.push("github-oidc-role-assumption-signal");
	if (githubOidc.some((row) => row.idToken && row.pullRequestTarget)) risks.push("github-oidc-pull-request-target-signal");
	if (terraformIam.some((row) => row.wildcard)) risks.push("terraform-wildcard-iam-policy-signal");
	if (kubernetes.some((row) => row.kind === "ClusterRoleBinding" || row.clusterAdmin)) risks.push("kubernetes-clusterrolebinding-signal");
	if (kubernetes.some((row) => row.serviceAccount && (row.privileged || row.hostNetwork || row.hostPath))) risks.push("kubernetes-privileged-service-account-signal");
	if (containers.some((row) => row.rootUser || row.curlPipe || row.privileged)) risks.push("container-build-runtime-risk-signal");
	return {
		githubOidc,
		terraformIam,
		kubernetes,
		containers,
		risks,
	};
}

function cloudIdentitySummary(target) {
	const files = collectDirectoryFiles(target, 5, 700).filter(textLikeCloudFile);
	const patterns = cloudIdentityPatterns();
	const findings = [];
	const perFile = new Map();
	for (const entry of files.slice(0, 420)) {
		const text = readSmallText(entry.path, 220_000);
		if (!text) continue;
		const lines = text.split(/\r?\n/);
		for (let lineIndex = 0; lineIndex < Math.min(lines.length, 2400); lineIndex++) {
			const line = lines[lineIndex];
			for (const spec of patterns) {
				spec.pattern.lastIndex = 0;
				if (!spec.pattern.test(line)) continue;
				const row = {
					file: entry.name,
					line: lineIndex + 1,
					category: spec.category,
					snippet: redact(line.trim().slice(0, 280)),
				};
				findings.push(row);
				const current = perFile.get(entry.name) ?? {};
				current[spec.category] = (current[spec.category] ?? 0) + 1;
				perFile.set(entry.name, current);
			}
			if (findings.length >= 500) break;
		}
		if (findings.length >= 500) break;
	}
	const categories = {};
	for (const finding of findings) categories[finding.category] = (categories[finding.category] ?? 0) + 1;
	const trustChains = cloudIdentityTrustChains(files);
	const risks = [];
	if (categories["secret-surface"]) risks.push("secret-or-credential-surface");
	if (categories["iam-surface"]) risks.push("iam-privilege-surface");
	if (categories["public-exposure"]) risks.push("public-network-exposure");
	if (categories["container-risk"]) risks.push("container-breakout-or-root-risk");
	if (categories["ci-oidc"]) risks.push("ci-oidc-deployment-trust-chain");
	if (categories["terraform-provider"] && categories["iam-surface"]) risks.push("terraform-identity-control-plane");
	risks.push(...trustChains.risks);
	return {
		kind: "repi-cloud-identity-map",
		schemaVersion: 2,
		fileCount: files.length,
		categories,
		risks,
		files: Array.from(perFile.entries())
			.slice(0, 120)
			.map(([file, counts]) => ({ file, counts })),
		trustChains,
		findings: findings.slice(0, 240),
	};
}

function cloudIdentityTrustClaims(summary) {
	const trustChains = summary.trustChains ?? {};
	const githubOidc = Array.isArray(trustChains.githubOidc) ? trustChains.githubOidc : [];
	const terraformIam = Array.isArray(trustChains.terraformIam) ? trustChains.terraformIam : [];
	const kubernetes = Array.isArray(trustChains.kubernetes) ? trustChains.kubernetes : [];
	const containers = Array.isArray(trustChains.containers) ? trustChains.containers : [];
	const findings = Array.isArray(summary.findings) ? summary.findings : [];
	const categories = summary.categories ?? {};
	const claimLedger = [];
	const observations = [];
	const addClaim = (claim) => {
		const normalized = {
			verdict: "promoted",
			confidence: 0.75,
			blockers: [],
			...claim,
		};
		claimLedger.push(normalized);
		if (normalized.verdict === "promoted") return;
		observations.push(normalized);
	};
	for (const row of githubOidc) {
		const rolePresent = Boolean(row.role);
		const promoted = Boolean(row.idToken && rolePresent);
		const pullRequestTarget = Boolean(row.pullRequestTarget);
		const claimType = promoted && pullRequestTarget ? "github-oidc-pull-request-target" : promoted ? "github-oidc-role-assumption" : "github-oidc-token-permission";
		addClaim({
			id: "cloud-" + claimType + "-" + shortHash(`${row.file}:${row.line}:${row.role ?? ""}:${row.risk ?? ""}`),
			claimType,
			sourceBinding: {
				file: row.file,
				line: row.line,
				provider: row.provider ?? "github-actions",
				role: row.role ?? null,
			},
			evidenceBinding: {
				idToken: Boolean(row.idToken),
				pullRequestTarget,
				rolePresent,
				risk: row.risk ?? null,
			},
			statement: promoted
				? "GitHub Actions workflow evidence binds id-token permission to a concrete cloud role assumption path."
				: "GitHub Actions workflow evidence exposes OIDC token permission but lacks a concrete role binding.",
			verdict: promoted ? "promoted" : "observation",
			confidence: promoted && pullRequestTarget ? 0.9 : promoted ? 0.82 : 0.58,
			blockers: promoted ? [] : ["missing-oidc-role"],
			rerunCommand: "cat cloud-identity-map.json | jq '.trustChains.githubOidc'",
		});
	}
	for (const row of terraformIam) {
		const wildcard = Boolean(row.wildcard);
		addClaim({
			id: "cloud-terraform-iam-" + shortHash(`${row.file}:${row.line}:${row.resourceType}:${row.name}:${wildcard}`),
			claimType: wildcard ? "terraform-wildcard-iam-policy" : "terraform-iam-principal",
			sourceBinding: {
				file: row.file,
				line: row.line,
				resourceType: row.resourceType,
				name: row.name,
			},
			evidenceBinding: {
				wildcard,
				snippet: row.snippet ?? null,
			},
			statement: wildcard
				? "Terraform IAM policy evidence contains wildcard Action or Resource material for privilege-boundary proof."
				: "Terraform IAM evidence identifies a control-plane principal that still needs permission expansion proof.",
			verdict: wildcard ? "promoted" : "observation",
			confidence: wildcard ? 0.86 : 0.6,
			blockers: wildcard ? [] : ["missing-iam-policy"],
			rerunCommand: "cat cloud-identity-map.json | jq '.trustChains.terraformIam'",
		});
	}
	for (const row of kubernetes) {
		const clusterAdmin = Boolean(row.clusterAdmin);
		const privilegedWorkload = Boolean(row.serviceAccount && (row.privileged || row.hostNetwork || row.hostPath));
		const promoted = clusterAdmin || privilegedWorkload;
		addClaim({
			id: "cloud-kubernetes-" + shortHash(`${row.file}:${row.line}:${row.kind}:${row.serviceAccount ?? row.name ?? ""}:${clusterAdmin}:${privilegedWorkload}`),
			claimType: clusterAdmin ? "kubernetes-cluster-admin-binding" : privilegedWorkload ? "kubernetes-privileged-service-account" : "kubernetes-workload-principal",
			sourceBinding: {
				file: row.file,
				line: row.line,
				kind: row.kind,
				serviceAccount: row.serviceAccount ?? null,
				name: row.name ?? null,
			},
			evidenceBinding: {
				clusterAdmin,
				privileged: Boolean(row.privileged),
				hostNetwork: Boolean(row.hostNetwork),
				hostPath: Boolean(row.hostPath),
				image: row.image ?? null,
			},
			statement: promoted
				? "Kubernetes manifest evidence binds a privileged workload or cluster-admin RBAC edge to a concrete principal."
				: "Kubernetes manifest evidence identifies a workload principal that needs privilege or RBAC expansion proof.",
			verdict: promoted ? "promoted" : "observation",
			confidence: clusterAdmin ? 0.88 : privilegedWorkload ? 0.84 : 0.58,
			blockers: promoted ? [] : ["missing-kubernetes-workload"],
			rerunCommand: "cat cloud-identity-map.json | jq '.trustChains.kubernetes'",
		});
	}
	for (const row of containers) {
		const runtimeRisk = Boolean(row.rootUser || row.curlPipe || row.privileged);
		addClaim({
			id: "cloud-container-runtime-" + shortHash(`${row.file}:${row.line}:${row.rootUser}:${row.curlPipe}:${row.privileged}:${(row.exposed ?? []).join(",")}`),
			claimType: runtimeRisk ? "container-build-runtime-risk" : "container-network-exposure",
			sourceBinding: {
				file: row.file,
				line: row.line,
			},
			evidenceBinding: {
				rootUser: Boolean(row.rootUser),
				curlPipe: Boolean(row.curlPipe),
				privileged: Boolean(row.privileged),
				exposed: Array.isArray(row.exposed) ? row.exposed : [],
			},
			statement: runtimeRisk
				? "Container build/runtime evidence exposes root execution, curl-pipe install, or privileged runtime configuration."
				: "Container evidence exposes network ports that still need runtime principal binding.",
			verdict: runtimeRisk ? "promoted" : "observation",
			confidence: runtimeRisk ? 0.78 : 0.55,
			blockers: runtimeRisk ? [] : ["missing-container-runtime"],
			rerunCommand: "cat cloud-identity-map.json | jq '.trustChains.containers'",
		});
	}
	const publicExposureFindings = findings.filter((row) => row.category === "public-exposure").slice(0, 12);
	for (const row of publicExposureFindings) {
		addClaim({
			id: "cloud-public-exposure-" + shortHash(`${row.file}:${row.line}:${row.snippet}`),
			claimType: "cloud-public-network-exposure",
			sourceBinding: {
				file: row.file,
				line: row.line,
				category: row.category,
			},
			evidenceBinding: {
				snippet: row.snippet,
			},
			statement: "Cloud/deployment evidence contains a public network exposure anchor that should be tied to an identity boundary.",
			verdict: "promoted",
			confidence: 0.72,
			blockers: [],
			rerunCommand: "cat cloud-identity-map.json | jq '.findings[] | select(.category==\"public-exposure\")'",
		});
	}
	const promotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted");
	const findPromoted = (typePattern) => promotedClaims.find((claim) => typePattern.test(claim.claimType));
	const oidcClaim = findPromoted(/^github-oidc-/);
	const iamClaim = findPromoted(/^terraform-wildcard-iam-policy$/);
	const kubeClaim = findPromoted(/^kubernetes-(?:privileged-service-account|cluster-admin-binding)$/);
	const containerClaim = findPromoted(/^container-build-runtime-risk$/);
	const publicClaim = findPromoted(/^cloud-public-network-exposure$/);
	const composedPaths = [];
	if (oidcClaim && iamClaim && (kubeClaim || containerClaim || publicClaim)) {
		const segments = [oidcClaim, iamClaim, kubeClaim, containerClaim, publicClaim].filter(Boolean);
		const composed = {
			id: "cloud-trust-chain-pivot-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "cloud-trust-chain-pivot",
			sourceBinding: {
				files: Array.from(new Set(segments.map((claim) => claim.sourceBinding?.file).filter(Boolean))),
				segments: segments.map((claim) => ({
					id: claim.id,
					claimType: claim.claimType,
					file: claim.sourceBinding?.file,
					line: claim.sourceBinding?.line,
				})),
			},
			evidenceBinding: {
				oidcRole: oidcClaim.sourceBinding?.role ?? null,
				iamWildcard: true,
				kubernetesPrincipal: kubeClaim?.sourceBinding?.serviceAccount ?? kubeClaim?.sourceBinding?.name ?? null,
				containerRuntimeRisk: Boolean(containerClaim),
				publicExposure: Boolean(publicClaim),
			},
			statement: "Static trust-chain evidence composes CI OIDC role assumption, Terraform wildcard IAM, and deployment/runtime exposure into one pivot candidate.",
			verdict: "promoted",
			confidence: kubeClaim && containerClaim ? 0.84 : 0.79,
			blockers: [],
			rerunCommand: "cat cloud-identity-trust-claims.json | jq '.composedPaths'",
		};
		composedPaths.push(composed);
		claimLedger.push(composed);
		promotedClaims.push(composed);
	}
	const blockers = [];
	if (!oidcClaim) blockers.push("missing-oidc-role");
	if (!iamClaim) blockers.push("missing-iam-policy");
	if (!kubeClaim) blockers.push("missing-kubernetes-workload");
	if (!containerClaim) blockers.push("missing-container-runtime");
	if (!publicClaim && !categories["public-exposure"]) blockers.push("missing-public-exposure");
	if (!oidcClaim && !kubeClaim) blockers.push("missing-principal-binding");
	const repairActions = {
		"missing-oidc-role": "Bind CI OIDC permissions to a concrete cloud role or provider trust policy before promoting the deployment pivot.",
		"missing-iam-policy": "Parse Terraform/provider state or IAM policy documents until wildcard or privilege-expanding permissions are source-bound.",
		"missing-kubernetes-workload": "Bind Kubernetes service accounts/RBAC to a workload and verify privileged, host, or cluster-admin expansion.",
		"missing-container-runtime": "Inspect Dockerfile/compose/runtime manifests for root, privileged, curl-pipe, exposed ports, or image provenance risk.",
		"missing-public-exposure": "Identify ingress, load balancers, NodePorts, security groups, or 0.0.0.0/0 rules and bind them to the principal chain.",
		"missing-principal-binding": "Correlate at least one CI/cloud principal with one runtime principal before claiming cross-plane reachability.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "cloud-identity-trust-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect source-bound cloud identity evidence and rerun claim promotion.",
		rerunCommand: "repi engage <cloud-stack-dir> --json",
	}));
	return {
		kind: "repi-cloud-identity-trust-claims",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		proofReady: promotedClaims.length > 0,
		claimLedger,
		composedPaths,
		promotionReport: {
			proofReady: promotedClaims.length > 0,
			promotedClaims,
			observations,
			blockers,
		},
		repairQueue,
	};
}

function cloudIdentitySourceLineCheck(target, claim) {
	const source = claim?.sourceBinding ?? {};
	const file = typeof source.file === "string" ? source.file : "";
	const line = Number(source.line);
	if (!file || !Number.isFinite(line) || line < 1) return undefined;
	const rootDir = resolve(target);
	const path = resolve(rootDir, file);
	if (path !== rootDir && !path.startsWith(`${rootDir}/`)) {
		return {
			claimId: claim.id ?? null,
			claimType: claim.claimType ?? null,
			file: redact(file),
			line,
			verified: false,
			error: "path-outside-target",
		};
	}
	if (!existsSync(path)) {
		return {
			claimId: claim.id ?? null,
			claimType: claim.claimType ?? null,
			file: redact(file),
			line,
			verified: false,
			error: "missing-source-file",
		};
	}
	let text = "";
	try {
		text = readFileSync(path, "utf8");
	} catch (error) {
		return {
			claimId: claim.id ?? null,
			claimType: claim.claimType ?? null,
			file: redact(file),
			line,
			verified: false,
			error: error instanceof Error ? redact(error.message) : "read-failed",
		};
	}
	const lines = text.split(/\r?\n/);
	const lineText = lines[line - 1] ?? "";
	const signalPatterns = {
		"github-oidc": /id-token|role-to-assume|pull_request_target|configure-aws-credentials|azure\/login|google-github-actions\/auth/i,
		"terraform-": /resource\s+"aws_iam_|Action\s*=|\bAction\b|Resource\s*=|\bResource\b|0\.0\.0\.0\/0|aws_security_group/i,
		"kubernetes-": /kind\s*:|serviceAccountName|ClusterRoleBinding|RoleBinding|privileged\s*:|hostNetwork\s*:|hostPath\s*:/i,
		"container-": /USER\s+root|curl\b|wget\b|privileged\s*:|EXPOSE|ports\s*:/i,
		"cloud-public": /0\.0\.0\.0\/0|public|public_access|public-read|ingress|LoadBalancer|NodePort|hostPort|EXPOSE|ports\s*:|privileged/i,
	};
	const matchedFamily = Object.entries(signalPatterns).find(([prefix]) => String(claim.claimType ?? "").startsWith(prefix));
	const semanticMatch = matchedFamily ? matchedFamily[1].test(lineText) : lineText.trim().length > 0;
	return {
		claimId: claim.id ?? null,
		claimType: claim.claimType ?? null,
		file: redact(file),
		line,
		verified: Boolean(lineText && semanticMatch),
		fileSha256: bufferSha256(readFileSync(path)),
		lineSha256: httpSecretHash(lineText),
		lineLength: lineText.length,
		semanticMatch,
	};
}

function cloudIdentityVerificationSummary(target, artifactDir, summary, trustClaims) {
	const map = summary ?? readJsonArtifact(join(artifactDir, "cloud-identity-map.json"));
	const claimsArtifact = trustClaims ?? readJsonArtifact(join(artifactDir, "cloud-identity-trust-claims.json"));
	const claimRows = claimsArtifact?.claimLedger ?? [];
	const promotedClaims = claimRows.filter((claim) => claim.verdict === "promoted" && claim.claimType !== "cloud-trust-chain-pivot");
	const sourceLineChecks = promotedClaims.map((claim) => cloudIdentitySourceLineCheck(target, claim)).filter(Boolean);
	const verifiedClaimIds = new Set(sourceLineChecks.filter((row) => row.verified).map((row) => row.claimId).filter(Boolean));
	const hasFamily = (pattern) => sourceLineChecks.some((row) => row.verified && pattern.test(String(row.claimType ?? "")));
	const missingFamilies = [];
	if (!hasFamily(/^github-oidc-/)) missingFamilies.push("github-oidc");
	if (!hasFamily(/^terraform-wildcard-iam-policy$/)) missingFamilies.push("terraform-wildcard-iam-policy");
	if (!sourceLineChecks.some((row) => row.verified && /^(?:kubernetes-|container-|cloud-public-network-exposure)/.test(String(row.claimType ?? "")))) missingFamilies.push("runtime-or-exposure");
	const sourceLineVerification = {
		verified: sourceLineChecks.length > 0 && sourceLineChecks.every((row) => row.verified),
		checkedClaims: sourceLineChecks.length,
		verifiedClaims: sourceLineChecks.filter((row) => row.verified).length,
		sourceFiles: Array.from(new Set(sourceLineChecks.filter((row) => row.verified).map((row) => row.file))).slice(0, 80),
	};
	const trustClaimCoverage = {
		verified: sourceLineVerification.verified && missingFamilies.length === 0,
		promotedSourceClaims: promotedClaims.length,
		verifiedSourceClaims: verifiedClaimIds.size,
		missingFamilies,
		risks: map?.risks ?? [],
		mapSha256: map ? httpSecretHash(JSON.stringify(map)) : null,
		claimsSha256: claimsArtifact ? httpSecretHash(JSON.stringify(claimsArtifact)) : null,
	};
	const claimById = new Map(claimRows.map((claim) => [claim.id, claim]));
	const pathRows = claimsArtifact?.composedPaths ?? [];
	const pathChecks = pathRows.map((pathRow) => {
		const segments = pathRow.sourceBinding?.segments ?? [];
		const resolvedSegments = segments.map((segment) => ({
			id: segment.id,
			claimType: segment.claimType,
			claimPresent: claimById.has(segment.id),
			sourceLineVerified: verifiedClaimIds.has(segment.id),
		}));
		return {
			id: pathRow.id ?? null,
			claimType: pathRow.claimType ?? null,
			verified: resolvedSegments.length > 0 && resolvedSegments.every((segment) => segment.claimPresent && segment.sourceLineVerified),
			segments: resolvedSegments,
		};
	});
	const composedPathVerification = {
		verified: pathChecks.some((row) => row.verified && row.claimType === "cloud-trust-chain-pivot"),
		pathCount: pathChecks.length,
		verifiedPathCount: pathChecks.filter((row) => row.verified).length,
		pathChecks,
	};
	const firstVerified = sourceLineChecks.find((row) => row.verified);
	const firstVerifiedPath = pathChecks.find((row) => row.verified);
	const negativeControls = [];
	if (firstVerified) {
		const missingClaim = cloudIdentitySourceLineCheck(target, {
			id: `${firstVerified.claimId}:missing-control`,
			claimType: firstVerified.claimType,
			sourceBinding: { file: `${firstVerified.file}.missing-control`, line: 1 },
		});
		negativeControls.push({
			controlType: "cloud-missing-file-negative-control",
			claimId: firstVerified.claimId,
			missingClaimVerified: Boolean(missingClaim?.verified),
			passed: Boolean(missingClaim && !missingClaim.verified),
		});
		const shifted = cloudIdentitySourceLineCheck(target, {
			id: `${firstVerified.claimId}:shifted-control`,
			claimType: firstVerified.claimType,
			sourceBinding: { file: firstVerified.file, line: firstVerified.line + 10000 },
		});
		negativeControls.push({
			controlType: "cloud-shifted-line-negative-control",
			claimId: firstVerified.claimId,
			passed: !shifted?.verified,
		});
		if (firstVerifiedPath) {
			const mutatedSegments = firstVerifiedPath.segments.map((segment, index) =>
				index === 0 ? { ...segment, id: `${segment.id}:negative-control-mutation` } : segment,
			);
			const mutatedPathVerified = mutatedSegments.every(
				(segment) => claimById.has(segment.id) && verifiedClaimIds.has(segment.id),
			);
			negativeControls.push({
				controlType: "cloud-mutated-segment-negative-control",
				claimId: firstVerifiedPath.id,
				mutatedPathVerified,
				passed: Boolean(!mutatedPathVerified),
			});
		}
	}
	const negativeControlVerification = {
		verified: negativeControls.length >= 3 && negativeControls.every((row) => row.passed),
		negativeControlsPassed: negativeControls.filter((row) => row.passed).length,
		negativeControls,
	};
	const claimLedger = [];
	const composedPaths = [];
	const addClaim = (claim) => {
		const normalized = { verdict: "promoted", confidence: 0.76, blockers: [], ...claim };
		claimLedger.push(normalized);
		return normalized;
	};
	const sourceClaim = sourceLineVerification.verified
		? addClaim({
				id: "cloud-source-line-verification-" + shortHash(sourceLineVerification.sourceFiles.join("|")),
				claimType: "cloud-source-line-verification-proof",
				sourceBinding: { artifact: "cloud-identity-verification.json", map: "cloud-identity-map.json", trustClaims: "cloud-identity-trust-claims.json" },
				evidenceBinding: sourceLineVerification,
				statement: "Cloud verifier rebound promoted identity claims to exact source files, lines, and hashes.",
				confidence: 0.86,
				rerunCommand: "python3 cloud-identity-verifier.py <cloud-stack-dir> cloud-identity-map.json cloud-identity-trust-claims.json cloud-identity-verification.json",
			})
		: undefined;
	const coverageClaim = trustClaimCoverage.verified
		? addClaim({
				id: "cloud-trust-claim-coverage-" + shortHash(JSON.stringify(trustClaimCoverage.missingFamilies)),
				claimType: "cloud-trust-claim-coverage-proof",
				sourceBinding: { artifact: "cloud-identity-verification.json", trustClaims: "cloud-identity-trust-claims.json" },
				evidenceBinding: trustClaimCoverage,
				statement: "Cloud verifier confirmed OIDC, IAM, and runtime/exposure trust-chain coverage.",
				confidence: 0.84,
				rerunCommand: "python3 cloud-identity-verifier.py <cloud-stack-dir> cloud-identity-map.json cloud-identity-trust-claims.json cloud-identity-verification.json",
			})
		: undefined;
	const pathClaim = composedPathVerification.verified
		? addClaim({
				id: "cloud-composed-path-verification-" + shortHash(JSON.stringify(composedPathVerification.pathChecks.map((row) => row.id))),
				claimType: "cloud-composed-path-verification-proof",
				sourceBinding: { artifact: "cloud-identity-verification.json", trustClaims: "cloud-identity-trust-claims.json" },
				evidenceBinding: composedPathVerification,
				statement: "Cloud verifier confirmed composed pivot segments resolve to source-bound promoted claims.",
				confidence: 0.86,
				rerunCommand: "python3 cloud-identity-verifier.py <cloud-stack-dir> cloud-identity-map.json cloud-identity-trust-claims.json cloud-identity-verification.json",
			})
		: undefined;
	const negativeClaim = negativeControlVerification.verified
		? addClaim({
				id: "cloud-verifier-negative-control-" + shortHash(JSON.stringify(negativeControlVerification.negativeControls)),
				claimType: "cloud-verifier-negative-control-proof",
				sourceBinding: { artifact: "cloud-identity-verification.json" },
				evidenceBinding: negativeControlVerification,
				statement: "Cloud verifier rejected missing-file, shifted-line, and mutated-segment controls.",
				confidence: 0.82,
				rerunCommand: "python3 cloud-identity-verifier.py <cloud-stack-dir> cloud-identity-map.json cloud-identity-trust-claims.json cloud-identity-verification.json",
			})
		: undefined;
	if (sourceClaim && coverageClaim && pathClaim && negativeClaim) {
		const segments = [sourceClaim, coverageClaim, pathClaim, negativeClaim];
		const composed = {
			id: "cloud-identity-verification-proof-path-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "cloud-identity-verification-proof-path",
			sourceBinding: { segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType, artifact: claim.sourceBinding?.artifact })) },
			evidenceBinding: {
				verifiedSourceClaims: sourceLineVerification.verifiedClaims,
				verifiedPathCount: composedPathVerification.verifiedPathCount,
				negativeControlsPassed: negativeControlVerification.negativeControlsPassed,
			},
			statement: "Cloud identity proof path composes source-line hashes, trust-chain coverage, composed path resolution, and negative controls.",
			verdict: "promoted",
			confidence: 0.88,
			blockers: [],
			rerunCommand: "python3 cloud-identity-verifier.py <cloud-stack-dir> cloud-identity-map.json cloud-identity-trust-claims.json cloud-identity-verification.json",
		};
		claimLedger.push(composed);
		composedPaths.push(composed);
	}
	const blockers = [];
	if (!sourceLineVerification.verified) blockers.push("missing-cloud-source-line-verification");
	if (!trustClaimCoverage.verified) blockers.push("missing-cloud-trust-claim-coverage");
	if (!composedPathVerification.verified) blockers.push("missing-cloud-composed-path-verification");
	if (!negativeControlVerification.verified) blockers.push("missing-cloud-negative-control");
	const repairActions = {
		"missing-cloud-source-line-verification": "Re-read source files and bind each promoted trust claim to exact file/line/hash evidence.",
		"missing-cloud-trust-claim-coverage": "Collect OIDC/IAM and runtime/exposure claims before promoting the cloud trust-chain.",
		"missing-cloud-composed-path-verification": "Require every composed pivot segment to resolve to a source-bound promoted claim.",
		"missing-cloud-negative-control": "Run missing-file, shifted-line, and mutated-segment controls before promotion.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "cloud-identity-verification-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect verifier-bound cloud identity evidence and rerun cloud-identity-verifier.py.",
		rerunCommand: `python3 ${shellQuote(join(artifactDir, "cloud-identity-verifier.py"))} ${shellQuote(target)} ${shellQuote(join(artifactDir, "cloud-identity-map.json"))} ${shellQuote(join(artifactDir, "cloud-identity-trust-claims.json"))} ${shellQuote(join(artifactDir, "cloud-identity-verification.json"))}`,
	}));
	const proofReady = composedPaths.length > 0;
	return {
		kind: "repi-cloud-identity-verification",
		schemaVersion: 1,
		target: redact(target),
		generatedAt: new Date().toISOString(),
		proofReady,
		unsafeProofReady: proofReady,
		sourceLineVerification,
		sourceLineChecks,
		trustClaimCoverage,
		composedPathVerification,
		negativeControlVerification,
		stats: {
			checkedClaims: sourceLineVerification.checkedClaims,
			verifiedClaims: sourceLineVerification.verifiedClaims,
			verifiedPathCount: composedPathVerification.verifiedPathCount,
			negativeControlsPassed: negativeControlVerification.negativeControlsPassed,
		},
		claimLedger,
		composedPaths,
		promotionReport: { proofReady, unsafeProofReady: proofReady, promotedClaims: claimLedger.filter((claim) => claim.verdict === "promoted"), blockers },
		repairQueue,
	};
}

function cloudIdentityVerifierSource() {
	return String.raw`#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import tempfile
import time

def sha256(value):
    if isinstance(value, str):
        value = value.encode("utf-8", "replace")
    return hashlib.sha256(value or b"").hexdigest()

def load(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)

def short(value):
    return sha256(str(value))[:12]

def source_line_check(root, claim):
    source = claim.get("sourceBinding") or {}
    rel = str(source.get("file") or "")
    try:
        line = int(source.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    if not rel or line < 1:
        return None
    root_abs = os.path.abspath(root)
    path = os.path.abspath(os.path.join(root_abs, rel))
    if path != root_abs and not path.startswith(root_abs + os.sep):
        return {"claimId": claim.get("id"), "claimType": claim.get("claimType"), "file": rel, "line": line, "verified": False, "error": "path-outside-target"}
    if not os.path.exists(path):
        return {"claimId": claim.get("id"), "claimType": claim.get("claimType"), "file": rel, "line": line, "verified": False, "error": "missing-source-file"}
    with open(path, "rb") as handle:
        raw = handle.read()
    text = raw.decode("utf-8", "replace")
    lines = re.split(r"\r?\n", text)
    line_text = lines[line - 1] if line - 1 < len(lines) else ""
    claim_type = str(claim.get("claimType") or "")
    patterns = [
        ("github-oidc", r"id-token|role-to-assume|pull_request_target|configure-aws-credentials|azure/login|google-github-actions/auth"),
        ("terraform-", r"resource\s+\"aws_iam_|Action\s*=|\bAction\b|Resource\s*=|\bResource\b|0\.0\.0\.0/0|aws_security_group"),
        ("kubernetes-", r"kind\s*:|serviceAccountName|ClusterRoleBinding|RoleBinding|privileged\s*:|hostNetwork\s*:|hostPath\s*:"),
        ("container-", r"USER\s+root|curl\b|wget\b|privileged\s*:|EXPOSE|ports\s*:"),
        ("cloud-public", r"0\.0\.0\.0/0|public|public_access|public-read|ingress|LoadBalancer|NodePort|hostPort|EXPOSE|ports\s*:|privileged"),
    ]
    semantic = bool(line_text.strip())
    for prefix, pattern in patterns:
        if claim_type.startswith(prefix):
            semantic = bool(re.search(pattern, line_text, re.I))
            break
    return {"claimId": claim.get("id"), "claimType": claim.get("claimType"), "file": rel, "line": line, "verified": bool(line_text and semantic), "fileSha256": sha256(raw), "lineSha256": sha256(line_text), "lineLength": len(line_text), "semanticMatch": semantic}

def add_claim(rows, **claim):
    row = {"verdict": "promoted", "confidence": 0.76, "blockers": []}
    row.update(claim)
    rows.append(row)
    return row

def verify(root, map_path, claims_path):
    cloud_map = load(map_path)
    trust = load(claims_path)
    claim_rows = trust.get("claimLedger") or []
    promoted = [claim for claim in claim_rows if claim.get("verdict") == "promoted" and claim.get("claimType") != "cloud-trust-chain-pivot"]
    checks = [row for row in (source_line_check(root, claim) for claim in promoted) if row]
    verified_ids = {row.get("claimId") for row in checks if row.get("verified") and row.get("claimId")}
    def has(pattern):
        return any(row.get("verified") and re.search(pattern, str(row.get("claimType") or "")) for row in checks)
    missing = []
    if not has(r"^github-oidc-"):
        missing.append("github-oidc")
    if not has(r"^terraform-wildcard-iam-policy$"):
        missing.append("terraform-wildcard-iam-policy")
    if not has(r"^(kubernetes-|container-|cloud-public-network-exposure)"):
        missing.append("runtime-or-exposure")
    source_line = {"verified": bool(checks) and all(row.get("verified") for row in checks), "checkedClaims": len(checks), "verifiedClaims": len(verified_ids), "sourceFiles": sorted({row.get("file") for row in checks if row.get("verified")})[:80]}
    coverage = {"verified": source_line["verified"] and not missing, "promotedSourceClaims": len(promoted), "verifiedSourceClaims": len(verified_ids), "missingFamilies": missing, "risks": cloud_map.get("risks") or [], "mapSha256": sha256(json.dumps(cloud_map, sort_keys=True)), "claimsSha256": sha256(json.dumps(trust, sort_keys=True))}
    by_id = {claim.get("id"): claim for claim in claim_rows}
    path_checks = []
    for path in trust.get("composedPaths") or []:
        segments = ((path.get("sourceBinding") or {}).get("segments") or [])
        resolved = [{"id": segment.get("id"), "claimType": segment.get("claimType"), "claimPresent": segment.get("id") in by_id, "sourceLineVerified": segment.get("id") in verified_ids} for segment in segments]
        path_checks.append({"id": path.get("id"), "claimType": path.get("claimType"), "verified": bool(resolved) and all(row["claimPresent"] and row["sourceLineVerified"] for row in resolved), "segments": resolved})
    path_verification = {"verified": any(row.get("verified") and row.get("claimType") == "cloud-trust-chain-pivot" for row in path_checks), "pathCount": len(path_checks), "verifiedPathCount": len([row for row in path_checks if row.get("verified")]), "pathChecks": path_checks}
    controls = []
    first = next((row for row in checks if row.get("verified")), None)
    first_path = next((row for row in path_checks if row.get("verified")), None)
    if first:
        missing_control = source_line_check(root, {"id": str(first.get("claimId")) + ":missing-control", "claimType": first.get("claimType"), "sourceBinding": {"file": str(first.get("file")) + ".missing-control", "line": 1}})
        controls.append({"controlType": "cloud-missing-file-negative-control", "claimId": first.get("claimId"), "missingClaimVerified": bool(missing_control and missing_control.get("verified")), "passed": bool(missing_control) and not missing_control.get("verified")})
        shifted = source_line_check(root, {"id": str(first.get("claimId")) + ":shifted-control", "claimType": first.get("claimType"), "sourceBinding": {"file": first.get("file"), "line": int(first.get("line")) + 10000}})
        controls.append({"controlType": "cloud-shifted-line-negative-control", "claimId": first.get("claimId"), "passed": not (shifted and shifted.get("verified"))})
        if first_path:
            mutated_segments = [dict(segment, id=str(segment.get("id")) + ":negative-control-mutation") if index == 0 else dict(segment) for index, segment in enumerate(first_path.get("segments") or [])]
            mutated_path_verified = bool(mutated_segments) and all(segment.get("id") in by_id and segment.get("id") in verified_ids for segment in mutated_segments)
            controls.append({"controlType": "cloud-mutated-segment-negative-control", "claimId": first_path.get("id"), "mutatedPathVerified": mutated_path_verified, "passed": not mutated_path_verified})
    negative = {"verified": len(controls) >= 3 and all(row.get("passed") for row in controls), "negativeControlsPassed": len([row for row in controls if row.get("passed")]), "negativeControls": controls}
    ledger = []
    paths = []
    source_claim = add_claim(ledger, id="cloud-source-line-verification-" + short("|".join(source_line.get("sourceFiles") or [])), claimType="cloud-source-line-verification-proof", sourceBinding={"artifact": "cloud-identity-verification.json", "map": "cloud-identity-map.json", "trustClaims": "cloud-identity-trust-claims.json"}, evidenceBinding=source_line, statement="Cloud verifier rebound promoted identity claims to exact source files, lines, and hashes.", confidence=0.86, rerunCommand="python3 cloud-identity-verifier.py <cloud-stack-dir> cloud-identity-map.json cloud-identity-trust-claims.json cloud-identity-verification.json") if source_line["verified"] else None
    coverage_claim = add_claim(ledger, id="cloud-trust-claim-coverage-" + short(json.dumps(missing, sort_keys=True)), claimType="cloud-trust-claim-coverage-proof", sourceBinding={"artifact": "cloud-identity-verification.json", "trustClaims": "cloud-identity-trust-claims.json"}, evidenceBinding=coverage, statement="Cloud verifier confirmed OIDC, IAM, and runtime/exposure trust-chain coverage.", confidence=0.84, rerunCommand="python3 cloud-identity-verifier.py <cloud-stack-dir> cloud-identity-map.json cloud-identity-trust-claims.json cloud-identity-verification.json") if coverage["verified"] else None
    path_claim = add_claim(ledger, id="cloud-composed-path-verification-" + short(json.dumps([row.get("id") for row in path_checks], sort_keys=True)), claimType="cloud-composed-path-verification-proof", sourceBinding={"artifact": "cloud-identity-verification.json", "trustClaims": "cloud-identity-trust-claims.json"}, evidenceBinding=path_verification, statement="Cloud verifier confirmed composed pivot segments resolve to source-bound promoted claims.", confidence=0.86, rerunCommand="python3 cloud-identity-verifier.py <cloud-stack-dir> cloud-identity-map.json cloud-identity-trust-claims.json cloud-identity-verification.json") if path_verification["verified"] else None
    negative_claim = add_claim(ledger, id="cloud-verifier-negative-control-" + short(json.dumps(controls, sort_keys=True)), claimType="cloud-verifier-negative-control-proof", sourceBinding={"artifact": "cloud-identity-verification.json"}, evidenceBinding=negative, statement="Cloud verifier rejected missing-file, shifted-line, and mutated-segment controls.", confidence=0.82, rerunCommand="python3 cloud-identity-verifier.py <cloud-stack-dir> cloud-identity-map.json cloud-identity-trust-claims.json cloud-identity-verification.json") if negative["verified"] else None
    if source_claim and coverage_claim and path_claim and negative_claim:
        segments = [source_claim, coverage_claim, path_claim, negative_claim]
        composed = {"id": "cloud-identity-verification-proof-path-" + short(">".join([claim["id"] for claim in segments])), "claimType": "cloud-identity-verification-proof-path", "sourceBinding": {"segments": [{"id": claim["id"], "claimType": claim["claimType"], "artifact": claim.get("sourceBinding", {}).get("artifact")} for claim in segments]}, "evidenceBinding": {"verifiedSourceClaims": source_line["verifiedClaims"], "verifiedPathCount": path_verification["verifiedPathCount"], "negativeControlsPassed": negative["negativeControlsPassed"]}, "statement": "Cloud identity proof path composes source-line hashes, trust-chain coverage, composed path resolution, and negative controls.", "verdict": "promoted", "confidence": 0.88, "blockers": [], "rerunCommand": "python3 cloud-identity-verifier.py <cloud-stack-dir> cloud-identity-map.json cloud-identity-trust-claims.json cloud-identity-verification.json"}
        ledger.append(composed)
        paths.append(composed)
    blockers = []
    if not source_line["verified"]:
        blockers.append("missing-cloud-source-line-verification")
    if not coverage["verified"]:
        blockers.append("missing-cloud-trust-claim-coverage")
    if not path_verification["verified"]:
        blockers.append("missing-cloud-composed-path-verification")
    if not negative["verified"]:
        blockers.append("missing-cloud-negative-control")
    proof_ready = bool(paths)
    return {"kind": "repi-cloud-identity-verification", "schemaVersion": 1, "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "proofReady": proof_ready, "unsafeProofReady": proof_ready, "sourceLineVerification": source_line, "sourceLineChecks": checks, "trustClaimCoverage": coverage, "composedPathVerification": path_verification, "negativeControlVerification": negative, "stats": {"checkedClaims": source_line["checkedClaims"], "verifiedClaims": source_line["verifiedClaims"], "verifiedPathCount": path_verification["verifiedPathCount"], "negativeControlsPassed": negative["negativeControlsPassed"]}, "claimLedger": ledger, "composedPaths": paths, "promotionReport": {"proofReady": proof_ready, "unsafeProofReady": proof_ready, "promotedClaims": ledger, "blockers": blockers}, "repairQueue": [{"id": "cloud-identity-verification-" + blocker, "blocker": blocker, "action": "Collect verifier-bound cloud identity evidence and rerun cloud-identity-verifier.py.", "rerunCommand": "python3 cloud-identity-verifier.py <cloud-stack-dir> cloud-identity-map.json cloud-identity-trust-claims.json cloud-identity-verification.json"} for blocker in blockers]}

def self_test():
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, ".github", "workflows"), exist_ok=True)
        os.makedirs(os.path.join(root, "k8s"), exist_ok=True)
        workflow = ".github/workflows/deploy.yml"
        tf = "main.tf"
        k8s = "k8s/deploy.yaml"
        docker = "Dockerfile"
        with open(os.path.join(root, workflow), "w", encoding="utf-8") as handle:
            handle.write("permissions:\n  id-token: write\non: pull_request_target\njobs:\n  deploy:\n    steps:\n      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n          role-to-assume: arn:aws:iam::123456789012:role/deploy\n")
        with open(os.path.join(root, tf), "w", encoding="utf-8") as handle:
            handle.write("resource \"aws_iam_policy\" \"admin\" { policy = jsonencode({ Statement = [{ Action = \"*\", Resource = \"*\" }] }) }\n")
        with open(os.path.join(root, k8s), "w", encoding="utf-8") as handle:
            handle.write("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      serviceAccountName: admin\n      hostNetwork: true\n")
        with open(os.path.join(root, docker), "w", encoding="utf-8") as handle:
            handle.write("FROM node:22\nUSER root\nRUN curl https://example.test/install.sh | sh\nEXPOSE 8080\n")
        map_path = os.path.join(root, "cloud-identity-map.json")
        claims_path = os.path.join(root, "cloud-identity-trust-claims.json")
        map_doc = {"risks": ["github-oidc-role-assumption-signal", "terraform-wildcard-iam-policy-signal", "container-build-runtime-risk-signal"]}
        claims = [
            {"id": "oidc", "claimType": "github-oidc-pull-request-target", "verdict": "promoted", "sourceBinding": {"file": workflow, "line": 9}},
            {"id": "iam", "claimType": "terraform-wildcard-iam-policy", "verdict": "promoted", "sourceBinding": {"file": tf, "line": 1}},
            {"id": "kube", "claimType": "kubernetes-privileged-service-account", "verdict": "promoted", "sourceBinding": {"file": k8s, "line": 2}},
            {"id": "container", "claimType": "container-build-runtime-risk", "verdict": "promoted", "sourceBinding": {"file": docker, "line": 2}},
        ]
        path = {"id": "cloud-trust-chain-pivot-selftest", "claimType": "cloud-trust-chain-pivot", "verdict": "promoted", "sourceBinding": {"segments": [{"id": row["id"], "claimType": row["claimType"]} for row in claims]}}
        with open(map_path, "w", encoding="utf-8") as handle:
            json.dump(map_doc, handle)
        with open(claims_path, "w", encoding="utf-8") as handle:
            json.dump({"claimLedger": claims + [path], "composedPaths": [path]}, handle)
        result = verify(root, map_path, claims_path)
        assert result["proofReady"], json.dumps(result, sort_keys=True)
        print(json.dumps({"kind": "repi-cloud-identity-verifier-self-test", "status": "ok", "stats": result["stats"]}, sort_keys=True))

def main():
    parser = argparse.ArgumentParser(description="Verify REPI cloud identity trust claims against exact source lines and negative controls.")
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("map", nargs="?", default="cloud-identity-map.json")
    parser.add_argument("claims", nargs="?", default="cloud-identity-trust-claims.json")
    parser.add_argument("output", nargs="?", default="cloud-identity-verification.json")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    result = verify(args.root, args.map, args.claims)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"kind": result["kind"], "proofReady": result["proofReady"], "stats": result["stats"], "output": args.output}, sort_keys=True))
    return 0 if result["proofReady"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
`;
}

function writeCloudIdentityVerifier(artifactDir) {
	if (noWrite || !artifactDir) return undefined;
	const path = join(artifactDir, "cloud-identity-verifier.py");
	writePrivate(path, cloudIdentityVerifierSource(), 0o700);
	return path;
}

function writeCloudIdentityVerification(artifactDir, target, summary, trustClaims) {
	if (noWrite || !artifactDir) return undefined;
	const verification = cloudIdentityVerificationSummary(target, artifactDir, summary, trustClaims);
	const path = join(artifactDir, "cloud-identity-verification.json");
	writePrivate(path, `${JSON.stringify(verification, null, 2)}\n`, 0o600);
	return { path, summary: verification };
}

function cloudIdentityVerifyPlanSource() {
	return `#!/usr/bin/env bash
set -euo pipefail

ROOT=\${1:-.}
OUT=\${2:-cloud-identity-verify}
mkdir -p "$OUT"/{terraform,kubernetes,containers,ci,logs}
printf '[repi-cloud] root=%s out=%s\\n' "$ROOT" "$OUT" | tee "$OUT/logs/plan.log"

if command -v terraform >/dev/null 2>&1 && find "$ROOT" -name '*.tf' -print -quit | grep -q .; then
  (cd "$ROOT" && terraform init -backend=false -input=false >/dev/null 2>&1 || true)
  (cd "$ROOT" && terraform validate -no-color > "$OUT/terraform/validate.txt" 2>&1 || true)
  (cd "$ROOT" && terraform providers > "$OUT/terraform/providers.txt" 2>&1 || true)
else
  printf '[repi-cloud] terraform=missing-or-no-tf\\n' | tee -a "$OUT/logs/plan.log"
fi

if command -v kubectl >/dev/null 2>&1; then
  find "$ROOT" -type f \\( -name '*.yaml' -o -name '*.yml' \\) -print0 | xargs -0 -r -I{} sh -c 'kubectl apply --dry-run=client -f "$1" > "$2/kubernetes/$(basename "$1").dryrun.txt" 2>&1 || true' sh {} "$OUT"
else
  printf '[repi-cloud] kubectl=missing\\n' | tee -a "$OUT/logs/plan.log"
fi

find "$ROOT" -type f \\( -iname 'Dockerfile' -o -name 'docker-compose.yml' -o -name 'compose.yaml' \\) -print > "$OUT/containers/files.txt" || true
grep -RInE 'privileged: true|hostNetwork: true|hostPath:|runAsUser: 0|USER root|0\\.0\\.0\\.0/0|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|client_secret|private_key|pull_request_target|id-token: write' "$ROOT" > "$OUT/high-risk-grep.txt" 2>/dev/null || true

cat > "$OUT/next.txt" <<'EOF'
1. Bind deployment truth: Terraform state/backend, GitHub Actions OIDC role, Kubernetes service account, and container runtime identity.
2. Verify whether public network exposure reaches privileged workloads or metadata services.
3. Treat secret findings as leads until tied to a file, workflow, state, or runtime principal.
4. Produce one least-privilege delta or exploit replay path with exact resource identifiers.
EOF
`;
}

export function cloudIdentityRows(target, artifactDir, runtime) {
	configureCloudIdentityRuntime(runtime);
	try {
		const summary = cloudIdentitySummary(target);
		const trustClaims = cloudIdentityTrustClaims(summary);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "cloud-identity-map.json"), `${JSON.stringify(summary, null, 2)}\n`);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "cloud-identity-trust-claims.json"), `${JSON.stringify(trustClaims, null, 2)}\n`);
		const rows = [
			{
				id: "cloud-identity-map",
				command: "internal",
				args: [redact(target)],
				cwd: root,
				exit: summary.findings.length ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(summary, null, 2)}\n`,
				stderr: "",
				error: summary.findings.length ? undefined : "no cloud identity findings",
			},
			{
				id: "cloud-identity-trust-claims",
				command: "internal",
				args: [redact(target)],
				cwd: root,
				exit: trustClaims.proofReady ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(trustClaims, null, 2)}\n`,
				stderr: "",
				error: trustClaims.proofReady ? undefined : "no cloud identity trust claims promoted",
			},
		];
		if (!noWrite && artifactDir) {
			const planPath = join(artifactDir, "cloud-identity-verify.sh");
			writePrivate(planPath, cloudIdentityVerifyPlanSource(), 0o700);
			const verifierPath = writeCloudIdentityVerifier(artifactDir);
			if (verifierPath) {
				rows.push({
					id: "cloud-identity-verifier-artifact",
					command: "internal",
					args: [redact(verifierPath)],
					cwd: root,
					exit: 0,
					signal: null,
					durationMs: 0,
					stdout: `verifier=${redact(verifierPath)}\nrun=python3 ${redact(verifierPath)} ${redact(target)} ${redact(join(artifactDir, "cloud-identity-map.json"))} ${redact(join(artifactDir, "cloud-identity-trust-claims.json"))} ${redact(join(artifactDir, "cloud-identity-verification.json"))}\n`,
					stderr: "",
					error: undefined,
				});
			}
			const verification = writeCloudIdentityVerification(artifactDir, target, summary, trustClaims);
			if (verification) {
				rows.push({
					id: "cloud-identity-verification",
					command: "internal",
					args: [redact(verification.path)],
					cwd: root,
					exit: verification.summary.proofReady ? 0 : 1,
					signal: null,
					durationMs: 0,
					stdout: `${JSON.stringify(verification.summary, null, 2)}\n`,
					stderr: "",
					error: verification.summary.proofReady ? undefined : "cloud identity verification blockers present",
				});
			}
			rows.push({
				id: "cloud-identity-verify-artifact",
				command: "internal",
				args: [redact(planPath)],
				cwd: root,
				exit: 0,
				signal: null,
				durationMs: 0,
				stdout: `plan=${redact(planPath)}\nrun=bash ${redact(planPath)} ${redact(target)}\n`,
				stderr: "",
				error: undefined,
			});
		}
		return rows;
	} catch (error) {
		return [{ id: "cloud-identity-map", command: "internal", args: [redact(target)], cwd: root, exit: 1, signal: null, durationMs: 0, stdout: "", stderr: error instanceof Error ? error.message : String(error), error: error instanceof Error ? error.message : String(error) }];
	}
}
