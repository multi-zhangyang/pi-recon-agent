# Containerization

REPI runs with all permissions by default, but in some cases, you will want to have more control over what directories REPI can write to and which accesses it has.

There are two general options. You can either
1. run the whole `repi` process inside an isolated environment, or
2. run `repi` on the host and route tool execution into an isolated environment.

## Choose a pattern

| Pattern | What is isolated | Best for | Notes |
| --- | --- | --- | --- |
| OpenShell | Whole `repi` process in a policy-controlled sandbox | Local or remote managed sandbox | Requires an OpenShell gateway |
| Gondolin extension | Built-in tools and `!` commands | Local micro-VM isolation while keeping auth on host | See [`examples/extensions/gondolin/`](../examples/extensions/gondolin/). |
| Plain Docker | Whole `repi` process in a local container | Simple local isolation | Provider API keys enter the container. |

Extensions run wherever the `repi` process runs. If you run host `repi` with a tool-routing extension, other custom extension tools still run on the host unless they also delegate their operations.

## OpenShell

Use [NVIDIA OpenShell](https://docs.nvidia.com/openshell/about/overview) when you want a policy-controlled sandbox with filesystem, process, network, credential, and inference controls.
OpenShell can run sandboxes through a local gateway backed by Docker, Podman, or a VM runtime, or through a remote Kubernetes gateway.

Every sandbox requires an active gateway.
Register and select one before creating a sandbox:

```bash
openshell gateway add <gateway-url> --name <name>
openshell gateway select <name>
```

Launch `repi` inside an OpenShell sandbox:

```bash
openshell sandbox create --name repi-sandbox --from repi -- repi
```

In this pattern, the whole `repi` process runs inside the sandbox.
Built-in tools, `!` commands, and extension tools execute inside the OpenShell boundary.

If the gateway is remote, project files are not bind-mounted from the host, meaning writes in the sandbox are not reflected on your machine.
Clone the repository inside the sandbox or use OpenShell file transfer commands:

```bash
openshell sandbox upload repi-sandbox ./repo /workspace
openshell sandbox download repi-sandbox /workspace/repo ./repo-out
```

OpenShell providers can keep raw model API keys outside the sandbox.
When inference routing is configured, code inside the sandbox can call `https://inference.local`, and the gateway injects the configured provider credentials upstream.
Configure REPI to use the corresponding OpenAI-compatible or Anthropic-compatible endpoint if you want model traffic to use this route.

## Gondolin

[Gondolin](https://github.com/earendil-works/gondolin) is a local Linux micro-VM.
Use the [example extension](../examples/extensions/gondolin) when you want `repi` on the host but all built-in tools routed into the VM.

Setup:

```bash
cp -R packages/coding-agent/examples/extensions/gondolin ~/.repi/agent/extensions/gondolin
cd ~/.repi/agent/extensions/gondolin
npm install --ignore-scripts
```

Run from the project you want mounted:

```bash
cd /path/to/project
repi -e ~/.repi/agent/extensions/gondolin
```

The extension mounts the host cwd at `/workspace` in the VM and overrides `read`, `write`, `edit`, `bash`, `grep`, `find`, and `ls`.
User `!` commands are routed into the VM, as well.
File changes under `/workspace` write through to the host.

Requirements: Node.js >= 23.6.0 for `@earendil-works/gondolin`, plus QEMU (requires installation through your package manager).

## Plain Docker

Run the whole `repi` process in Docker when you want the simplest local container boundary.

`Dockerfile.repi` for source installs:

```dockerfile
FROM node:24-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends bash ca-certificates git ripgrep \
  && rm -rf /var/lib/apt/lists/*

ARG REPI_REPO=https://github.com/multi-zhangyang/pi-recon-agent.git
RUN git clone "$REPI_REPO" /opt/pi-recon-agent \
  && cd /opt/pi-recon-agent \
  && npm ci --ignore-scripts \
  && npm run install:repi

WORKDIR /workspace
ENTRYPOINT ["repi"]
```

For a tarball-based image, put the four files from one GitHub Release beside the Dockerfile. They must be installed by one command because the internal packages are not published to the npm registry:

```dockerfile
COPY pi-recon-repi-*.tgz /tmp/repi-release/
RUN npm install -g /tmp/repi-release/*.tgz \
  && rm -rf /tmp/repi-release
```

Build and run:

```bash
docker build -t repi-sandbox -f Dockerfile.repi .

docker run --rm -it \
  -e ANTHROPIC_API_KEY \
  -v "$PWD:/workspace" \
  -v repi-agent-home:/root/.repi/agent \
  repi-sandbox
```

The `-v "$PWD:/workspace"` mounts your current directory into the container at /workspace such that reads and writes in `/workspace` inside Docker directly affect your host files, like in the Gondolin example.

Use a named volume for `/root/.repi/agent` if you want container-local settings and sessions. Mounting your host `~/.repi/agent` exposes host auth and session files to the container.
