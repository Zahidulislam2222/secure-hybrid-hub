# Future scalability: path toward 1M+ simultaneous users

**Proposed engineering target, not a benchmark.** The current local broker is not
a million-user server. This plan describes an optional distributed open-source
deployment and the evidence needed to reach that scale. Operators choose their
own infrastructure; paid services or load generators require separate approval.

## Define the workload before selecting infrastructure

Track registered users, simultaneously connected sessions, active UI requests,
job submissions, running AI jobs and streaming subscribers separately. A million
idle connections and a million concurrent model generations have very different
CPU, memory, bandwidth, provider-quota and cost requirements.

The following is an **illustrative planning scenario**, not a capacity promise:

| Input | Assumption |
|---|---|
| Connected users | 1,000,000 |
| Active status viewers | 10% of connected users |
| Status refresh equivalent | One request per active viewer per 10 seconds |
| Task submitters | 1% of connected users submit once per 10 minutes |
| Mean job duration | 120 seconds, including approved model work |
| Encoded status event | 1 KiB before protocol overhead |

Derived baseline:

- Status traffic: `1,000,000 × 0.10 / 10 = 10,000 requests/second`.
- Job arrivals: `1,000,000 × 0.01 / 600 ≈ 16.7 jobs/second`.
- Mean in-flight jobs: `16.7 × 120 ≈ 2,000`, using steady-state Little's Law.
- Event payload: `10,000 × 1 KiB ≈ 9.77 MiB/second`, before fan-out, headers,
  retries, replication, TLS and bursts.
- Connection memory must be measured. At an assumed 32 KiB per connection,
  connections alone consume about 30.5 GiB across the gateway fleet; application,
  kernel, TLS and buffered data can raise this substantially.

These assumptions must be replaced by an approved representative workload.
Doubling mean job duration doubles in-flight work at unchanged arrival rate.
Token throughput and provider quotas may dominate well before API CPU saturates.

## Capacity model

For each tier measure safe per-instance throughput at the latency/error target.
If a measured instance sustains `q` requests/second, selected utilization is `u`,
and demand is `r`, estimate `ceil(r / (q × u))` instances, then add capacity for
the specified failure domain. Do not double-count headroom if `q` already embeds
the utilization cap. Benchmark realistic tenant skew and expensive operations.

Measure connection count, event fan-out, task arrivals, worker-slot occupancy,
tokens/second, database contention, object throughput and queue age independently.
Record peak and sustained values. A connection benchmark alone does not pass
the end-to-end million-user target.

## Proposed topology and controls

| Tier | Scaling approach | Failure protection |
|---|---|---|
| Static frontend | Replicated static origin and optional CDN | Versioned assets, independent origin recovery |
| Connections | Horizontally partitioned event gateways | Bounded buffers, backpressure, reconnect jitter |
| Control API | Stateless replicas within regional cells | Per-tenant quotas and admission limits |
| Metadata | Transactional store, tenant partitioning when measured necessary | Backups, replica failover, migration and split-brain tests |
| Queue | Durable partitioned queues and explicit priorities | Bounded backlog, deduplication, poison-job quarantine |
| Workers | Isolated pools by trust class and resource need | Fencing, cancellation, resource ceilings, tenant fairness |
| Artifacts | Scoped object storage and lifecycle policies | Digest checks, integrity verification, authorization |
| Providers | Approved endpoint/account budgets | Circuit breaking, quota-aware admission, explicit fallback consent |

Route a tenant to its home cell with a bounded maximum tenant count/load per cell.
Scale by adding cells after proving isolation and migration. Do not let shared
control metadata become a global lock for every job. Keep data in approved regions;
cross-region failover must preserve residency and authorization constraints.

Prefer bounded queues over unlimited acceptance. Shed excess work predictably
with a retryable response and retry guidance. Reserve capacity for cancellation,
status, audit and incident controls. Read
[Amazon's load-shedding guidance](https://aws.amazon.com/builders-library/using-load-shedding-to-avoid-overload/)
for overload failure modes; specific architecture here is a project proposal.

## Benchmark stages and exit gates

| Stage | Connected-user target | Required evidence before progression |
|---|---|---|
| Local baseline | One operator; bounded synthetic jobs | Correctness, isolation, cancellation and crash recovery |
| Team pilot | 100 | Real browser/API flow, realistic tenancy and measured job throughput |
| Shared deployment | 1,000 → 10,000 | Queue fairness, database behavior, revocation, sustained latency |
| Regional cells | 100,000 | Load balancing, cell isolation and one failure-domain loss |
| Large deployment | 1,000,000+ | Representative mixed traffic, reconnect storm and sustained failure recovery |

At each stage run ramp, steady state, burst, soak and recovery workloads. Proposed
large-stage acceptance is a 24-hour soak at the agreed workload plus a separately
defined 2× burst and a failed cell/zone exercise. Use distributed generators whose
own CPU, sockets and bandwidth are monitored so generator exhaustion is visible.

Record source/image digests, hardware, topology, generators, data size, tenant
distribution, workload scripts, duration, p50/p95/p99 latency, error reasons,
backlog age, job completion, resource utilization and monetary cost. Publish a
sanitized reproducible report. Require the [reliability targets](RELIABILITY.md),
no cross-tenant access and no lost/duplicated committed effects before advancing.

## Economics and unresolved choices

Estimate compute-hours, memory, storage/IOPS, egress, logging, replication,
backups, security tooling, staffing and model tokens separately. Calculate cost
per connected-user-hour and per successful task under the same workload.
Use current operator-selected prices; no fixed dollar estimate is credible
without workload, region and provider selection. Open-source licensing does not
make model execution or million-user infrastructure free.

Database engine, scheduler, gateway protocol, cache and orchestration platform
remain decisions to benchmark. Kubernetes and microservices are options, not
prerequisites. A million simultaneous AI jobs is outside the example and needs
a separate capacity, energy, quota and budget model.
