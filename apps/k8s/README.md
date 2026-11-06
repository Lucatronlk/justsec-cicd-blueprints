# Kubernetes YAML scan sample

Namespace, non-root web Deployment, ClusterIP Service and default-deny egress NetworkPolicy. This is a standalone manifest, not tied to other sample apps. It uses a versioned public image tag; pin a verified digest before production use. The NetworkPolicy only has effect with a network-policy-capable CNI; namespace-wide isolation needs separate policy.

```sh
kubectl apply --dry-run=client -f namespace.yaml
kubectl apply --dry-run=client -f workload.yaml
```

Only apply to a disposable test cluster. To undo an apply, delete `workload.yaml` then `namespace.yaml`. No cluster is needed for static Checkov/Trivy/KICS scans.
