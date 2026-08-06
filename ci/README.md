# CI — target-service

CI for this repo is the **shared** `service-ci` Argo WorkflowTemplate, defined and
deployed from the infra-gitops repo (`argo-workflows/ci/service-ci.yaml`). There is no
per-repo pipeline definition; the pipeline derives everything from the `service`
parameter (repo/image/chart/release name = `target-service`).

- Trigger: GitHub push webhook → argo-server → `workflow-eventbinding.yaml` (deployed copy
  lives in infra-gitops `argo-workflows/ci/target-service-eventbinding.yaml`; this file is a reference).
- Manual run: UI → Workflow Templates → `service-ci` → Submit with `service=target-service`, or:
  `argo submit -n argo-workflows --from workflowtemplate/service-ci -p service=target-service -p revision=main`
- Pipeline: clone (maps go.mod `../shared-libs/go-X` replaces to sibling checkouts of the
  paaavkata/<lib> repos) → go vet+test → build amd64 binary → Kaniko image push →
  helm chart push → bump `bootstrap/applications/services/target-service-dev.yaml` (dev auto-deploy).
- Build contract: Dockerfile at repo root (`COPY \${APP_NAME}-\${TARGETARCH}`); helm chart
  under `helm/` named `target-service`.
- Prod: `promote-to-prod` workflow copies the dev-verified version into
  `bootstrap/applications/services/target-service-prod.yaml`.
