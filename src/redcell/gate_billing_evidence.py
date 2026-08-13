"""Non-secret evidence that a Provider usage field covers every billed token.

`usage_covers_billed_tokens=True` is a necessary runtime declaration, not proof.
This module binds the human-reviewed proof to the exact non-secret billing subject
(provider, endpoint, model, and approved thinking setting) used by a Gate role.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date
from enum import StrEnum

from pydantic import Field, model_validator

from redcell.protocols.common import RedCellModel
from redcell.protocols.run import ProviderRunConfiguration


class BillingRole(StrEnum):
    TARGET = "target"
    ATTACKER = "attacker"
    CONTROLLER = "controller"


def billing_subject_fingerprint(configuration: ProviderRunConfiguration) -> str:
    """Hash only fields that identify the Provider billing behaviour, never credentials."""
    payload = {
        "provider": configuration.provider,
        "base_url": configuration.base_url,
        "model": configuration.model,
        "extra_body": configuration.extra_body.model_dump(mode="json", exclude_none=True),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class ProviderBillingEvidence(RedCellModel):
    """One human-reviewed, non-secret attestation for a concrete Gate model role."""

    role: BillingRole
    subject_fingerprint: str = Field(min_length=64, max_length=64)
    provider: str
    model: str
    service_tier: str = Field(min_length=1)
    checked_on: date
    source_reference: str = Field(min_length=1)
    """Official documentation URL/title or an internal billing-export reference; never a secret."""

    source_summary: str = Field(min_length=1)
    """Safe summary explaining coverage, including thinking/reasoning when applicable."""

    usage_covers_billed_tokens: bool = False
    reasoning_tokens_covered: bool = False

    @property
    def passed(self) -> bool:
        return self.usage_covers_billed_tokens and self.reasoning_tokens_covered


class BillingEvidenceBundle(RedCellModel):
    version: str = "billing-usage-evidence-v1"
    records: list[ProviderBillingEvidence] = Field(default_factory=list)

    @model_validator(mode="after")
    def roles_are_unique(self) -> BillingEvidenceBundle:
        roles = [record.role for record in self.records]
        if len(roles) != len(set(roles)):
            raise ValueError("billing evidence 中每个角色只能出现一次")
        return self

    def digest(self) -> str:
        payload = self.model_dump_json(exclude_none=True, by_alias=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def billing_evidence_failures(
    configurations: dict[BillingRole, ProviderRunConfiguration],
    evidence: BillingEvidenceBundle | None,
) -> list[str]:
    """Return fail-closed evidence failures for the expected formal roles."""
    if evidence is None:
        return ["missing_billing_evidence"]
    by_role = {record.role: record for record in evidence.records}
    failures: list[str] = []
    for role, configuration in configurations.items():
        record = by_role.get(role)
        if record is None:
            failures.append(f"billing_evidence_missing:{role.value}")
            continue
        if record.subject_fingerprint != billing_subject_fingerprint(configuration):
            failures.append(f"billing_evidence_subject_mismatch:{role.value}")
        if record.provider != configuration.provider or record.model != configuration.model:
            failures.append(f"billing_evidence_identity_mismatch:{role.value}")
        if not record.passed:
            failures.append(f"billing_evidence_coverage_unconfirmed:{role.value}")
        if configuration.usage_covers_billed_tokens is not True:
            failures.append(f"billing_usage_coverage_missing:{role.value}")
    return failures


def billing_evidence_template(
    configurations: dict[BillingRole, ProviderRunConfiguration],
) -> BillingEvidenceBundle:
    """Create an explicitly incomplete template without making any Provider call."""
    return BillingEvidenceBundle(
        records=[
            ProviderBillingEvidence(
                role=role,
                subject_fingerprint=billing_subject_fingerprint(configuration),
                provider=configuration.provider,
                model=configuration.model,
                service_tier="TO_FILL",
                checked_on=date.today(),
                source_reference="TO_FILL: official documentation URL or billing-export reference",
                source_summary="TO_FILL: explain coverage of every billed token class",
                usage_covers_billed_tokens=False,
                reasoning_tokens_covered=False,
            )
            for role, configuration in configurations.items()
        ]
    )
