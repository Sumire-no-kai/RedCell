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
from typing import Literal

from pydantic import Field, model_validator

from redcell.protocols.common import RedCellModel
from redcell.protocols.run import ProviderRunConfiguration

BILLING_EVIDENCE_VERSION = "billing-usage-evidence-v1"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"


def _completed_text(value: str | None) -> bool:
    """A draft placeholder is not independently reviewed evidence."""
    if value is None:
        return False
    cleaned = value.strip()
    return bool(cleaned) and not cleaned.casefold().startswith("to_fill")


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
    subject_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    service_tier: str | None = None
    checked_on: date | None = None
    source_reference: str | None = None
    """Official documentation URL/title or an internal billing-export reference; never a secret."""

    source_summary: str | None = None
    """Safe summary explaining coverage, including thinking/reasoning when applicable."""

    usage_covers_billed_tokens: bool = False
    reasoning_tokens_covered: bool = False

    @property
    def metadata_complete(self) -> bool:
        return (
            _completed_text(self.service_tier)
            and self.checked_on is not None
            and _completed_text(self.source_reference)
            and _completed_text(self.source_summary)
        )

    @property
    def passed(self) -> bool:
        return (
            self.metadata_complete
            and self.usage_covers_billed_tokens
            and self.reasoning_tokens_covered
        )


class BillingEvidenceBundle(RedCellModel):
    version: Literal["billing-usage-evidence-v1"] = BILLING_EVIDENCE_VERSION
    records: list[ProviderBillingEvidence] = Field(default_factory=list)

    @model_validator(mode="after")
    def roles_are_unique(self) -> BillingEvidenceBundle:
        roles = [record.role for record in self.records]
        if len(roles) != len(set(roles)):
            raise ValueError("billing evidence 中每个角色只能出现一次")
        return self

    def digest(self) -> str:
        payload = self.model_dump(mode="json", exclude_none=True, by_alias=True)
        payload["records"] = sorted(payload["records"], key=lambda record: record["role"])
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


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
                service_tier=None,
                checked_on=None,
                source_reference=None,
                source_summary=None,
                usage_covers_billed_tokens=False,
                reasoning_tokens_covered=False,
            )
            for role, configuration in configurations.items()
        ]
    )
