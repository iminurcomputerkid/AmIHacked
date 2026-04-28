from amihacked.core.models import Finding


class SuppressionEngine:
    def apply(self, findings: list[Finding]) -> list[Finding]:
        return findings

