from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from .auth import AuthContext
from .tamper import TamperFinding


@dataclass
class HuntReport:
    target: str
    discovered_paths: list[str] = field(default_factory=list)
    backup_hits: list[str] = field(default_factory=list)
    leaked_emails: list[str] = field(default_factory=list)
    credential_used: AuthContext | None = None
    admin_flag: str | None = None
    post_auth_findings: list[TamperFinding] = field(default_factory=list)

    def to_json(self) -> str:
        payload = asdict(self)
        return json.dumps(payload, indent=2)

    def print_human(self) -> None:
        print("=" * 68)
        print("THM Web Hunt Report")
        print("=" * 68)
        print(f"Target: {self.target}")
        print(f"Discovered paths: {len(self.discovered_paths)}")
        print(f"Backup leaks: {len(self.backup_hits)}")

        if self.leaked_emails:
            print("Leaked emails:")
            for email in self.leaked_emails:
                print(f"  - {email}")

        if self.credential_used:
            print("Auth success:")
            print(f"  - email: {self.credential_used.email}")
            print(f"  - password: {self.credential_used.password}")
            print(f"  - otp bypassed: {self.credential_used.otp_bypassed}")
        else:
            print("Auth success: no")

        print(f"Admin flag: {self.admin_flag or 'not found'}")

        if self.post_auth_findings:
            print("Post-auth findings:")
            for finding in self.post_auth_findings:
                mark = "FLAG" if finding.extracted_flag else "-"
                print(f"  [{mark}] {finding.endpoint} payload={finding.payload}")
                if finding.extracted_flag:
                    print(f"      -> {finding.extracted_flag}")
