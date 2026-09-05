from hunter import ModelAbuseHunter

sample_incident = (
    "A fake payroll portal asks employees to log in through helpdesk@secure-payroll.co "
    "and https://payroll-login-secure.co/portal. The attacker also instructs the model "
    "to ignore safeguards, reveal secrets, and generate a credential theft workflow. "
    "The malicious IP is 185.220.101.42."
)

hunter = ModelAbuseHunter()
result = hunter.analyze(sample_incident, assignee="Analyst A", notes=["Initial triage for phishing + prompt override attempt."])

print("SOC analyst workflow demo")
print("=" * 32)
print(f"Case ID: {result['case_id']}")
print(f"Priority: {result['priority']}")
print(f"Status: {result['status']}")
print(f"Risk: {result['risk']['score']} / {result['risk']['severity']}")
print(f"Indicators: {len(result['indicators'])}")
print(f"Related cases: {len(result['related_cases'])}")
print("\nAlert titles:")
for alert in result["alerts"][:3]:
    print(f"- {alert['title']} [{alert['severity']}]")

print("\nCase summary:")
print(result["summary"][:500])
