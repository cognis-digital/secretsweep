"""Demo source file with PLANTED FAKE secrets (none are real credentials).

Exercises: more provider rules, the high-entropy heuristic, the inline
allow-comment, and a placeholder that the allowlist should suppress.
"""

# OpenAI + Hugging Face + Linear + DigitalOcean tokens (fake):
OPENAI_API_KEY = "sk-proj-aB3xQ9zK7mP2wL5nT8vR4cF6yH1jD0sGqW9eU4iO"
HF_TOKEN = "hf_EXAMPLEEXAMPLEEXAMPLEEXAMPLE000000"
LINEAR_KEY = "lin_api_THIS_IS_AN_EXAMPLE_NOT_A_REAL_LINEAR_KEY"
DO_TOKEN = "dop_v1_THIS_IS_AN_EXAMPLE_NOT_A_REAL_DIGITALOCEAN_TOKEN"

# A high-entropy base64 blob with no provider keyword (entropy heuristic):
SESSION_SIGNING_KEY = "Zk9Qm2Xv7Lp4Rt8Wb1Hn6Yc3Df0Gj5Ka9Os2Ue4Iy7Tq"

# This one is a known false positive we explicitly accept inline:
TEST_DUMMY = "sk_live_EXAMPLE0000000000000"  # secretsweep:allow

# A placeholder the allowlist suppresses by the stop-word heuristic:
PLACEHOLDER_KEY = "your_api_key_here_replaceme_example"
