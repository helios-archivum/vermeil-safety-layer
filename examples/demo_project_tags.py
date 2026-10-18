"""Demonstration: project_tags.py in action.

Run this to see how the deterministic tagger classifies different turns.
"""

from project_tags import classify_project, project_tags

# Example turns and their classifications
test_turns = [
    "Hindsight memory retain for this conversation",
    "NVIDIA API key rate limit reached",
    "hyprland waybar config update",
    "hermes gateway skills plugins",
    "LM Studio memory provider tweak",
    "something completely unrelated",
]

print("project_tags.py - Classification Demo")
print("=" * 50)

for turn in test_turns:
    proj = classify_project(turn)
    tags = project_tags(turn)
    print(f"Turn: {turn}")
    print(f"  Project: {proj}")
    print(f"  Tags: {tags}")
    print()
