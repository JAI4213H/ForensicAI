# ForensicAI

Evidence-grounded cybersecurity root-cause analysis for CAM-LDS telemetry.

## Pipeline

1. `rca_engine.py` parses defender-visible logs into normalized events.
2. `correlation_engine.py` builds a compact event/entity graph.
3. `hypothesis_engine.py` ranks deterministic, evidence-linked hypotheses.
4. `agentic_hypothesis_agent.py` optionally refines hypotheses with Groq.

Attacker-side logs are excluded by the parser. They are evaluation labels, not defender evidence.

## Usage

```powershell
python rca_engine.py path/to/scenario
python correlation_engine.py path/to/output
python hypothesis_engine.py path/to/output

$env:GROQ_API_KEY = "your-key"
python agentic_hypothesis_agent.py path/to/output
```

The API key is read only from `GROQ_API_KEY`; never put it in source code or committed files.

Use `python correlation_engine.py path/to/output --full` only when a detailed graph with edge explanations is required.
