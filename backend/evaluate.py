import json
from pathlib import Path
from typing import Any

from backend.app.firewall import analyze_segments, extract_segments


DATASET = Path(__file__).parent / "evaluation" / "cases.json"


def load_cases() -> list[dict[str, Any]]:
    return json.loads(DATASET.read_text(encoding="utf-8"))


def evaluate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    evaluated = []
    categories: set[str] = set()
    benign_flagged = 0
    benign_count = 0

    for case in cases:
        expected = set(case["expected"])
        result = analyze_segments(extract_segments(case["content"], case["format"]))
        predicted = set(result["categories"])
        categories.update(expected | predicted)
        evaluated.append({"id": case["id"], "expected": expected, "predicted": predicted})
        if not expected:
            benign_count += 1
            benign_flagged += bool(predicted)

    per_category = {}
    for category in sorted(categories):
        true_positive = sum(category in case["expected"] and category in case["predicted"] for case in evaluated)
        false_positive = sum(category not in case["expected"] and category in case["predicted"] for case in evaluated)
        false_negative = sum(category in case["expected"] and category not in case["predicted"] for case in evaluated)
        true_negative = sum(category not in case["expected"] and category not in case["predicted"] for case in evaluated)
        per_category[category] = {
            "precision": true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0,
            "recall": true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0,
            "false_positive_rate": false_positive / (false_positive + true_negative)
            if false_positive + true_negative
            else 0.0,
            "support": true_positive + false_negative,
        }

    return {
        "case_count": len(cases),
        "benign_case_count": benign_count,
        "benign_false_positive_rate": benign_flagged / benign_count if benign_count else 0.0,
        "per_category": per_category,
    }


def main() -> None:
    results = evaluate(load_cases())
    print(f"Cases: {results['case_count']} (benign: {results['benign_case_count']})")
    print(f"Benign false-positive rate: {results['benign_false_positive_rate']:.1%}")
    print("\nCategory                       Precision  Recall  FPR      Support")
    for category, metrics in results["per_category"].items():
        print(
            f"{category:<30} {metrics['precision']:>8.1%}  {metrics['recall']:>6.1%}  "
            f"{metrics['false_positive_rate']:>6.1%}  {metrics['support']:>7}"
        )


if __name__ == "__main__":
    main()