from typing import Dict, List

from src.anomaly_detector import AnomalyDetector
from src.network_packet import NetworkPacket
from src.exceptions import DetectionError


class ModelEvaluator:
    """
    Evaluates AnomalyDetector accuracy against a labeled test set.
    Produces per-class recall, overall accuracy, and a confusion matrix.
    """

    def __init__(self, detector: AnomalyDetector):
        self._detector = detector

    def evaluate(self, packets: List[NetworkPacket]) -> Dict:
        results = []
        for p in packets:
            try:
                predicted, confidence = self._detector.predict(p)
            except DetectionError:
                predicted, confidence = "normal", 0.0
            results.append({
                "actual": p.label,
                "predicted": predicted,
                "confidence": confidence,
                "correct": p.label == predicted,
            })

        total = len(results)
        correct = sum(1 for r in results if r["correct"])
        accuracy = correct / total if total else 0.0

        labels = sorted(set(r["actual"] for r in results))
        per_class = {}
        for label in labels:
            actual_pos = [r for r in results if r["actual"] == label]
            true_pos = [r for r in actual_pos if r["predicted"] == label]
            recall = len(true_pos) / len(actual_pos) if actual_pos else 0.0
            per_class[label] = {
                "total": len(actual_pos),
                "correct": len(true_pos),
                "recall": round(recall, 2),
            }

        return {
            "total": total,
            "correct": correct,
            "accuracy": round(accuracy, 2),
            "per_class": per_class,
            "results": results,
        }

    def confusion_matrix(self, packets: List[NetworkPacket]) -> Dict[str, Dict[str, int]]:
        all_labels = sorted(set(p.label for p in packets))
        matrix: Dict[str, Dict[str, int]] = {a: {p: 0 for p in all_labels} for a in all_labels}

        for p in packets:
            try:
                predicted, _ = self._detector.predict(p)
            except DetectionError:
                predicted = "normal"
            actual = p.label
            if predicted not in matrix[actual]:
                matrix[actual][predicted] = 0
            matrix[actual][predicted] += 1

        return matrix

    def print_report(self, packets: List[NetworkPacket]) -> None:
        metrics = self.evaluate(packets)
        matrix = self.confusion_matrix(packets)
        all_labels = sorted(set(
            list(matrix.keys()) + [k for v in matrix.values() for k in v]
        ))

        print(f"\n{'=' * 52}")
        print("  AI MODEL EVALUATION REPORT")
        print(f"{'=' * 52}")
        print(f"  Total packets tested : {metrics['total']}")
        print(f"  Correctly classified : {metrics['correct']}")
        print(f"  Overall accuracy     : {metrics['accuracy'] * 100:.1f}%")

        print("\n  Per-class results (recall = correct / total):")
        for label, stats in metrics["per_class"].items():
            bar = "#" * int(stats["recall"] * 20)
            print(f"    {label:12s}  total={stats['total']:3d}  "
                  f"correct={stats['correct']:3d}  recall={stats['recall']:.0%}  [{bar:<20s}]")

        print("\n  Confusion matrix  (rows = actual, cols = predicted):")
        header = f"    {'actual \\ pred':14s}" + "".join(f"{l:14s}" for l in all_labels)
        print(header)
        print("    " + "-" * (14 + 14 * len(all_labels)))
        for actual in all_labels:
            row = matrix.get(actual, {})
            print(f"    {actual:14s}" + "".join(f"{row.get(p, 0):<14d}" for p in all_labels))
        print(f"{'=' * 52}")