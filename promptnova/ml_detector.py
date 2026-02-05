"""Traditional ML detector for prompt security analysis.

This module trains (or loads) a lightweight, production-style ML stack:

- Binary classifier: benign vs malicious (used for the *risk score*).
- Attack classifier: predicts the most likely attack type (used for *telemetry*).

This split dramatically reduces false positives on normal prompts while still
providing rich ML insights for the UI.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from joblib import dump, load
from sklearn.metrics import confusion_matrix, precision_score, recall_score
from sklearn.pipeline import FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

BASE_DIR = Path(__file__).resolve().parent
DATASET_DIR = BASE_DIR / "dataset"
MODEL_DIR = BASE_DIR / "ml_model"
MODEL_PATH = MODEL_DIR / "prompt_classifier.joblib"
FEEDBACK_PATH = DATASET_DIR / "feedback.csv"

DEFAULT_ATTACK_THRESHOLD = 0.40  # show attack-type predictions only if ML risk passes this


@dataclass
class MLMetadata:
    model_version: str
    trained_on: str
    sample_count: int
    class_distribution: Dict[str, int]
    validation_accuracy: float
    validation_f1: float

    def to_dict(self) -> Dict[str, object]:
        return {
            "model_version": self.model_version,
            "trained_on": self.trained_on,
            "sample_count": self.sample_count,
            "class_distribution": self.class_distribution,
            "validation_accuracy": round(self.validation_accuracy, 4),
            "validation_f1": round(self.validation_f1, 4),
        }


class PromptMLDetector:
    """Encapsulates training + inference for the prompt classifier."""

    def __init__(self, model_path: Path | None = None, auto_retrain: bool = False):
        self.model_path = model_path or MODEL_PATH
        self.model_path = Path(self.model_path)
        self.binary_pipeline: Pipeline | None = None
        self.attack_pipeline: Pipeline | None = None
        self.attack_labels: List[str] = []
        self.metadata: Dict[str, object] = {}
        self.available = False
        self.status = ""
        self.attack_threshold = DEFAULT_ATTACK_THRESHOLD

        if auto_retrain:
            self._train_model()
        else:
            self._load_or_train()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def predict(self, prompt: str) -> Dict[str, object]:
        """Score a prompt and return probabilities + metadata."""
        prompt = prompt or ""
        if not self.available or not self.binary_pipeline:
            return {
                "score": 0.0,
                "label": "unknown",
                "confidence": 0.0,
                "top_predictions": [],
                "status": self.status or "ML detector unavailable",
                "metadata": self.metadata,
            }

        try:
            # Binary risk (benign vs malicious)
            binary_probs = self.binary_pipeline.predict_proba([prompt])[0]
            benign_prob, malicious_prob = self._split_binary_probs(binary_probs)
        except Exception as exc:
            return {
                "score": 0.0,
                "label": "unknown",
                "confidence": 0.0,
                "top_predictions": [],
                "status": f"offline (predict error: {exc})",
                "metadata": self.metadata,
            }

        label = "benign"
        label_confidence = float(benign_prob)
        top_predictions: List[Dict[str, object]] = [
            {"label": "benign", "probability": round(float(benign_prob), 4)},
            {"label": "malicious", "probability": round(float(malicious_prob), 4)},
        ]

        # Attack-type telemetry only if the binary risk is above threshold
        attack_info: Dict[str, object] = {"threshold": self.attack_threshold, "predictions": []}
        if (
            self.attack_pipeline
            and malicious_prob >= self.attack_threshold
        ):
            attack_probs = self.attack_pipeline.predict_proba([prompt])[0]
            best_idx = int(np.argmax(attack_probs))
            label = self.attack_labels[best_idx]
            label_confidence = float(attack_probs[best_idx])

            top_k = np.argsort(attack_probs)[::-1][:3]
            attack_predictions = [
                {
                    "label": self.attack_labels[idx],
                    "probability": round(float(attack_probs[idx]), 4),
                }
                for idx in top_k
            ]
            top_predictions = attack_predictions
            attack_info = {"threshold": self.attack_threshold, "predictions": attack_predictions}

        return {
            "score": round(float(malicious_prob), 4),
            "label": label,
            "confidence": round(float(label_confidence), 4),
            "top_predictions": top_predictions,
            "status": "online",
            "metadata": self.metadata,
            "binary": {
                "benign_probability": round(float(benign_prob), 4),
                "malicious_probability": round(float(malicious_prob), 4),
                "threshold": self.attack_threshold,
            },
            "attack": attack_info,
        }

    def retrain(self) -> Dict[str, object]:
        """Force a re-train using the bundled datasets."""
        self._train_model()
        return self.metadata

    def get_status(self) -> Dict[str, object]:
        """Summarize detector readiness."""
        return {
            "status": "online" if self.available else "offline",
            "metadata": self.metadata,
        }

    def evaluate(self) -> Dict[str, object]:
        """Evaluate binary + attack models on the bundled datasets (plus feedback if present)."""
        if not self.available or not self.binary_pipeline:
            return {"status": "offline", "error": self.status or "ML detector unavailable"}

        dataset = self._load_training_dataset(include_feedback=True, augment=False)
        y_true = (dataset["label"] != "benign").astype(int).to_numpy()
        probas = self.binary_pipeline.predict_proba(dataset["prompt"])[:, 1]
        preds_05 = (probas >= 0.5).astype(int)

        tn, fp, fn, tp = confusion_matrix(y_true, preds_05, labels=[0, 1]).ravel()
        accuracy = float(accuracy_score(y_true, preds_05))
        precision = float(precision_score(y_true, preds_05, zero_division=0))
        recall = float(recall_score(y_true, preds_05, zero_division=0))
        f1 = float(f1_score(y_true, preds_05, zero_division=0))
        try:
            auc = float(roc_auc_score(y_true, probas))
        except Exception:
            auc = 0.0

        # False positives (benign predicted malicious)
        benign = dataset[dataset["label"] == "benign"].copy()
        benign["malicious_prob"] = self.binary_pipeline.predict_proba(benign["prompt"])[:, 1]
        benign_fp = benign.sort_values("malicious_prob", ascending=False).head(10)

        report: Dict[str, object] = {
            "status": "online",
            "binary": {
                "threshold": 0.5,
                "accuracy": round(accuracy, 4),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "auc": round(auc, 4),
                "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            },
            "false_positives_top10": [
                {"prompt": str(row.prompt), "malicious_probability": round(float(row.malicious_prob), 4)}
                for row in benign_fp.itertuples(index=False)
            ],
            "metadata": self.metadata,
        }

        if self.attack_pipeline is not None and self.attack_labels:
            malicious_df = self._load_malicious_dataset(include_feedback=True, augment=False)
            if len(malicious_df) > 1:
                attack_preds = self.attack_pipeline.predict(malicious_df["prompt"])
                attack_acc = float(accuracy_score(malicious_df["label"], attack_preds))
                attack_f1 = float(f1_score(malicious_df["label"], attack_preds, average="macro"))
                report["attack"] = {
                    "validation_accuracy": round(attack_acc, 4),
                    "validation_f1": round(attack_f1, 4),
                    "label_count": len(self.attack_labels),
                }

        return report

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _load_or_train(self):
        if self.model_path.exists():
            try:
                state = load(self.model_path)
            except Exception:
                # Corrupted or incompatible artifact - recover by retraining.
                self._train_model()
                return
            # Backward compatible loader for older single-pipeline artifacts.
            if "binary_pipeline" in state:
                self.binary_pipeline = state["binary_pipeline"]
                self.attack_pipeline = state.get("attack_pipeline")
                self.attack_labels = state.get("attack_labels", [])
                self.metadata = state.get("metadata", {})
                self.attack_threshold = float(state.get("attack_threshold", DEFAULT_ATTACK_THRESHOLD))
                self.available = True
                self.status = "online"
            elif "pipeline" in state:
                # Old format: automatically upgrade by retraining to the new artifact format.
                self._train_model()
            else:
                self._train_model()
        else:
            self._train_model()

    def _train_model(self) -> MLMetadata:
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        malicious_path = DATASET_DIR / "malicious_prompts.csv"
        safe_path = DATASET_DIR / "safe_prompts.csv"

        malicious_df = pd.read_csv(malicious_path)
        safe_df = pd.read_csv(safe_path)

        malicious_df["label"] = malicious_df["attack_type"].fillna("unknown_attack")
        safe_df["label"] = "benign"

        dataset = pd.concat(
            [
                malicious_df[["prompt", "label"]],
                safe_df[["prompt", "label"]],
            ],
            ignore_index=True,
        )

        dataset = self._merge_feedback(dataset)
        raw_dataset = dataset.dropna().drop_duplicates(subset=["prompt"]).copy()
        dataset = self._augment_dataset(raw_dataset)
        augmented_dataset = dataset.copy()

        # --- Binary risk model (benign vs malicious) ---
        is_malicious = (dataset["label"] != "benign").astype(int)
        X_train, X_val, y_train, y_val = train_test_split(
            dataset["prompt"], is_malicious, test_size=0.2, random_state=42, stratify=is_malicious
        )

        binary_pipeline = Pipeline(
            steps=[
                ("features", self._build_features()),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=3000,
                        solver="lbfgs",
                        C=2.0,
                    ),
                ),
            ]
        )
        binary_pipeline.fit(X_train, y_train)
        preds = binary_pipeline.predict(X_val)
        probas = binary_pipeline.predict_proba(X_val)[:, 1]
        val_accuracy = accuracy_score(y_val, preds)
        val_f1 = f1_score(y_val, preds)
        try:
            val_auc = roc_auc_score(y_val, probas)
        except Exception:
            val_auc = 0.0

        # --- Attack type model (malicious-only) ---
        malicious_only = self._load_malicious_dataset(include_feedback=True, augment=True)
        attack_pipeline, attack_metrics, attack_labels = self._train_attack_model(malicious_only)

        trained_on = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        metadata = MLMetadata(
            model_version="2.1.0",
            trained_on=trained_on,
            sample_count=int(len(raw_dataset)),
            class_distribution=raw_dataset["label"].value_counts().to_dict(),
            validation_accuracy=val_accuracy,
            validation_f1=val_f1,
        )

        metadata_dict = metadata.to_dict()
        metadata_dict.update(
            {
                "binary_validation_auc": round(float(val_auc), 4),
                "attack_model": attack_metrics,
                "attack_threshold": self.attack_threshold,
                "augmented_sample_count": int(len(augmented_dataset)),
                "augmented_class_distribution": augmented_dataset["label"].value_counts().to_dict(),
            }
        )

        dump(
            {
                "binary_pipeline": binary_pipeline,
                "attack_pipeline": attack_pipeline,
                "attack_labels": attack_labels,
                "attack_threshold": self.attack_threshold,
                "metadata": metadata_dict,
            },
            self.model_path,
        )

        self.binary_pipeline = binary_pipeline
        self.attack_pipeline = attack_pipeline
        self.attack_labels = attack_labels
        self.metadata = metadata_dict
        self.available = True
        self.status = "online"
        return metadata

    def _build_features(self) -> FeatureUnion:
        """Word + char TF-IDF improves generalization for short prompts."""
        word = TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            min_df=1,
            max_features=8000,
            strip_accents="unicode",
        )
        char = TfidfVectorizer(
            lowercase=True,
            analyzer="char_wb",
            ngram_range=(3, 5),
            min_df=1,
            max_features=8000,
        )
        return FeatureUnion([("word", word), ("char", char)])

    def _train_attack_model(self, malicious_df: pd.DataFrame) -> Tuple[Pipeline | None, Dict[str, object], List[str]]:
        labels = sorted(malicious_df["label"].dropna().unique().tolist())
        if len(labels) < 2:
            return None, {"status": "disabled (insufficient classes)"}, []

        X_train, X_val, y_train, y_val = train_test_split(
            malicious_df["prompt"], malicious_df["label"], test_size=0.2, random_state=42, stratify=malicious_df["label"]
        )
        attack_pipeline = Pipeline(
            steps=[
                ("features", self._build_features()),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=3000,
                        solver="lbfgs",
                        multi_class="multinomial",
                        C=2.0,
                    ),
                ),
            ]
        )
        attack_pipeline.fit(X_train, y_train)
        preds = attack_pipeline.predict(X_val)
        acc = accuracy_score(y_val, preds)
        f1 = f1_score(y_val, preds, average="macro")

        return (
            attack_pipeline,
            {"status": "online", "validation_accuracy": round(float(acc), 4), "validation_f1": round(float(f1), 4)},
            attack_pipeline.classes_.tolist(),
        )

    def _load_malicious_dataset(self, include_feedback: bool, augment: bool) -> pd.DataFrame:
        malicious_path = DATASET_DIR / "malicious_prompts.csv"
        malicious_df = pd.read_csv(malicious_path)
        malicious_df["label"] = malicious_df["attack_type"].fillna("unknown_attack")
        malicious_df["label"] = (
            malicious_df["label"]
            .astype(str)
            .str.split(";", n=1)
            .str[0]
            .str.strip()
        )

        if include_feedback and FEEDBACK_PATH.exists():
            fb = pd.read_csv(FEEDBACK_PATH)
            fb = fb[(fb.get("user_label") == "malicious") & (fb.get("attack_type").fillna("").astype(str) != "")]
            if not fb.empty:
                fb = fb.rename(columns={"attack_type": "label"})
                malicious_df = pd.concat([malicious_df[["prompt", "label"]], fb[["prompt", "label"]]], ignore_index=True)
            else:
                malicious_df = malicious_df[["prompt", "label"]]
        else:
            malicious_df = malicious_df[["prompt", "label"]]

        if augment:
            malicious_df = self._augment_dataset(malicious_df)
            malicious_df = malicious_df[malicious_df["label"] != "benign"]

        return malicious_df.dropna().drop_duplicates(subset=["prompt"])

    def _load_training_dataset(self, include_feedback: bool, augment: bool) -> pd.DataFrame:
        malicious_path = DATASET_DIR / "malicious_prompts.csv"
        safe_path = DATASET_DIR / "safe_prompts.csv"
        malicious_df = pd.read_csv(malicious_path)
        safe_df = pd.read_csv(safe_path)
        malicious_df["label"] = malicious_df["attack_type"].fillna("unknown_attack")
        safe_df["label"] = "benign"
        dataset = pd.concat([malicious_df[["prompt", "label"]], safe_df[["prompt", "label"]]], ignore_index=True)

        if include_feedback:
            dataset = self._merge_feedback(dataset)
        if augment:
            dataset = self._augment_dataset(dataset)
        return dataset.dropna().drop_duplicates(subset=["prompt"])

    def _merge_feedback(self, dataset: pd.DataFrame) -> pd.DataFrame:
        if not FEEDBACK_PATH.exists():
            return dataset
        try:
            fb = pd.read_csv(FEEDBACK_PATH)
        except Exception:
            return dataset

        if fb.empty:
            return dataset

        fb = fb.copy()
        fb["user_label"] = fb.get("user_label", "").astype(str).str.lower().str.strip()
        fb["attack_type"] = fb.get("attack_type", "").astype(str).str.strip()
        fb["label"] = np.where(
            fb["user_label"] == "benign",
            "benign",
            np.where(fb["attack_type"] != "", fb["attack_type"], "unknown_attack"),
        )

        merged = pd.concat([dataset, fb[["prompt", "label"]]], ignore_index=True)
        return merged

    def _augment_dataset(self, dataset: pd.DataFrame) -> pd.DataFrame:
        """Deterministic, lightweight augmentation to improve robustness with small datasets."""
        rows: List[Tuple[str, str]] = []
        for prompt, label in dataset[["prompt", "label"]].itertuples(index=False):
            prompt = str(prompt)
            label = str(label)
            is_malicious = label != "benign"
            for variant in self._augment_prompt(prompt, is_malicious=is_malicious):
                rows.append((variant, label))
        augmented = pd.DataFrame(rows, columns=["prompt", "label"])
        return augmented.drop_duplicates(subset=["prompt"])

    def _augment_prompt(self, prompt: str, is_malicious: bool) -> List[str]:
        base = " ".join((prompt or "").strip().split())
        if not base:
            return []

        variants = {base}

        # Universal variants
        variants.add(f"Please {base}")
        if not base.endswith((".", "?", "!")):
            variants.add(base + ("." if is_malicious else "?"))

        # Malicious-specific synonym substitutions (kept small & deterministic)
        if is_malicious:
            repls = [
                ("Ignore", "Disregard"),
                ("ignore", "disregard"),
                ("previous instructions", "prior instructions"),
                ("system prompt", "system message"),
                ("internal instructions", "hidden instructions"),
                ("bypass", "circumvent"),
            ]
            for a, b in repls:
                if a in base:
                    variants.add(base.replace(a, b))
        else:
            # Benign-specific: add a friendly prefix (common in real traffic)
            variants.add(f"Hi, {base}")

        # Keep output bounded (stable order)
        out = [v for v in variants if v]
        out.sort()
        return out[:5]

    def _split_binary_probs(self, probs: np.ndarray) -> Tuple[float, float]:
        # scikit-learn orders classes ascending, so [0,1] for labels {0,1}.
        if probs.shape[0] == 2:
            return float(probs[0]), float(probs[1])
        # Fallback for unexpected shapes
        benign = float(probs[0]) if probs.size else 1.0
        return benign, 1.0 - benign


if __name__ == "__main__":
    detector = PromptMLDetector(auto_retrain=True)
    print(json.dumps(detector.metadata, indent=2))
