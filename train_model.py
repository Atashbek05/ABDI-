"""
Phishing URL Detection - Model Training Script
Trains a RandomForestClassifier on URL-based features extracted from a labeled dataset.
"""

import os
import re
import glob
import joblib
import logging
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR  = os.path.join(SCRIPT_DIR, "..", "dataset")
MODEL_DIR    = os.path.join(SCRIPT_DIR, "..", "model")
MODEL_PATH   = os.path.join(MODEL_DIR, "model.pkl")
ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoder.pkl")

# Keywords commonly abused in phishing URLs
SUSPICIOUS_KEYWORDS = {"login", "verify", "secure", "account", "bank", "update",
                       "confirm", "signin", "password", "webscr", "ebayisapi"}


# ── Feature Extraction ────────────────────────────────────────────────────────

def _count_subdomains(parsed) -> int:
    """Return the number of subdomains (dots in hostname minus 1, min 0)."""
    host = parsed.netloc or parsed.path
    host = host.split(":")[0]   # strip port
    parts = host.split(".")
    # e.g. 'sub.example.com' → 3 parts → 1 subdomain
    return max(0, len(parts) - 2)


def _is_ip_address(parsed) -> int:
    """Return 1 if the hostname looks like a raw IPv4 address."""
    host = (parsed.netloc or parsed.path).split(":")[0]
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    return int(bool(ip_pattern.match(host)))


def _has_suspicious_keyword(url: str) -> int:
    """Return 1 if any suspicious keyword appears in the URL (case-insensitive)."""
    url_lower = url.lower()
    return int(any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS))


def extract_features(url: str) -> dict:
    """
    Extract hand-crafted features from a single URL string.
    Returns a flat dictionary of numeric feature values.
    """
    url = str(url).strip()

    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        parsed = urlparse("")

    features = {
        "url_length":          len(url),
        "num_dots":            url.count("."),
        "num_hyphens":         url.count("-"),
        "has_at_symbol":       int("@" in url),
        "has_https":           int(url.lower().startswith("https")),
        "num_digits":          sum(c.isdigit() for c in url),
        "num_subdomains":      _count_subdomains(parsed),
        "has_suspicious_kw":   _has_suspicious_keyword(url),
        "uses_ip_address":     _is_ip_address(parsed),
        # bonus features that add predictive value
        "num_slashes":         url.count("/"),
        "num_params":          len(parsed.query.split("&")) if parsed.query else 0,
        "url_depth":           len([p for p in parsed.path.split("/") if p]),
        "has_double_slash":    int("//" in parsed.path),
        "domain_length":       len(parsed.netloc),
    }
    return features


def build_feature_matrix(urls: pd.Series) -> pd.DataFrame:
    """Apply extract_features to every URL and return a DataFrame."""
    log.info("Extracting features from %d URLs …", len(urls))
    records = [extract_features(url) for url in urls]
    return pd.DataFrame(records)


# ── Dataset Loading ───────────────────────────────────────────────────────────

# Possible column names for URL and label, in priority order
URL_CANDIDATES   = ["url", "URL", "Url", "domain", "Domain", "link", "Link"]
LABEL_CANDIDATES = ["label", "Label", "status", "Status", "type", "Type",
                    "class", "Class", "phishing", "result", "Result"]


def _find_column(df: pd.DataFrame, candidates: list[str], role: str) -> str:
    """Return the first matching column name or raise a clear error."""
    for name in candidates:
        if name in df.columns:
            return name
    raise ValueError(
        f"Could not find the {role} column. "
        f"Searched for: {candidates}. "
        f"Available columns: {list(df.columns)}"
    )


def load_dataset(dataset_dir: str) -> tuple[pd.Series, pd.Series]:
    """
    Auto-detect and load the first CSV file found in dataset_dir.
    Returns (url_series, label_series).
    """
    csv_files = glob.glob(os.path.join(dataset_dir, "*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in: {dataset_dir}")

    csv_path = csv_files[0]
    log.info("Loading dataset: %s", csv_path)

    df = pd.read_csv(csv_path)
    log.info("Loaded %d rows, %d columns", len(df), len(df.columns))

    url_col   = _find_column(df, URL_CANDIDATES,   "URL")
    label_col = _find_column(df, LABEL_CANDIDATES, "label")
    log.info("URL column: '%s'  |  Label column: '%s'", url_col, label_col)

    urls   = df[url_col].dropna().astype(str)
    labels = df[label_col].loc[urls.index]

    return urls, labels


# ── Label Encoding ────────────────────────────────────────────────────────────

def encode_labels(labels: pd.Series) -> tuple[np.ndarray, LabelEncoder]:
    """
    Encode string labels (e.g. 'phishing'/'legitimate') to integers.
    Returns (encoded_array, fitted_encoder).
    """
    le = LabelEncoder()
    encoded = le.fit_transform(labels.astype(str).str.strip().str.lower())
    log.info("Label classes: %s", list(le.classes_))
    return encoded, le


# ── Training ──────────────────────────────────────────────────────────────────

def train(X_train: pd.DataFrame, y_train: np.ndarray) -> RandomForestClassifier:
    """Fit a RandomForestClassifier and return the trained model."""
    log.info("Training RandomForestClassifier …")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",   # handles class imbalance
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)
    log.info("Training complete.")
    return clf


# ── Evaluation ────────────────────────────────────────────────────────────────

def evaluate(clf: RandomForestClassifier, X_test: pd.DataFrame,
             y_test: np.ndarray, label_encoder: LabelEncoder) -> None:
    """Print a full classification report to stdout."""
    y_pred = clf.predict(X_test)

    # Use 'binary' averaging when there are exactly 2 classes, else 'weighted'
    avg = "binary" if len(label_encoder.classes_) == 2 else "weighted"

    accuracy  = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average=avg, zero_division=0)
    recall    = recall_score(y_test, y_pred, average=avg, zero_division=0)
    f1        = f1_score(y_test, y_pred, average=avg, zero_division=0)

    print("\n" + "=" * 50)
    print("       MODEL EVALUATION RESULTS")
    print("=" * 50)
    print(f"  Accuracy  : {accuracy:.4f}  ({accuracy * 100:.2f}%)")
    print(f"  Precision : {precision:.4f}")
    print(f"  Recall    : {recall:.4f}")
    print(f"  F1-Score  : {f1:.4f}")
    print("=" * 50)

    # Feature importance (top 10)
    feature_names = X_test.columns.tolist()
    importances   = clf.feature_importances_
    ranked        = sorted(zip(feature_names, importances),
                           key=lambda x: x[1], reverse=True)
    print("\n  Top feature importances:")
    for name, score in ranked[:10]:
        print(f"    {name:<22} {score:.4f}")
    print()


# ── Persistence ───────────────────────────────────────────────────────────────

def save_artifacts(clf: RandomForestClassifier, le: LabelEncoder) -> None:
    """Persist the trained model and label encoder to disk."""
    os.makedirs(MODEL_DIR, exist_ok=True)

    joblib.dump(clf, MODEL_PATH)
    log.info("Model saved → %s", MODEL_PATH)

    joblib.dump(le, ENCODER_PATH)
    log.info("Label encoder saved → %s", ENCODER_PATH)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    # 1. Load raw data
    urls, raw_labels = load_dataset(DATASET_DIR)

    # 2. Encode labels
    y, label_encoder = encode_labels(raw_labels)

    # 3. Build feature matrix
    X = build_feature_matrix(urls)

    # 4. Train / test split (80 / 20, stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    log.info("Split → train: %d  |  test: %d", len(X_train), len(X_test))

    # 5. Train model
    clf = train(X_train, y_train)

    # 6. Evaluate and print metrics
    evaluate(clf, X_test, y_test, label_encoder)

    # 7. Persist model artefacts
    save_artifacts(clf, label_encoder)

    log.info("Done. Run inference by loading %s", MODEL_PATH)


if __name__ == "__main__":
    main()
