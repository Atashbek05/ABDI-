"""
Train the CyberShield multi-model phishing detection ensemble.

Run: python -m ml.train_model
Saves model.pkl to the ml/ directory in the bundle format consumed by
ai_engine.ModelManager:

    {
        "models":  {name: estimator, ...},
        "scaler":  StandardScaler (shared by NN/LR),
        "weights": {name: float, ...},
        "metrics": {name: {accuracy, precision, recall, f1, roc_auc}},
        "confusion": {name: [[tn, fp], [fn, tp]]},
        "roc":     {name: {fpr, tpr, auc}},
        "feature_count": int,
        "trained_at": iso-timestamp,
    }

XGBoost is used when available; otherwise we substitute sklearn's
GradientBoostingClassifier (which uses the same ensemble of boosted trees
strategy) so the engine still ships with four distinct models.
"""
import os
import time
import joblib
import logging
import numpy as np

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    roc_curve,
    confusion_matrix,
)

try:
    from ml.feature_extractor import FeatureExtractor
except ImportError:
    from feature_extractor import FeatureExtractor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ─── Try importing XGBoost (optional dep) ────────────────────────────────────
try:
    from xgboost import XGBClassifier  # type: ignore
    HAS_XGBOOST = True
except Exception:  # pragma: no cover
    HAS_XGBOOST = False
    logger.warning("xgboost not installed — falling back to GradientBoostingClassifier")


# ─── Training data ───────────────────────────────────────────────────────────
LEGITIMATE_URLS = [
    "https://www.google.com/search?q=python",
    "https://github.com/user/repo",
    "https://stackoverflow.com/questions/12345",
    "https://wikipedia.org/wiki/Machine_learning",
    "https://docs.python.org/3/library/",
    "https://news.ycombinator.com/",
    "https://www.reddit.com/r/programming",
    "https://twitter.com/home",
    "https://www.linkedin.com/in/user",
    "https://www.amazon.com/dp/B08",
    "https://www.netflix.com/browse",
    "https://mail.google.com/mail/u/0/",
    "https://drive.google.com/drive/my-drive",
    "https://www.youtube.com/watch?v=abc123",
    "https://medium.com/@author/article",
    "https://www.microsoft.com/en-us/windows",
    "https://developer.mozilla.org/en-US/",
    "https://www.w3schools.com/python/",
    "https://npmjs.com/package/express",
    "https://pypi.org/project/fastapi/",
    "https://cloud.google.com/docs",
    "https://aws.amazon.com/documentation/",
    "https://azure.microsoft.com/en-us/",
    "https://www.cloudflare.com/",
    "https://stripe.com/docs/api",
    "https://twilio.com/docs/sms",
    "https://openai.com/api/",
    "https://huggingface.co/models",
    "https://kaggle.com/datasets",
    "https://arxiv.org/abs/2301.00001",
]

PHISHING_URLS = [
    "http://paypa1-secure-login.tk/verify",
    "http://192.168.1.1/admin/login.php",
    "http://amazon-update-account.xyz/signin",
    "http://googIe-security-alert.top/verify/account",
    "http://microsoft-secure-login.ml/auth/update",
    "http://apple-id-verify.tk/confirm",
    "http://facebook-login-secure.ga/signin",
    "http://bankofamerica-alert.xyz/account/verify",
    "http://paypal.account-suspended.xyz/restore",
    "http://secure-login.netflix-update.tk/auth",
    "http://amazon.com.verify-account.xyz/update",
    "http://google-security.account-check.ml/verify",
    "http://login-paypal-verify.top/confirm",
    "http://microsoft-office365-update.xyz/signin",
    "http://apple-support-id-verify.gq/confirm",
    "http://chase-bank-secure-login.tk/",
    "http://wellsfargo-account-alert.ml/verify",
    "http://coinbase-security-alert.xyz/verify",
    "http://binance-account-suspended.tk/restore",
    "http://metamask-wallet-verify.top/confirm",
    "http://bitcoin-reward-claim.xyz/winner",
    "http://free-prize-winner-claim.tk/congratulations",
    "http://instagram-login-secure.cf/signin",
    "http://twitter-account-verify.ga/confirm",
    "http://dropbox-security-alert.xyz/update",
    "http://ebay-account-suspended.ml/restore",
    "http://paypa1.com.account-update.xyz/",
    "http://amazone-support-login.tk/account",
    "http://secure.googlecom-verify.top/account",
    "http://login-microsofft-online.xyz/signin",
    "http://app1e-security-alert.gq/verify",
    "http://facebok-login.tk/signin",
    "http://netflix-account-hold.ml/restore",
    "http://chase-online-banking.xyz/login",
    "http://citibank-secure-login.top/auth",
    "http://crypto-wallet-earn-free.tk/claim",
    "http://download-update-now.xyz/install",
    "http://your-account-suspended.ml/verify",
    "http://paypalcom.account-verify.gq/confirm",
    "http://amaZ0n-account-alert.top/update",
]


def generate_synthetic_urls(n_legit: int = 600, n_phish: int = 600):
    import random
    import string

    def random_domain(length=8):
        return "".join(random.choices(string.ascii_lowercase, k=length))

    def random_legit():
        tlds = ["com", "org", "net", "io", "edu", "gov"]
        paths = ["", "/home", "/about", "/products", "/docs", "/api", "/search"]
        return f"https://www.{random_domain()}.{random.choice(tlds)}{random.choice(paths)}"

    def random_phish():
        brands = ["paypal", "amazon", "google", "microsoft", "apple", "facebook", "netflix"]
        tlds = ["tk", "ml", "xyz", "top", "gq", "cf", "ga", "online"]
        paths = ["/login", "/verify", "/account/update", "/signin", "/confirm", "/restore"]
        brand = random.choice(brands)
        variation = random.choice([
            f"{brand}-secure", f"secure-{brand}", f"{brand}update",
            f"{brand}1", f"{brand}-account", f"login-{brand}",
        ])
        return f"http://{variation}.{random.choice(tlds)}{random.choice(paths)}"

    legit = [random_legit() for _ in range(n_legit)]
    phish = [random_phish() for _ in range(n_phish)]
    return legit + phish, [0] * n_legit + [1] * n_phish


# ─── Per-model factories ─────────────────────────────────────────────────────
def build_random_forest():
    return RandomForestClassifier(
        n_estimators=200, max_depth=14, min_samples_split=3,
        random_state=42, n_jobs=-1,
    )


def build_xgboost():
    if HAS_XGBOOST:
        return XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            use_label_encoder=False, eval_metric="logloss",
            random_state=42, n_jobs=-1,
        )
    # Fallback: gradient-boosted trees with similar capacity.
    return GradientBoostingClassifier(
        n_estimators=200, max_depth=5, learning_rate=0.1, random_state=42,
    )


def build_neural_network():
    return MLPClassifier(
        hidden_layer_sizes=(64, 32),
        activation="relu",
        solver="adam",
        max_iter=500,
        random_state=42,
        early_stopping=True,
    )


def build_logistic_regression():
    return LogisticRegression(
        C=1.0, max_iter=1000, solver="lbfgs", random_state=42,
    )


# ─── Evaluation helpers ──────────────────────────────────────────────────────
def evaluate(name, model, X_test, y_test, scaled_X_test=None):
    X_use = scaled_X_test if scaled_X_test is not None else X_test
    y_pred = model.predict(X_use)
    y_prob = model.predict_proba(X_use)[:, 1]

    metrics = {
        "accuracy":  float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall":    float(recall_score(y_test, y_pred, zero_division=0)),
        "f1":        float(f1_score(y_test, y_pred, zero_division=0)),
        "roc_auc":   float(roc_auc_score(y_test, y_prob)),
    }
    cm = confusion_matrix(y_test, y_pred).tolist()
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    # Down-sample ROC to ~25 points so the JSON payload stays small.
    if len(fpr) > 25:
        idx = np.linspace(0, len(fpr) - 1, 25).astype(int)
        fpr, tpr = fpr[idx], tpr[idx]
    roc = {"fpr": [round(x, 4) for x in fpr.tolist()],
           "tpr": [round(x, 4) for x in tpr.tolist()],
           "auc": metrics["roc_auc"]}

    logger.info(
        f"{name:>20s}  acc={metrics['accuracy']:.3f} "
        f"prec={metrics['precision']:.3f} rec={metrics['recall']:.3f} "
        f"f1={metrics['f1']:.3f} auc={metrics['roc_auc']:.3f}"
    )
    return metrics, cm, roc


def main():
    logger.info("Preparing training data...")
    fe = FeatureExtractor()

    base_urls = LEGITIMATE_URLS + PHISHING_URLS
    base_labels = [0] * len(LEGITIMATE_URLS) + [1] * len(PHISHING_URLS)

    synth_urls, synth_labels = generate_synthetic_urls(700, 700)
    all_urls = base_urls + synth_urls
    all_labels = base_labels + synth_labels

    logger.info(
        f"Total samples: {len(all_urls)} "
        f"({sum(1 for l in all_labels if l==0)} legit, "
        f"{sum(1 for l in all_labels if l==1)} phish)"
    )

    X = np.array([fe.extract(u) for u in all_urls])
    y = np.array(all_labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )

    scaler = StandardScaler().fit(X_train)
    X_train_s = scaler.transform(X_train)
    X_test_s = scaler.transform(X_test)

    estimators = {
        "random_forest":       (build_random_forest(),       False),
        "xgboost":             (build_xgboost(),             False),
        "neural_network":      (build_neural_network(),       True),
        "logistic_regression": (build_logistic_regression(),  True),
    }

    logger.info("Training models...")
    models, metrics, confusion, roc = {}, {}, {}, {}
    for name, (est, needs_scale) in estimators.items():
        Xt = X_train_s if needs_scale else X_train
        est.fit(Xt, y_train)
        Xv = X_test_s if needs_scale else X_test
        m, cm, rc = evaluate(name, est, X_test, y_test, scaled_X_test=Xv if needs_scale else None)
        models[name] = est
        metrics[name] = m
        confusion[name] = cm
        roc[name] = rc

    # Performance-weighted voting: better models pull more weight.
    f1_total = sum(metrics[n]["f1"] for n in models) or 1.0
    weights = {n: metrics[n]["f1"] / f1_total for n in models}

    bundle = {
        "models": models,
        "scaler": scaler,
        "weights": weights,
        "metrics": metrics,
        "confusion": confusion,
        "roc": roc,
        "feature_count": fe.feature_count,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    out_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(out_dir, "model.pkl")
    joblib.dump(bundle, model_path)

    logger.info(f"Saved ensemble bundle -> {model_path}")
    logger.info(f"Weights: {weights}")


if __name__ == "__main__":
    main()
