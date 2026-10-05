"""Central configuration. Every tunable lives here, overridable by env (AEGIS_*)."""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    # --- storage -------------------------------------------------------------
    database_url: str = f"sqlite:///{REPO_ROOT / 'data' / 'aegis.db'}"
    model_dir: Path = REPO_ROOT / "data" / "models"
    dataset_dir: Path = REPO_ROOT / "data" / "datasets"
    pcap_dir: Path = REPO_ROOT / "data" / "pcaps"

    # --- api -----------------------------------------------------------------
    host: str = "127.0.0.1"
    port: int = 8000
    jwt_secret: str = "change-me-in-production"
    jwt_ttl_minutes: int = 720
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # --- flow assembly -------------------------------------------------------
    flow_idle_timeout: float = 15.0          # export a flow after N s without packets
    flow_syn_timeout: float = 3.0            # unanswered connection attempt: export fast
    flow_active_timeout: float = 120.0       # force-export long-lived flows
    host_window_short: float = 10.0          # short behavioural window (s)
    host_window_long: float = 60.0           # long behavioural window (s)

    # --- detection -----------------------------------------------------------
    # Chosen from the measured operating curve (see docs/BENCHMARK.md). Because
    # stage A scores are benign percentiles, these numbers are directly readable:
    # 0.98 means "alert on traffic more unusual than 98% of this host's normal".
    #   0.98 -> ~1.8% of benign flows, 99.8% loud recall, 97.2% stealth recall
    #   0.99 -> ~1.1% of benign flows, 97.6% loud recall, 62.9% stealth recall
    base_threshold: float = 0.98             # global floor, and cold-start value
    min_threshold: float = 0.97              # adaptation may not go below this
    max_threshold: float = 0.995             # ceiling: how far a host may raise its bar
    host_quantile: float = 0.99              # per-host FP budget: alert on the top 1%
    baseline_min_samples: int = 60           # flows needed before trusting a baseline
    supervised_min_confidence: float = 0.55  # below this, family stays "unknown"
    # Stage B as a precision filter (the cascade). Stage A is tuned for
    # sensitivity, which costs false positives in the marginal band just above
    # the threshold. When the supervised classifier recognises that traffic as
    # benign *and says so confidently*, the alert is suppressed.
    benign_suppress_confidence: float = 0.90
    # ... but never above this score: a strong anomaly always alerts, even if the
    # classifier calls it benign. That is what preserves detection of attacks the
    # classifier has never been trained on.
    alert_override_score: float = 0.9975

    # --- correlation ---------------------------------------------------------
    dedup_window: float = 60.0               # merge alerts into an incident within N s
    incident_max_alerts: int = 2000          # cap stored alerts per incident

    # --- live stream ---------------------------------------------------------
    stream_tick: float = 1.0                 # aggregate stream points every N s
    stream_history: int = 180                # points kept in memory for late joiners

    @property
    def stage_a_path(self) -> Path:
        return self.model_dir / "stage_a_isoforest.joblib"

    @property
    def stage_b_path(self) -> Path:
        return self.model_dir / "stage_b_classifier.joblib"


settings = Settings()
settings.model_dir.mkdir(parents=True, exist_ok=True)
settings.dataset_dir.mkdir(parents=True, exist_ok=True)
settings.pcap_dir.mkdir(parents=True, exist_ok=True)
