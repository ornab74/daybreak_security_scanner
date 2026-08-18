from __future__ import annotations

import html
import json
import os
import queue
import threading
import concurrent.futures
from enum import Enum
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk
import nh3
from openai import OpenAI
from lockfiles import parse_dependency_file

from manifest import build_manifest, infer_project_types, manifest_as_json
from models import (
    AdvancedDependencyFutureReview,
    DependencyDeepReview,
    DependencyRiskMap,
    PatchProposal,
    PatchVerification,
    Ratings,
    SourceReview,
)
from prompts import (
    DEFAULT_USER_PROMPT,
    DEPENDENCY_DEEP_DEVELOPER_PROMPT,
    DEPENDENCY_FORECAST_DEVELOPER_PROMPT,
    DIFF_MODEL,
    DIFF_VERIFY_DEVELOPER_PROMPT,
    REVIEW_MODEL,
    SECURITY_DIFF_DEVELOPER_PROMPT,
    SOURCE_REVIEW_DEVELOPER_PROMPT,
    TRIAGE_DEVELOPER_PROMPT,
    TRIAGE_MODEL,
    VERIFY_MODEL,
    dependency_deep_prompt,
    dependency_forecast_prompt,
    dependency_prompt,
    diff_verify_prompt,
    manifest_prompt,
    security_diff_prompt,
    source_review_prompt,
)
from secure_store import (
    SecureStoreError,
    forget_api_key,
    has_saved_key,
    load_api_key,
    save_api_key,
)
from provider_store import PROVIDER_PRESETS, ProviderProfile, ProviderStore, validate_profile
from source_review import (
    MAX_DEEP_FILES,
    MAX_FINDINGS_PER_FILE,
    is_reviewable_source,
    load_source_snapshot,
    number_source,
    source_review_priority,
    validate_finding_spans,
    validate_unified_diff,
)
from http_transport import RetryPolicy, build_httpx_client, retry_call
from risk_gate import tune_future_risk
from main import (
    ENGINE_DESCRIPTIONS,
    SEVERITY_VALUE,
    VERSION as SCANNER_VERSION,
    atomic_write,
    render_sarif,
    result_document,
    scan as local_security_scan,
)

APP_TITLE = "Daybreak Security Workbench"
MODEL_CHOICES = {
    "GPT-5.6 Terra — standard API": "gpt-5.6-terra",
    "Daybreak Blue — approval required": "daybreak-blue-latest",
}
THEME_PALETTES = {
    "Daybreak Midnight": {
        "mode": "dark", "window": "#08111f", "surface": "#101c2e", "panel": "#17263b",
        "accent": "#38a3ff", "hover": "#1677c8", "text": "#edf6ff", "muted": "#8fa9c4",
        "textbox": "#0b1524", "border": "#27415f",
    },
    "Cyber Neon": {
        "mode": "dark", "window": "#050709", "surface": "#0b1110", "panel": "#101a17",
        "accent": "#00e6a8", "hover": "#00a97c", "text": "#eafff8", "muted": "#78aa9d",
        "textbox": "#060d0b", "border": "#164d3e",
    },
    "Violet Horizon": {
        "mode": "dark", "window": "#100b1c", "surface": "#19122b", "panel": "#241a3d",
        "accent": "#a970ff", "hover": "#7546c2", "text": "#f6f0ff", "muted": "#b4a2cf",
        "textbox": "#0f0a19", "border": "#49336e",
    },
    "Solar Flare": {
        "mode": "dark", "window": "#17100a", "surface": "#25180d", "panel": "#332113",
        "accent": "#ff9d2e", "hover": "#c86b16", "text": "#fff4e7", "muted": "#cbb092",
        "textbox": "#120c08", "border": "#674321",
    },
    "Arctic Light": {
        "mode": "light", "window": "#eaf2f8", "surface": "#f7fbff", "panel": "#dce9f2",
        "accent": "#1878b9", "hover": "#105b8e", "text": "#102638", "muted": "#536d80",
        "textbox": "#ffffff", "border": "#a9bfce",
    },
    "High Contrast": {
        "mode": "dark", "window": "#000000", "surface": "#080808", "panel": "#111111",
        "accent": "#ffe600", "hover": "#b8a600", "text": "#ffffff", "muted": "#d0d0d0",
        "textbox": "#000000", "border": "#ffffff",
    },
}
MAX_REQUIREMENTS = 500
DEPENDENCY_BATCH = 30
MANIFEST_BATCH = 40
MAX_MANIFEST_API_ENTRIES = 2_000


class Risk(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


def clean_for_ui(value: object, max_len: int = 100_000) -> str:
    text = str(value)
    try:
        text = html.unescape(nh3.clean(text, tags=set(), attributes={}))
    except Exception:
        pass
    text = "".join(ch for ch in text if ch in "\n\t" or ord(ch) >= 32)
    return text[:max_len]


class DaybreakClient:
    def __init__(self, api_key: str, live_web: bool, cancel_event=None, status_callback=None, model_override: str | None = None, base_url: str = "https://api.openai.com/v1", protocol: str = "responses"):
        self.http_client = build_httpx_client()
        # One retry owner only: the SDK layer is disabled so attempts cannot multiply.
        self.client = OpenAI(api_key=api_key, base_url=base_url, http_client=self.http_client, max_retries=0)
        self.protocol = protocol
        self.live_web = live_web and protocol == "responses"
        self.cancel_event = cancel_event
        self.status_callback = status_callback
        self.retry_policy = RetryPolicy.from_environment()
        self.fallback_model = os.getenv("DAYBREAK_FALLBACK_MODEL", "gpt-4.1-mini").strip() if protocol == "responses" else ""
        self.model_fallbacks: dict[str, str] = {}
        self.model_override = model_override

    def _model(self, stage_default: str) -> str:
        return self.model_override or stage_default

    def _cancelled(self):
        return bool(self.cancel_event and self.cancel_event.is_set())

    def _wait(self, seconds: float) -> bool:
        return self.cancel_event.wait(seconds) if self.cancel_event else False

    def _retry_notice(self, attempt: int, delay: float, exc: BaseException):
        if self.status_callback:
            status = getattr(exc, "status_code", None)
            detail = f"HTTP {status}" if status else type(exc).__name__
            self.status_callback(f"Transient {detail}; retry {attempt + 1}/{self.retry_policy.max_attempts} in {delay:.1f}s")

    @staticmethod
    def _model_not_found(exc: BaseException) -> bool:
        if getattr(exc, "code", None) == "model_not_found":
            return True
        body = getattr(exc, "body", None)
        if isinstance(body, dict):
            error = body.get("error", body)
            return isinstance(error, dict) and error.get("code") == "model_not_found"
        return False

    @staticmethod
    def _supports_reasoning(model: str) -> bool:
        return model.startswith(("gpt-5", "o1", "o3", "o4", "daybreak-"))

    def _parse(self, *, model: str, instructions: str, prompt: str, schema, web: bool = False, effort: str = "low"):
        kwargs = {}
        if web and self.live_web:
            kwargs["tools"] = [{"type": "web_search"}]
        active_model = self.model_fallbacks.get(model, model)

        def request(selected_model: str):
            if self.protocol == "chat_completions":
                response = retry_call(
                    lambda: self.client.chat.completions.create(
                        model=selected_model,
                        messages=[{"role": "system", "content": instructions}, {"role": "user", "content": prompt}],
                        response_format={"type": "json_schema", "json_schema": {"name": schema.__name__, "strict": True, "schema": schema.model_json_schema()}},
                    ),
                    policy=self.retry_policy, cancelled=self._cancelled, wait=self._wait,
                    on_retry=self._retry_notice,
                )
                content = response.choices[0].message.content
                if not content:
                    raise RuntimeError("Provider returned no structured output.")
                return schema.model_validate_json(content)
            options = dict(
                model=model,
                instructions=instructions,
                input=prompt,
                text_format=schema,
                **kwargs,
            )
            options["model"] = selected_model
            if self._supports_reasoning(selected_model):
                options["reasoning"] = {"effort": effort}
            return retry_call(
                lambda: self.client.responses.parse(**options),
                policy=self.retry_policy,
                cancelled=self._cancelled,
                wait=self._wait,
                on_retry=self._retry_notice,
            )

        try:
            response = request(active_model)
        except Exception as exc:
            can_fallback = (
                active_model == model and self._model_not_found(exc)
                and self.fallback_model and self.fallback_model != model
            )
            if not can_fallback:
                raise
            self.model_fallbacks[model] = self.fallback_model
            if self.status_callback:
                self.status_callback(
                    f"Model {model!r} is not provisioned; using {self.fallback_model!r} for this session"
                )
            response = request(self.fallback_model)
        if self.protocol == "chat_completions":
            return response
        if response.output_parsed is None:
            raise RuntimeError("Model returned no structured output.")
        return response.output_parsed

    def classify_dependencies(self, items: list[str], custom_prompt: str, horizon_months: int, scan_mode: str = "both"):
        parsed = self._parse(
            model=self._model(TRIAGE_MODEL),
            instructions=TRIAGE_DEVELOPER_PROMPT,
            prompt=dependency_prompt(items, custom_prompt, horizon_months, scan_mode),
            schema=DependencyRiskMap,
            web=True,
            effort="low",
        )
        if len(parsed.ratings) != len(items):
            raise RuntimeError("Dependency classifier cardinality mismatch.")
        return parsed.ratings

    def deep_dependency(self, package: str, rating: str, custom_prompt: str) -> DependencyDeepReview:
        return self._parse(
            model=self._model(REVIEW_MODEL),
            instructions=DEPENDENCY_DEEP_DEVELOPER_PROMPT,
            prompt=dependency_deep_prompt(package, rating, custom_prompt),
            schema=DependencyDeepReview,
            web=True,
            effort="medium",
        )

    def forecast_dependency(self, package: str, rating: str, horizon_months: int, custom_prompt: str) -> AdvancedDependencyFutureReview:
        return self._parse(
            model=self._model(REVIEW_MODEL),
            instructions=DEPENDENCY_FORECAST_DEVELOPER_PROMPT,
            prompt=dependency_forecast_prompt(package, rating, horizon_months, custom_prompt),
            schema=AdvancedDependencyFutureReview,
            web=True,
            effort="high",
        )

    def classify_manifest(self, project_types: list[str], entries: list[dict], custom_prompt: str) -> list[str]:
        parsed = self._parse(
            model=self._model(TRIAGE_MODEL),
            instructions=TRIAGE_DEVELOPER_PROMPT,
            prompt=manifest_prompt(project_types=project_types, entries=entries, custom_prompt=custom_prompt),
            schema=Ratings,
            web=False,
            effort="low",
        )
        values = [r.value for r in parsed.ratings]
        if len(values) != len(entries):
            raise RuntimeError("Manifest classifier cardinality mismatch.")
        return values

    def review_source(self, *, path: str, project_types: list[str], rating: str, numbered: str, custom_prompt: str) -> SourceReview:
        return self._parse(
            model=self._model(REVIEW_MODEL),
            instructions=SOURCE_REVIEW_DEVELOPER_PROMPT,
            prompt=source_review_prompt(
                path=path,
                project_types=project_types,
                initial_rating=rating,
                numbered_source=numbered,
                custom_prompt=custom_prompt,
            ),
            schema=SourceReview,
            web=False,
            effort="high",
        )

    def propose_patch(self, *, path: str, source: str, finding_index: int, finding: dict) -> PatchProposal:
        return self._parse(
            model=self._model(DIFF_MODEL),
            instructions=SECURITY_DIFF_DEVELOPER_PROMPT,
            prompt=security_diff_prompt(path=path, source=source, finding_index=finding_index, finding=finding),
            schema=PatchProposal,
            web=False,
            effort="high",
        )

    def verify_patch(self, *, path: str, source: str, finding: dict, proposal: dict) -> PatchVerification:
        return self._parse(
            model=self._model(VERIFY_MODEL),
            instructions=DIFF_VERIFY_DEVELOPER_PROMPT,
            prompt=diff_verify_prompt(path=path, source=source, finding=finding, proposal=proposal),
            schema=PatchVerification,
            web=False,
            effort="high",
        )

    def close(self):
        try:
            self.client.close()
        except Exception:
            pass
        try:
            self.http_client.close()
        except Exception:
            pass


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1380x900")
        self.minsize(1100, 760)
        ctk.set_appearance_mode("system")
        ctk.set_default_color_theme("blue")

        self.events: queue.Queue = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.active_client: DaybreakClient | None = None
        self.client_lock = threading.Lock()
        self.requirements_path: Path | None = None
        self.manifest_root: Path | None = None
        self.manifest_data: dict | None = None
        self.latest_source_text = ""
        self.local_root: Path | None = None
        self.local_findings = []
        self.local_metadata: dict = {}
        self.selected_source_file: Path | None = None
        self.provider_store = ProviderStore()
        self._api_base_url = "https://api.openai.com/v1"
        self._api_protocol = "responses"

        self._build_ui()
        self.after(100, self._drain_events)
        self._refresh_key_status()
        self._apply_theme(self.theme_choice.get())
        self.after(350, self._show_startup_if_needed)

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(self, corner_radius=14, border_width=1)
        top.grid(row=0, column=0, padx=12, pady=(12, 6), sticky="ew")
        top.grid_columnconfigure(0, weight=1)

        heading = ctk.CTkFrame(top, fg_color="transparent")
        heading.grid(row=0, column=0, padx=18, pady=(14,8), sticky="ew")
        heading.grid_columnconfigure(0, weight=1)
        brand = ctk.CTkFrame(heading, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(brand, text="DAYBREAK", font=ctk.CTkFont(size=20, weight="bold"), anchor="w").pack(anchor="w")
        ctk.CTkLabel(brand, text="Security Workbench · local evidence + layered AI review", font=ctk.CTkFont(size=12), anchor="w").pack(anchor="w")
        self.key_status = ctk.CTkLabel(heading, text="", corner_radius=10, width=105, height=28)
        self.key_status.grid(row=0, column=1, padx=6)
        ctk.CTkButton(heading, text="Provider settings", command=self._open_provider_settings, width=130, fg_color="transparent", border_width=1).grid(row=0, column=2, padx=4)
        ctk.CTkButton(heading, text="Setup", command=self._open_startup_wizard, width=82).grid(row=0, column=3, padx=(4,0))

        toolbar = ctk.CTkFrame(top, corner_radius=10)
        toolbar.grid(row=1, column=0, padx=14, pady=(0,10), sticky="ew")
        toolbar.grid_columnconfigure(5, weight=1)
        ctk.CTkLabel(toolbar, text="Model", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=(12,5), pady=9)
        self.model_choice = ctk.StringVar(value="GPT-5.6 Terra — standard API")
        ctk.CTkOptionMenu(toolbar, values=list(MODEL_CHOICES), variable=self.model_choice, width=270).grid(row=0, column=1, padx=(0,12), pady=9)
        ctk.CTkLabel(toolbar, text="Theme", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=2, padx=(0,5), pady=9)
        self.theme_choice = ctk.StringVar(value="Daybreak Midnight")
        ctk.CTkOptionMenu(toolbar, values=list(THEME_PALETTES), variable=self.theme_choice, command=self._apply_theme, width=165).grid(row=0, column=3, padx=(0,12), pady=9)
        self.model_status = ctk.CTkLabel(toolbar, text="Daybreak Blue requires provisioning", anchor="w")
        self.model_status.grid(row=0, column=4, padx=(0,8), pady=9, sticky="w")

        self.live_web_var = ctk.BooleanVar(value=True)
        self.deep_scan_var = ctk.BooleanVar(value=True)
        switches = ctk.CTkFrame(top, fg_color="transparent")
        switches.grid(row=2, column=0, padx=18, pady=(0,12), sticky="ew")
        ctk.CTkCheckBox(switches, text="Live advisory evidence", variable=self.live_web_var).pack(side="left", padx=(0,18))
        ctk.CTkCheckBox(switches, text="Deep source review + verified patch", variable=self.deep_scan_var).pack(side="left")

        self.connection_panel = ctk.CTkFrame(top, corner_radius=10, border_width=1)
        self.connection_panel.grid(row=3, column=0, padx=14, pady=(0,12), sticky="ew")
        self.connection_panel.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(self.connection_panel, text="API key", font=ctk.CTkFont(weight="bold")).grid(row=0,column=0,padx=(12,8),pady=10)
        self.key_entry = ctk.CTkEntry(self.connection_panel, show="•", placeholder_text="Use saved key or enter a session key")
        self.key_entry.grid(row=0,column=1,padx=4,pady=10,sticky="ew")
        ctk.CTkButton(self.connection_panel, text="Save encrypted", command=self._save_key, width=120).grid(row=0,column=2,padx=4,pady=10)
        ctk.CTkButton(self.connection_panel, text="Forget", command=self._forget_key, width=80, fg_color="transparent", border_width=1).grid(row=0,column=3,padx=(4,12),pady=10)
        self.connection_panel.grid_remove()

        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=1, column=0, padx=12, pady=6, sticky="nsew")
        dep = self.tabs.add("Dependencies")
        man = self.tabs.add("Manifest")
        review = self.tabs.add("Deep Source Review")
        local = self.tabs.add("Local Super Scan")
        self._build_dependency_tab(dep)
        self._build_manifest_tab(man)
        self._build_review_tab(review)
        self._build_local_tab(local)

        bottom = ctk.CTkFrame(self)
        bottom.grid(row=2, column=0, padx=12, pady=(6,12), sticky="ew")
        bottom.grid_columnconfigure(1, weight=1)
        self.cancel_btn = ctk.CTkButton(bottom, text="Cancel", command=self._cancel, state="disabled")
        self.cancel_btn.grid(row=0, column=0, padx=8, pady=8)
        self.progress = ctk.CTkProgressBar(bottom, mode="indeterminate")
        self.progress.grid(row=0, column=1, padx=8, pady=8, sticky="ew")
        self.progress.set(0)

    def _common_prompt_box(self, parent, row: int):
        ctk.CTkLabel(parent, text="Operator preference (untrusted, lower-priority than security protocol)").grid(row=row, column=0, columnspan=3, padx=8, pady=(8,2), sticky="w")
        box = ctk.CTkTextbox(parent, height=78)
        box.grid(row=row+1, column=0, columnspan=3, padx=8, pady=(0,8), sticky="ew")
        box.insert("1.0", DEFAULT_USER_PROMPT)
        return box

    def _build_dependency_tab(self, parent):
        parent.grid_columnconfigure(1, weight=1); parent.grid_rowconfigure(4, weight=1)
        ctk.CTkButton(parent, text="Choose lockfile", command=self._pick_requirements).grid(row=0, column=0, padx=8, pady=8)
        self.dep_path_label = ctk.CTkLabel(parent, text="No file selected", anchor="w")
        self.dep_path_label.grid(row=0, column=1, padx=8, pady=8, sticky="ew")
        self.dep_scan_btn = ctk.CTkButton(parent, text="Layered dependency scan", command=self._start_dependency_scan)
        self.dep_scan_btn.grid(row=0, column=2, padx=8, pady=8)
        self.dep_prompt = self._common_prompt_box(parent, 1)
        forecast = ctk.CTkFrame(parent, fg_color="transparent")
        forecast.grid(row=3, column=0, columnspan=3, padx=8, pady=(0,2), sticky="ew")
        ctk.CTkLabel(forecast, text="Scan mode").pack(side="left", padx=(0,8))
        self.dependency_mode = ctk.StringVar(value="Current + future")
        ctk.CTkOptionMenu(
            forecast, values=["Current packages/CVEs", "Future horizon only", "Current + future"],
            variable=self.dependency_mode, command=self._dependency_mode_changed, width=190,
        ).pack(side="left", padx=(0,18))
        ctk.CTkLabel(forecast, text="Future horizon").pack(side="left", padx=(0,8))
        self.forecast_horizon = ctk.StringVar(value="12 months")
        self.forecast_menu = ctk.CTkOptionMenu(forecast, values=["1 month", "6 months", "12 months", "36 months"], variable=self.forecast_horizon, width=130)
        self.forecast_menu.pack(side="left")
        ctk.CTkLabel(forecast, text="Depth").pack(side="left", padx=(18,8))
        self.dependency_depth = ctk.StringVar(value="Fast")
        ctk.CTkOptionMenu(forecast, values=["Fast", "Balanced", "Exhaustive"], variable=self.dependency_depth, width=125).pack(side="left")
        self.dep_output = ctk.CTkTextbox(parent)
        self.dep_output.grid(row=4, column=0, columnspan=3, padx=8, pady=(8,8), sticky="nsew")

    def _build_manifest_tab(self, parent):
        parent.grid_columnconfigure(1, weight=1); parent.grid_rowconfigure(4, weight=1)
        ctk.CTkButton(parent, text="Choose project folder", command=self._pick_folder).grid(row=0, column=0, padx=8, pady=8)
        self.man_path_label = ctk.CTkLabel(parent, text="No folder selected", anchor="w")
        self.man_path_label.grid(row=0, column=1, padx=8, pady=8, sticky="ew")
        btns = ctk.CTkFrame(parent, fg_color="transparent"); btns.grid(row=0, column=2, padx=8, pady=8)
        ctk.CTkButton(btns, text="Create manifest", command=self._create_manifest).pack(side="left", padx=3)
        self.man_scan_btn = ctk.CTkButton(btns, text="Triage + deep review", command=self._start_manifest_scan); self.man_scan_btn.pack(side="left", padx=3)
        self.man_prompt = self._common_prompt_box(parent, 1)
        self.man_output = ctk.CTkTextbox(parent)
        self.man_output.grid(row=4, column=0, columnspan=3, padx=8, pady=(8,8), sticky="nsew")

    def _build_review_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1); parent.grid_columnconfigure(1, weight=2)
        parent.grid_rowconfigure(1, weight=2); parent.grid_rowconfigure(3, weight=1)
        review_controls=ctk.CTkFrame(parent,fg_color="transparent")
        review_controls.grid(row=0,column=0,columnspan=2,padx=8,pady=8,sticky="ew")
        ctk.CTkButton(review_controls,text="Choose source file",command=self._pick_source_file,width=145).pack(side="left")
        ctk.CTkButton(review_controls,text="Review selected",command=self._start_selected_source_review,width=130).pack(side="left",padx=8)
        self.review_file_label = ctk.CTkLabel(review_controls, text="No source file selected", anchor="w")
        self.review_file_label.pack(side="left",padx=8,fill="x",expand=True)
        self.findings_output = ctk.CTkTextbox(parent, width=430)
        self.findings_output.grid(row=1, column=0, padx=(8,4), pady=4, sticky="nsew")
        self.source_code = ctk.CTkTextbox(parent)
        self.source_code.grid(row=1, column=1, padx=(4,8), pady=4, sticky="nsew")
        ctk.CTkLabel(parent, text="Verified candidate security diffs (never auto-applied)").grid(row=2, column=0, columnspan=2, padx=8, pady=(8,2), sticky="w")
        self.diff_output = ctk.CTkTextbox(parent)
        self.diff_output.grid(row=3, column=0, columnspan=2, padx=8, pady=(0,8), sticky="nsew")

    def _build_local_tab(self, parent):
        parent.grid_columnconfigure(1, weight=1)
        parent.grid_rowconfigure(3, weight=1)
        ctk.CTkButton(parent, text="Choose project folder", command=self._pick_local_folder).grid(row=0, column=0, padx=8, pady=8)
        self.local_path_label = ctk.CTkLabel(parent, text="No folder selected", anchor="w")
        self.local_path_label.grid(row=0, column=1, padx=8, pady=8, sticky="ew")
        self.local_scan_btn = ctk.CTkButton(parent, text="Run 14-engine scan", command=self._start_local_scan)
        self.local_scan_btn.grid(row=0, column=2, padx=8, pady=8)

        controls = ctk.CTkFrame(parent)
        controls.grid(row=1, column=0, columnspan=3, padx=8, pady=4, sticky="ew")
        ctk.CTkLabel(controls, text="Minimum severity").pack(side="left", padx=(8,4), pady=8)
        self.local_severity = ctk.StringVar(value="medium")
        ctk.CTkOptionMenu(controls, values=list(SEVERITY_VALUE), variable=self.local_severity, width=120).pack(side="left", padx=4)
        ctk.CTkLabel(controls, text="Minimum confidence").pack(side="left", padx=(18,4))
        self.local_confidence = ctk.CTkEntry(controls, width=80)
        self.local_confidence.insert(0, "0.0")
        self.local_confidence.pack(side="left", padx=4)
        ctk.CTkLabel(controls, text="Profile").pack(side="left", padx=(18,4))
        self.local_profile = ctk.StringVar(value="Application source")
        ctk.CTkOptionMenu(controls, values=["Application source","Full repository","CI / infrastructure"], variable=self.local_profile, width=165).pack(side="left",padx=4)
        ctk.CTkButton(controls, text="Export JSON", width=105, command=lambda: self._export_local("json")).pack(side="right", padx=4)
        ctk.CTkButton(controls, text="Export SARIF", width=105, command=lambda: self._export_local("sarif")).pack(side="right", padx=4)

        self.local_summary = ctk.CTkLabel(parent, text=f"Daybreak deterministic scanner v{SCANNER_VERSION} · local-only · no API key required", anchor="w")
        self.local_summary.grid(row=2, column=0, columnspan=3, padx=8, pady=(6,2), sticky="ew")
        self.local_output = ctk.CTkTextbox(parent, font=("Courier", 13))
        self.local_output.grid(row=3, column=0, columnspan=3, padx=8, pady=8, sticky="nsew")
        widget = self.local_output._textbox
        widget.tag_configure("critical", foreground="#ff5f73")
        widget.tag_configure("high", foreground="#ff955c")
        widget.tag_configure("medium", foreground="#e7be45")
        widget.tag_configure("low", foreground="#65c78a")

    def _style_widget_tree(self, widget, palette):
        for child in widget.winfo_children():
            try:
                if isinstance(child, ctk.CTkTabview):
                    child.configure(
                        fg_color=palette["surface"], border_color=palette["border"],
                        segmented_button_selected_color=palette["accent"],
                        segmented_button_selected_hover_color=palette["hover"],
                        segmented_button_unselected_color=palette["panel"],
                        text_color=palette["text"],
                    )
                elif isinstance(child, ctk.CTkTextbox):
                    child.configure(fg_color=palette["textbox"], text_color=palette["text"], border_color=palette["border"])
                elif isinstance(child, ctk.CTkEntry):
                    child.configure(fg_color=palette["textbox"], text_color=palette["text"], border_color=palette["border"], placeholder_text_color=palette["muted"])
                elif isinstance(child, ctk.CTkButton):
                    if child.cget("fg_color") != "transparent":
                        child.configure(fg_color=palette["accent"], hover_color=palette["hover"], text_color=palette["text"])
                    child.configure(border_color=palette["border"])
                elif isinstance(child, ctk.CTkOptionMenu):
                    child.configure(fg_color=palette["accent"], button_color=palette["hover"], button_hover_color=palette["accent"], text_color=palette["text"], dropdown_fg_color=palette["surface"], dropdown_text_color=palette["text"], dropdown_hover_color=palette["panel"])
                elif isinstance(child, ctk.CTkCheckBox):
                    child.configure(fg_color=palette["accent"], hover_color=palette["hover"], border_color=palette["border"], text_color=palette["text"])
                elif isinstance(child, ctk.CTkProgressBar):
                    child.configure(fg_color=palette["panel"], progress_color=palette["accent"], border_color=palette["border"])
                elif isinstance(child, ctk.CTkLabel):
                    child.configure(text_color=palette["text"])
                elif isinstance(child, ctk.CTkFrame):
                    current = child.cget("fg_color")
                    child.configure(fg_color="transparent" if current == "transparent" else palette["surface"], border_color=palette["border"])
            except Exception:
                # CustomTkinter versions expose slightly different style options.
                pass
            self._style_widget_tree(child, palette)

    def _apply_theme(self, name):
        palette = THEME_PALETTES.get(name, THEME_PALETTES["Daybreak Midnight"])
        ctk.set_appearance_mode(palette["mode"])
        self.configure(fg_color=palette["window"])
        self._style_widget_tree(self, palette)
        if hasattr(self, "key_status"):
            self.key_status.configure(fg_color=palette["panel"], text_color=palette["accent"])
        if hasattr(self, "model_status"):
            self.model_status.configure(text_color=palette["muted"])
        if hasattr(self, "_startup_window") and self._startup_window and self._startup_window.winfo_exists():
            self._startup_window.configure(fg_color=palette["window"])
            self._style_widget_tree(self._startup_window, palette)

    def _show_startup_if_needed(self):
        if not has_saved_key() and not self.key_entry.get().strip():
            self._open_startup_wizard()

    def _open_startup_wizard(self):
        existing = getattr(self, "_startup_window", None)
        if existing and existing.winfo_exists():
            existing.lift()
            return
        wizard = ctk.CTkToplevel(self)
        self._startup_window = wizard
        wizard.title("Welcome to Daybreak Security Workbench")
        wizard.geometry("720x520")
        wizard.minsize(640, 460)
        wizard.transient(self)
        wizard.grab_set()
        wizard.grid_columnconfigure(0, weight=1)
        wizard.grid_rowconfigure(0, weight=1)
        body = ctk.CTkFrame(wizard, corner_radius=16, border_width=1)
        body.grid(row=0, column=0, padx=22, pady=22, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(2, weight=1)

        step_label = ctk.CTkLabel(body, text="WELCOME · STEP 1 OF 2", font=ctk.CTkFont(size=12, weight="bold"), anchor="w")
        step_label.grid(row=0, column=0, padx=28, pady=(26,4), sticky="ew")
        title = ctk.CTkLabel(body, text="Local evidence first. AI depth when you choose.", font=ctk.CTkFont(size=26, weight="bold"), anchor="w")
        title.grid(row=1, column=0, padx=28, pady=(4,14), sticky="ew")
        content = ctk.CTkFrame(body, fg_color="transparent")
        content.grid(row=2, column=0, padx=28, pady=4, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        actions = ctk.CTkFrame(body, fg_color="transparent")
        actions.grid(row=3, column=0, padx=28, pady=(12,26), sticky="ew")

        def clear(frame):
            for child in frame.winfo_children():
                child.destroy()

        def close_local():
            try:
                wizard.grab_release()
            except Exception:
                pass
            wizard.destroy()
            self._startup_window = None

        def show_credentials():
            clear(content); clear(actions)
            step_label.configure(text="SECURE CREDENTIALS · STEP 2 OF 2")
            title.configure(text="Connect an API project")
            ctk.CTkLabel(content, text="The API key enables dependency evidence, source review, patch generation, and verification. It is never required for Local Super Scan.", wraplength=620, justify="left", anchor="w").grid(row=0,column=0,pady=(4,14),sticky="ew")
            ctk.CTkLabel(content, text="API key", anchor="w", font=ctk.CTkFont(weight="bold")).grid(row=1,column=0,pady=(4,4),sticky="ew")
            key = ctk.CTkEntry(content, show="•", placeholder_text="sk-…", height=42)
            key.grid(row=2,column=0,pady=(0,8),sticky="ew"); key.focus_set()
            reveal = ctk.BooleanVar(value=False)
            ctk.CTkCheckBox(content, text="Show key", variable=reveal, command=lambda:key.configure(show="" if reveal.get() else "•")).grid(row=3,column=0,pady=(2,12),sticky="w")
            ctk.CTkLabel(content, text="Model", anchor="w", font=ctk.CTkFont(weight="bold")).grid(row=4,column=0,pady=(4,4),sticky="ew")
            wizard_model = ctk.StringVar(value=self.model_choice.get())
            ctk.CTkOptionMenu(content, values=list(MODEL_CHOICES), variable=wizard_model, width=310).grid(row=5,column=0,pady=(0,12),sticky="w")
            ctk.CTkLabel(content, text="Encrypted storage uses AES-GCM; its master key is held by the OS credential vault. Daybreak Blue requires separate API provisioning.", wraplength=620, justify="left", anchor="w").grid(row=6,column=0,pady=6,sticky="ew")

            def accept(persist):
                value = key.get().strip()
                if not value:
                    return messagebox.showwarning("API key", "Enter an API key or continue in local-only mode.", parent=wizard)
                try:
                    if persist:
                        save_api_key(value)
                    else:
                        self.key_entry.delete(0,"end"); self.key_entry.insert(0,value)
                    self.model_choice.set(wizard_model.get())
                    self._refresh_key_status()
                    close_local()
                except Exception as exc:
                    messagebox.showerror("Secure storage error", clean_for_ui(exc,1000), parent=wizard)

            ctk.CTkButton(actions,text="Back",command=show_welcome,fg_color="transparent",border_width=1,width=90).pack(side="left")
            ctk.CTkButton(actions,text="Use for this session",command=lambda:accept(False),fg_color="transparent",border_width=1,width=150).pack(side="right",padx=(8,0))
            ctk.CTkButton(actions,text="Save encrypted & continue",command=lambda:accept(True),width=190).pack(side="right")
            self._apply_theme(self.theme_choice.get())

        def show_welcome():
            clear(content); clear(actions)
            step_label.configure(text="WELCOME · STEP 1 OF 2")
            title.configure(text="Local evidence first. AI depth when you choose.")
            cards = (
                ("LOCAL SUPER SCAN", "Fourteen deterministic engines, TUI/CLI parity, SARIF export, and no source transmission. No API key required."),
                ("AI-ASSISTED LAYERS", "Current-CVE evidence, future-risk timelines, deep source review, minimal patch proposals, and independent verification."),
            )
            for row,(heading,description) in enumerate(cards):
                card=ctk.CTkFrame(content,corner_radius=12,border_width=1)
                card.grid(row=row,column=0,pady=7,sticky="ew")
                ctk.CTkLabel(card,text=heading,font=ctk.CTkFont(size=14,weight="bold"),anchor="w").pack(fill="x",padx=18,pady=(14,3))
                ctk.CTkLabel(card,text=description,wraplength=570,justify="left",anchor="w").pack(fill="x",padx=18,pady=(0,14))
            ctk.CTkButton(actions,text="Continue without API",command=close_local,fg_color="transparent",border_width=1,width=170).pack(side="left")
            ctk.CTkButton(actions,text="Configure API access",command=show_credentials,width=180).pack(side="right")
            self._apply_theme(self.theme_choice.get())

        wizard.protocol("WM_DELETE_WINDOW", close_local)
        show_welcome()

    def _toggle_connection_panel(self):
        if self.connection_panel.winfo_ismapped():
            self.connection_panel.grid_remove()
        else:
            self.connection_panel.grid()
            self.key_entry.focus_set()

    def _dependency_mode_changed(self, selected):
        self.forecast_menu.configure(state="disabled" if selected == "Current packages/CVEs" else "normal")

    def _refresh_key_status(self):
        saved = self.provider_store.exists() or has_saved_key()
        self.key_status.configure(text="● API READY" if saved else "○ LOCAL ONLY")
    def _save_key(self):
        try:
            save_api_key(self.key_entry.get()); self.key_entry.delete(0,"end"); self._refresh_key_status()
        except Exception as exc: messagebox.showerror("Secure storage error", clean_for_ui(exc,1000))
    def _forget_key(self):
        try:
            self.provider_store.forget(); forget_api_key(); self.key_entry.delete(0,"end"); self.model_choice.set("GPT-5.6 Terra — standard API"); self._provider_model=None; self._refresh_key_status(); self.after(100,self._open_startup_wizard)
        except Exception as exc: messagebox.showerror("Secure storage error", clean_for_ui(exc,1000))

    def _open_provider_settings(self):
        window=ctk.CTkToplevel(self); window.title("Secure provider profile"); window.geometry("760x620"); window.transient(self); window.grab_set(); window.grid_columnconfigure(1,weight=1)
        stored=None
        try: stored=self.provider_store.load(resolve_dns=False)
        except Exception as exc: messagebox.showerror("Provider profile",clean_for_ui(exc,1000),parent=window)
        fields={}
        def field(row,label,value="",secret=False):
            ctk.CTkLabel(window,text=label,anchor="w",font=ctk.CTkFont(weight="bold")).grid(row=row,column=0,padx=(22,8),pady=8,sticky="w")
            entry=ctk.CTkEntry(window,show="•" if secret else ""); entry.grid(row=row,column=1,padx=(4,22),pady=8,sticky="ew"); entry.insert(0,value); fields[label]=entry
        preset=ctk.StringVar(value=stored.provider if stored and stored.provider in PROVIDER_PRESETS else "OpenAI")
        ctk.CTkLabel(window,text="Provider preset",font=ctk.CTkFont(weight="bold")).grid(row=0,column=0,padx=(22,8),pady=(22,8),sticky="w")
        menu=ctk.CTkOptionMenu(window,values=list(PROVIDER_PRESETS),variable=preset); menu.grid(row=0,column=1,padx=(4,22),pady=(22,8),sticky="ew")
        field(1,"Profile label",stored.label if stored else "Primary")
        field(2,"HTTPS API endpoint",stored.base_url if stored else PROVIDER_PRESETS["OpenAI"][0])
        field(3,"Model ID",stored.model if stored else PROVIDER_PRESETS["OpenAI"][1])
        field(4,"API key","",True)
        protocol=ctk.StringVar(value=stored.protocol if stored else "responses")
        ctk.CTkLabel(window,text="Protocol",font=ctk.CTkFont(weight="bold")).grid(row=5,column=0,padx=(22,8),pady=8,sticky="w")
        ctk.CTkOptionMenu(window,values=["responses","chat_completions"],variable=protocol).grid(row=5,column=1,padx=(4,22),pady=8,sticky="ew")
        note=ctk.CTkLabel(window,text="Kimi K2.5 is the currently documented DigitalOcean model. Kimi K3 can be entered as a custom model ID after your provider officially exposes it. Meta Muse Spark 1.1 preview routing values must be copied from the Meta console; Daybreak will not guess them. Custom endpoints must be public HTTPS and are revalidated before use.",wraplength=700,justify="left",anchor="w")
        note.grid(row=6,column=0,columnspan=2,padx=22,pady=12,sticky="ew")
        def apply_preset(choice):
            endpoint,model,style=PROVIDER_PRESETS[choice]
            for label,value in (("HTTPS API endpoint",endpoint),("Model ID",model)):
                fields[label].delete(0,"end"); fields[label].insert(0,value)
            protocol.set(style)
        menu.configure(command=apply_preset)
        def save():
            try:
                existing_key=stored.api_key if stored else ""
                profile=ProviderProfile(fields["Profile label"].get(),preset.get(),fields["HTTPS API endpoint"].get(),fields["Model ID"].get(),fields["API key"].get().strip() or existing_key,protocol.get())
                self.provider_store.save(profile); self._refresh_key_status(); window.destroy()
            except Exception as exc: messagebox.showerror("Secure provider settings",clean_for_ui(exc,1500),parent=window)
        actions=ctk.CTkFrame(window,fg_color="transparent"); actions.grid(row=7,column=0,columnspan=2,padx=22,pady=18,sticky="ew")
        ctk.CTkButton(actions,text="Cancel",command=window.destroy,fg_color="transparent",border_width=1).pack(side="left")
        ctk.CTkButton(actions,text="Validate & save encrypted",command=save,width=210).pack(side="right")
    def _pick_requirements(self):
        selected = filedialog.askopenfilename(
            title="Select dependency manifest or lockfile",
            filetypes=[
                ("Dependency files", "requirements*.txt package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml Cargo.lock go.sum pubspec.lock composer.lock Gemfile.lock Pipfile.lock poetry.lock uv.lock packages.lock.json gradle.lockfile Package.resolved Podfile.lock conan.lock vcpkg.json"),
                ("All files", "*.*"),
            ],
        )
        if selected: self.requirements_path=Path(selected); self.dep_path_label.configure(text=clean_for_ui(selected,1000))
    def _pick_folder(self):
        selected = filedialog.askdirectory(title="Select local project folder")
        if selected: self.manifest_root=Path(selected); self.manifest_data=None; self.man_path_label.configure(text=clean_for_ui(selected,1000))
    def _pick_local_folder(self):
        selected = filedialog.askdirectory(title="Select project for local security scan")
        if selected:
            self.local_root = Path(selected)
            self.local_path_label.configure(text=clean_for_ui(selected,1000))
    def _pick_source_file(self):
        selected=filedialog.askopenfilename(title="Select source file",filetypes=[("Source files","*.py *.pyi *.js *.jsx *.ts *.tsx *.go *.rs *.java *.kt *.cs *.php *.rb *.dart *.swift *.c *.h *.cpp *.hpp *.sh *.ps1 *.sql"),("All files","*.*")])
        if selected:
            self.selected_source_file=Path(selected)
            self.review_file_label.configure(text=clean_for_ui(selected,1000))
    def _create_manifest(self):
        if not self.manifest_root: return messagebox.showwarning("Manifest","Choose a project folder first.")
        try:
            self.manifest_data=build_manifest(self.manifest_root); self.man_output.delete("1.0","end"); self.man_output.insert("end",manifest_as_json(self.manifest_data))
        except Exception as exc: messagebox.showerror("Manifest error", clean_for_ui(exc,1000))
    def _get_api_key(self):
        entered=self.key_entry.get().strip()
        if entered:
            self._api_base_url="https://api.openai.com/v1"; self._api_protocol="responses"; self._provider_model=None
            if self.model_choice.get() not in MODEL_CHOICES: self.model_choice.set("GPT-5.6 Terra — standard API")
            return entered
        profile=self.provider_store.load()
        if profile:
            self._api_base_url=profile.base_url; self._api_protocol=profile.protocol; self.model_choice.set(profile.model); self.model_status.configure(text=f"{profile.provider} · {profile.protocol}"); self._provider_model=profile.model; return profile.api_key
        saved=load_api_key()
        if not saved: raise SecureStoreError("Enter an API key or save one securely first.")
        self._api_base_url="https://api.openai.com/v1"; self._api_protocol="responses"; self._provider_model=None
        return saved

    def _selected_model(self):
        return getattr(self,"_provider_model",None) or MODEL_CHOICES[self.model_choice.get()]
    def _set_busy(self,busy):
        state="disabled" if busy else "normal"; self.dep_scan_btn.configure(state=state); self.man_scan_btn.configure(state=state); self.local_scan_btn.configure(state=state); self.cancel_btn.configure(state="normal" if busy else "disabled")
        if busy: self.progress.start()
        else: self.progress.stop(); self.progress.set(0)
    def _cancel(self):
        if self.cancel_event.is_set():
            return
        self.cancel_event.set()
        self.cancel_btn.configure(state="disabled", text="Cancelling…")
        self.title(f"{APP_TITLE} — cancelling active requests")
        self.events.put(("dep","\nCANCEL REQUESTED — interrupting active network work…\n"))
        with self.client_lock:
            client=self.active_client
        if client:
            # Closing the pool interrupts active reads; do it off the Tk event loop.
            threading.Thread(target=client.close,daemon=True,name="daybreak-cancel").start()
    def _launch(self,target,*args):
        if self.worker and self.worker.is_alive(): return
        self.cancel_event.clear(); self._set_busy(True); self.worker=threading.Thread(target=target,args=args,daemon=True); self.worker.start()

    def _start_dependency_scan(self):
        if not self.requirements_path: return messagebox.showwarning("Dependencies","Choose a supported dependency file first.")
        try:
            api_key = self._get_api_key()
        except Exception as exc:
            return messagebox.showerror("API key error", clean_for_ui(exc, 1000))
        mode_labels={"Current packages/CVEs":"current","Future horizon only":"future","Current + future":"both"}
        scan_mode=mode_labels[self.dependency_mode.get()]
        depth=self.dependency_depth.get().lower()
        horizon=int(self.forecast_horizon.get().split()[0]); prompt=self.dep_prompt.get("1.0","end").strip(); live_web=bool(self.live_web_var.get()); model=self._selected_model(); self.dep_output.delete("1.0","end"); self._launch(self._dependency_worker,self.requirements_path,prompt,api_key,live_web,model,horizon,scan_mode,depth)

    def _start_selected_source_review(self):
        if not self.selected_source_file:
            return messagebox.showwarning("Source review","Choose a source file first.")
        try:
            api_key=self._get_api_key()
        except Exception as exc:
            return messagebox.showerror("API key error",clean_for_ui(exc,1000))
        model=self._selected_model()
        self.findings_output.delete("1.0","end"); self.diff_output.delete("1.0","end")
        self._launch(self._selected_source_worker,self.selected_source_file,api_key,model)

    def _selected_source_worker(self,path,api_key,model):
        client=None
        try:
            resolved=path.resolve(strict=True)
            root=self.manifest_root.resolve(strict=True) if self.manifest_root else resolved.parent
            try: relative=resolved.relative_to(root).as_posix()
            except ValueError: root=resolved.parent; relative=resolved.name
            snap=load_source_snapshot(root,relative)
            client=DaybreakClient(api_key,live_web=False,cancel_event=self.cancel_event,status_callback=lambda message:self.events.put(("status",message)),model_override=model,base_url=self._api_base_url,protocol=self._api_protocol)
            with self.client_lock: self.active_client=client
            self.events.put(("status",f"Reviewing {relative}"))
            review=client.review_source(path=relative,project_types=infer_project_types(root),rating="medium",numbered=number_source(snap.text),custom_prompt=DEFAULT_USER_PROMPT)
            findings=validate_finding_spans(review.findings,snap.line_count)[:MAX_FINDINGS_PER_FILE]
            bundles=[{"finding":finding.model_dump(),"proposal":None,"local_patch_ok":False,"patch_reason":"Direct review completed; generate a verified patch from project deep review.","verification":None} for finding in findings]
            self.events.put(("source_bundle",{"path":relative,"source":snap.text,"bundles":bundles,"no_findings_reason":review.no_findings_reason}))
            self.events.put(("man",f"Direct source review {relative}: {len(findings)} validated finding(s).\n"))
        except Exception as exc:
            self.events.put(("man",f"Direct source review failed: {clean_for_ui(exc,2000)}\n"))
        finally:
            if client: client.close()
            with self.client_lock:
                if self.active_client is client: self.active_client=None
            self.events.put(("done",None))

    def _start_local_scan(self):
        if not self.local_root:
            return messagebox.showwarning("Local scan", "Choose a project folder first.")
        try:
            confidence = float(self.local_confidence.get().strip())
            if not 0.0 <= confidence <= 1.0:
                raise ValueError
        except ValueError:
            return messagebox.showwarning("Local scan", "Minimum confidence must be between 0.0 and 1.0.")
        self.local_output._textbox.configure(state="normal")
        self.local_output.delete("1.0", "end")
        self.local_summary.configure(text="Scanning locally…")
        self._launch(self._local_worker, self.local_root, self.local_severity.get(), confidence, self.local_profile.get())

    def _local_worker(self, root, severity, confidence, profile="Application source"):
        try:
            profiles={
                "Application source": frozenset(ENGINE_DESCRIPTIONS)-{"cicd","iac"},
                "Full repository": frozenset(ENGINE_DESCRIPTIONS),
                "CI / infrastructure": frozenset({"cicd","iac","supply-chain","secrets","entropy"}),
            }
            engines=profiles[profile]
            findings, metadata = local_security_scan(
                root.resolve(strict=True), engines,
                min(32, (os.cpu_count() or 2) + 4), 25_000, set(),
            )
            threshold = SEVERITY_VALUE[severity]
            findings = [f for f in findings if SEVERITY_VALUE[f.severity] >= threshold and f.confidence >= confidence]
            metadata["findings_after_gui_filters"] = len(findings)
            metadata["profile"] = profile
            self.events.put(("local_result", {"findings": findings, "metadata": metadata}))
        except Exception as exc:
            self.events.put(("local_error", clean_for_ui(exc, 4000)))
        finally:
            self.events.put(("done", None))

    def _current_dependency_detail(self, client, item, current, custom_prompt):
        deep=client.deep_dependency(item,current,custom_prompt)
        final=deep.confirmed_risk.value
        correction=" (triage corrected)" if final != current else ""
        return f"  ↳ FINAL CURRENT={final.upper()}{correction}; applicable={'yes' if deep.applicable else 'no'}\n  ↳ evidence confidence={deep.confidence:.2f}: {deep.evidence_summary}\n  ↳ action: {deep.recommended_action}\n  ↳ safer/fixed: {deep.fixed_or_safer_version or 'not established'}\n\n"

    def _future_dependency_detail(self, client, item, future, horizon_months, custom_prompt):
        forecast=client.forecast_dependency(item,future,horizon_months,custom_prompt)
        drivers="; ".join(forecast.risk_drivers) or "none established"
        actions="; ".join(forecast.preventive_actions) or "continue monitoring"
        triggers="; ".join(forecast.monitoring_triggers) or "new advisories or releases"
        curve=" → ".join(f"{point.month}m:{point.risk.upper()}({point.confidence:.2f})" for point in sorted(forecast.risk_timeline,key=lambda point:point.month))
        facts="; ".join(forecast.observed_facts) or "none established"
        inferences="; ".join(forecast.bounded_inferences) or "none"
        unknowns="; ".join(forecast.critical_unknowns) or "none material"
        controls="; ".join(forecast.control_assumptions) or "no compensating controls established"
        scenarios="\n".join(f"      {scenario.name}: {scenario.risk.upper()} | signal={scenario.leading_signal} | mitigation={scenario.mitigation}" for scenario in forecast.scenarios)
        indicators="\n".join(f"      {indicator.metric} | trigger={indicator.trigger} | response={indicator.response}" for indicator in forecast.leading_indicators)
        return f"  ↳ ADVANCED FUTURE-RISK FORECAST [{forecast.risk.upper()} confidence={forecast.confidence:.2f}]: {forecast.forecast_summary}\n  ↳ temporal curve: {curve}\n  ↳ inherent→residual: {forecast.inherent_risk.upper()}→{forecast.residual_risk.upper()}\n  ↳ control assumptions: {controls}\n  ↳ highest-leverage control: {forecast.highest_leverage_control}\n  ↳ observed facts: {facts}\n  ↳ bounded inferences: {inferences}\n  ↳ critical unknowns: {unknowns}\n  ↳ drivers: {drivers}\n  ↳ uncertainty: {forecast.uncertainty}\n  ↳ preventive actions: {actions}\n  ↳ monitoring triggers: {triggers}\n  ↳ stress scenarios:\n{scenarios}\n  ↳ leading indicators:\n{indicators}\n  ↳ {forecast.disclaimer}\n\n"

    def _dependency_worker(self,path,custom_prompt,api_key,live_web,model,horizon_months,scan_mode="both",depth="fast"):
        client=None; pool=None
        try:
            records,skipped=parse_dependency_file(path)
            items=[record.display() for record in records]
            ecosystems=", ".join(sorted({record.ecosystem for record in records}))
            exact=sum(record.exact for record in records)
            labels={"current":"current package/CVE evidence", "future":"future-risk horizon", "both":"current evidence + future-risk horizon"}
            self.events.put(("dep",f"Loaded {len(items)} dependencies from {path.name} ({ecosystems}); {exact} exact pins, {len(items)-exact} constraints; skipped {len(skipped)} unsupported entries.\nMode: {labels[scan_mode]}; future horizon: {horizon_months} month(s); depth: {depth}.\n\n"))
            client=DaybreakClient(api_key,live_web,self.cancel_event,lambda message:self.events.put(("status",message)),model_override=model,base_url=self._api_base_url,protocol=self._api_protocol)
            with self.client_lock: self.active_client=client
            for start in range(0,len(items),DEPENDENCY_BATCH):
                if self.cancel_event.is_set(): return
                batch=items[start:start+DEPENDENCY_BATCH]; ratings=client.classify_dependencies(batch,custom_prompt,horizon_months,scan_mode)
                detail_jobs=[]
                for item,rating in zip(batch,ratings):
                    current=rating.current_risk.value; requested_future=rating.future_risk.value
                    gate=tune_future_risk(requested_future,current,horizon_months,rating.surface_signals,rating.future_confidence)
                    future=gate.calibrated
                    current_label="TRIAGE" if depth != "fast" and current in {"medium","high"} and scan_mode in {"current","both"} else "CURRENT"
                    if scan_mode == "current":
                        self.events.put(("dep",f"{item:<52} {current_label}={current.upper():<6}\n"))
                    elif scan_mode == "future":
                        self.events.put(("dep",f"{item:<52} FUTURE({horizon_months}m)={future.upper():<6} model={requested_future.upper():<6} confidence={rating.future_confidence:.2f}\n  ↳ entropy gate: {gate.reason}; supercharge={'active' if gate.supercharged else 'inactive'}\n"))
                    else:
                        self.events.put(("dep",f"{item:<52} {current_label}={current.upper():<6} FUTURE({horizon_months}m)={future.upper():<6} model={requested_future.upper():<6} confidence={rating.future_confidence:.2f}\n  ↳ entropy gate: {gate.reason}; supercharge={'active' if gate.supercharged else 'inactive'}\n"))
                    if depth != "fast" and scan_mode in {"current","both"} and current in {"medium","high"}:
                        detail_jobs.append((item,"current",self._current_dependency_detail,(client,item,current,custom_prompt)))
                    if depth != "fast" and scan_mode in {"future","both"} and future in {"medium","high"}:
                        detail_jobs.append((item,"future",self._future_dependency_detail,(client,item,future,horizon_months,custom_prompt)))
                if depth == "fast":
                    self.events.put(("dep","  Fast depth: ratings and entropy calibration complete; per-package web dossiers skipped.\n\n"))
                elif detail_jobs:
                    workers=min(len(detail_jobs), 4 if depth == "balanced" else 2)
                    self.events.put(("dep",f"\nEvidence stage: {len(detail_jobs)} dossier(s), {workers} concurrent worker(s).\n"))
                    pool=concurrent.futures.ThreadPoolExecutor(max_workers=workers,thread_name_prefix="daybreak-evidence")
                    pending={pool.submit(function,*arguments):(item,kind) for item,kind,function,arguments in detail_jobs}
                    for completed,future_job in enumerate(concurrent.futures.as_completed(pending),1):
                        item,kind=pending[future_job]
                        if self.cancel_event.is_set():
                            for job in pending: job.cancel()
                            pool.shutdown(wait=False,cancel_futures=True); pool=None
                            return
                        try:
                            detail=future_job.result()
                        except Exception as exc:
                            detail=f"  ↳ {kind} evidence failed: {clean_for_ui(exc,1200)}\n"
                        self.events.put(("dep",f"\n[{completed}/{len(detail_jobs)} dossiers] {item} · {kind}\n{detail}"))
                        self.events.put(("status",f"Dependency evidence {completed}/{len(detail_jobs)} complete"))
                    pool.shutdown(wait=True); pool=None
            self.events.put(("dep", "\nSCAN COMPLETE — all dependency specifications processed.\n"))
        except Exception as exc: self.events.put(("dep","\nERROR: "+clean_for_ui(exc,4000)+"\n"))
        finally:
            if pool: pool.shutdown(wait=False,cancel_futures=True)
            if client: client.close()
            with self.client_lock:
                if self.active_client is client: self.active_client=None
            self.events.put(("done",None))

    def _start_manifest_scan(self):
        if not self.manifest_root: return messagebox.showwarning("Manifest","Choose a project folder first.")
        if self.manifest_data is None:
            try: self.manifest_data=build_manifest(self.manifest_root)
            except Exception as exc: return messagebox.showerror("Manifest error",clean_for_ui(exc,1000))
        if self.manifest_data["entry_count"]>MAX_MANIFEST_API_ENTRIES:
            return messagebox.showwarning("Manifest too large",f"Manifest has {self.manifest_data['entry_count']} entries; cap is {MAX_MANIFEST_API_ENTRIES}.")
        try:
            api_key = self._get_api_key()
        except Exception as exc:
            return messagebox.showerror("API key error", clean_for_ui(exc, 1000))
        prompt=self.man_prompt.get("1.0","end").strip(); deep_scan=bool(self.deep_scan_var.get()); model=self._selected_model(); self.man_output.delete("1.0","end"); self.findings_output.delete("1.0","end"); self.diff_output.delete("1.0","end")
        self._launch(self._manifest_worker,self.manifest_data,prompt,api_key,deep_scan,model)

    def _manifest_worker(self,manifest,custom_prompt,api_key,deep_scan,model):
        client=None
        escalated=[]
        try:
            client=DaybreakClient(api_key,live_web=False,cancel_event=self.cancel_event,status_callback=lambda message:self.events.put(("status",message)),model_override=model,base_url=self._api_base_url,protocol=self._api_protocol)
            with self.client_lock: self.active_client=client
            entries=sorted((entry for entry in manifest["entries"] if is_reviewable_source(entry)),key=source_review_priority)
            self.events.put(("man",f"Source-first triage: {len(entries)} reviewable files; application code precedes tests, metadata, and workflows.\n\n"))
            for start in range(0,len(entries),MANIFEST_BATCH):
                if self.cancel_event.is_set(): return
                batch=entries[start:start+MANIFEST_BATCH]; ratings=client.classify_manifest(manifest["project_types"],batch,custom_prompt)
                for entry,rating in zip(batch,ratings):
                    self.events.put(("man",f"{entry['path']:<72} {rating.upper()}\n"))
                    if rating in {"medium","high"}: escalated.append((entry,rating))
            if not deep_scan:
                self.events.put(("man", "\nSCAN COMPLETE — manifest triage processed; deep review was disabled.\n"))
                return
            self.events.put(("man",f"\nLayer 2 gate: {len(escalated)} reviewable MEDIUM/HIGH files; processing at most {MAX_DEEP_FILES}.\n"))
            for n,(entry,rating) in enumerate(escalated[:MAX_DEEP_FILES],1):
                if self.cancel_event.is_set(): return
                path=entry["path"]
                try:
                    snap=load_source_snapshot(self.manifest_root,path)
                    review=client.review_source(path=path,project_types=manifest["project_types"],rating=rating,numbered=number_source(snap.text),custom_prompt=custom_prompt)
                    findings=validate_finding_spans(review.findings,snap.line_count)[:MAX_FINDINGS_PER_FILE]
                    self.events.put(("man",f"Layer 2 [{n}/{min(len(escalated),MAX_DEEP_FILES)}] {path}: {len(findings)} validated finding(s).\n"))
                    if findings:
                        bundles=[]
                        for idx,f in enumerate(findings):
                            proposal=None; verification=None; local_patch_ok=False; patch_reason="not generated"
                            try:
                                proposal=client.propose_patch(path=path,source=snap.text,finding_index=idx,finding=f.model_dump())
                                local_patch_ok,patch_reason=validate_unified_diff(proposal.unified_diff,path)
                                if local_patch_ok:
                                    verification=client.verify_patch(path=path,source=snap.text,finding=f.model_dump(),proposal=proposal.model_dump())
                            except Exception as exc:
                                patch_reason=f"patch pipeline error: {clean_for_ui(exc,800)}"
                            bundles.append({"finding":f.model_dump(),"proposal":proposal.model_dump() if proposal else None,"local_patch_ok":local_patch_ok,"patch_reason":patch_reason,"verification":verification.model_dump() if verification else None})
                        self.events.put(("source_bundle",{"path":path,"source":snap.text,"bundles":bundles}))
                except Exception as exc:
                    self.events.put(("man",f"  deep-review skipped {path}: {clean_for_ui(exc,1200)}\n"))
            self.events.put(("man", "\nSCAN COMPLETE — manifest and enabled deep-review stages processed.\n"))
        except Exception as exc: self.events.put(("man","\nERROR: "+clean_for_ui(exc,4000)+"\n"))
        finally:
            if client: client.close()
            with self.client_lock:
                if self.active_client is client: self.active_client=None
            self.events.put(("done",None))

    def _show_source_bundle(self,payload):
        path=payload["path"]; source=payload["source"]; bundles=payload["bundles"]
        self.review_file_label.configure(text=clean_for_ui(path,1000)); self.findings_output.delete("1.0","end"); self.source_code.delete("1.0","end"); self.diff_output.delete("1.0","end")
        self.source_code.insert("1.0",source)
        if not bundles:
            reason=payload.get("no_findings_reason") or "No schema-valid security finding met the confidence threshold."
            self.findings_output.insert("end",f"NO VALIDATED FINDINGS\n\n{clean_for_ui(reason,4000)}\n")
        # CTkTextbox wraps tkinter.Text. Tags are applied only from validated model spans.
        text_widget=self.source_code._textbox
        for tag in ("security_medium","security_high","security_critical"):
            try: text_widget.tag_delete(tag)
            except Exception: pass
        text_widget.tag_configure("security_medium",background="#5a4b00")
        text_widget.tag_configure("security_high",background="#6b2f00")
        text_widget.tag_configure("security_critical",background="#6b0000")
        for i,b in enumerate(bundles,1):
            f=b["finding"]; sev=f["severity"]
            self.findings_output.insert("end",f"[{i}] {sev.upper()}  lines {f['line_start']}-{f['line_end']}  confidence={f['confidence']:.2f}\n{f['title']}\n{f['evidence']}\nImpact: {f['security_impact']}\nFix goal: {f['remediation_goal']}\n\n")
            start=f"{f['line_start']}.0"; end=f"{f['line_end']+1}.0"
            text_widget.tag_add(f"security_{sev}",start,end)
            proposal=b.get("proposal"); verification=b.get("verification")
            self.diff_output.insert("end",f"=== Finding {i}: {f['title']} ===\n")
            if not proposal:
                self.diff_output.insert("end",f"No patch: {b.get('patch_reason')}\n\n"); continue
            if not b.get("local_patch_ok"):
                self.diff_output.insert("end",f"LOCAL PATCH REJECTED: {b.get('patch_reason')}\n\n"); continue
            if not verification or not verification.get("approved"):
                issues="; ".join((verification or {}).get("issues",[])) or "verifier did not approve"
                self.diff_output.insert("end",f"VERIFIER REJECTED: {issues}\n\n"); continue
            self.diff_output.insert("end","VERIFIED CANDIDATE PATCH — NOT APPLIED\n")
            self.diff_output.insert("end",proposal["unified_diff"]+"\n")
            self.diff_output.insert("end","Verification: "+verification["verification_summary"]+"\n\n")
        self.tabs.set("Deep Source Review")

    def _show_local_result(self, payload):
        self.local_findings = payload["findings"]
        self.local_metadata = payload["metadata"]
        meta = self.local_metadata
        counts = {severity: sum(f.severity == severity for f in self.local_findings) for severity in SEVERITY_VALUE}
        summary = " · ".join(f"{name.upper()} {counts[name]}" for name in ("critical", "high", "medium", "low", "info"))
        self.local_summary.configure(text=f"{meta.get('profile','Full repository')} · {meta['files_scanned']} files · {len(self.local_findings)} findings · {meta['elapsed_seconds']:.3f}s · {summary}")
        widget = self.local_output._textbox
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        if not self.local_findings:
            engines=", ".join(meta.get("engines",[]))
            widget.insert("end",f"NO ACTIONABLE FINDINGS\n\nProfile: {meta.get('profile','Full repository')}\nEngines completed: {engines}\nFiles examined: {meta['files_scanned']}\n\nNo finding met the selected severity/confidence gates. This is a bounded static result, not proof that the project is vulnerability-free.\n")
        else:
            grouped={}
            for finding in self.local_findings: grouped.setdefault(finding.engine,[]).append(finding)
            for engine,findings in sorted(grouped.items()):
                widget.insert("end",f"══ {engine.upper()} · {len(findings)} finding(s) ══\n\n")
                for finding in findings:
                    header = f"{finding.severity.upper():8} {finding.rule_id}  {finding.path}:{finding.line}:{finding.column}\n"
                    widget.insert("end", header, finding.severity)
                    widget.insert("end", f"  {finding.title} · confidence {finding.confidence:.2f}\n")
                    widget.insert("end", f"  {finding.evidence}\n")
                    widget.insert("end", f"  Fix: {finding.guidance}\n  Fingerprint: {finding.fingerprint}\n\n")
        widget.configure(state="disabled")
        self.tabs.set("Local Super Scan")

    def _export_local(self, report_format):
        if not self.local_metadata:
            return messagebox.showwarning("Export", "Run a local scan first.")
        suffix = ".sarif" if report_format == "sarif" else ".json"
        selected = filedialog.asksaveasfilename(
            title=f"Export {report_format.upper()} report", defaultextension=suffix,
            filetypes=[(report_format.upper(), f"*{suffix}"), ("All files", "*.*")],
        )
        if not selected:
            return
        try:
            document = render_sarif(self.local_findings, self.local_metadata) if report_format == "sarif" else result_document(self.local_findings, self.local_metadata)
            atomic_write(Path(selected), json.dumps(document, indent=2) + "\n")
            messagebox.showinfo("Export complete", f"Wrote {report_format.upper()} report to:\n{selected}")
        except Exception as exc:
            messagebox.showerror("Export failed", clean_for_ui(exc, 2000))

    def _drain_events(self):
        try:
            while True:
                kind,payload=self.events.get_nowait()
                if kind=="dep": self.dep_output.insert("end",clean_for_ui(payload)); self.dep_output.see("end")
                elif kind=="man": self.man_output.insert("end",clean_for_ui(payload)); self.man_output.see("end")
                elif kind=="source_bundle": self._show_source_bundle(payload)
                elif kind=="local_result": self._show_local_result(payload)
                elif kind=="local_error": self.local_summary.configure(text="Local scan failed"); messagebox.showerror("Local scan failed",payload)
                elif kind=="status": self.title(f"{APP_TITLE} — {clean_for_ui(payload, 300)}")
                elif kind=="done":
                    self._set_busy(False); self.cancel_btn.configure(text="Cancel"); self.title(APP_TITLE)
        except queue.Empty: pass
        self.after(100,self._drain_events)


if __name__ == "__main__":
    App().mainloop()
