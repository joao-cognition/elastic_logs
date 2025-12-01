#!/usr/bin/env python3
"""
Devin API client module for launching analysis tasks.

This module provides a wrapper around Devin's API for creating and managing
analysis sessions.
"""

import os
import time
from typing import Any

import requests


class DevinAPIClient:
    """Client for interacting with Devin's API."""

    BASE_URL = "https://api.devin.ai/v1"

    def __init__(self, api_key: str | None = None) -> None:
        """
        Initialize the Devin API client.

        Args:
            api_key: Devin API key. If not provided, reads from DEVIN_API_KEY env var.
        """
        self.api_key = api_key or os.environ.get("DEVIN_API_KEY")
        if not self.api_key:
            raise ValueError(
                "Devin API key is required. Set DEVIN_API_KEY environment variable "
                "or pass api_key parameter."
            )
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def create_session(
        self,
        prompt: str,
        playbook_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """
        Create a new Devin session with the given prompt.

        Args:
            prompt: The task prompt for Devin to execute.
            playbook_id: Optional playbook ID to use for the session.
            idempotency_key: Optional key to prevent duplicate sessions.

        Returns:
            Dictionary containing session information including session_id and url.
        """
        payload: dict[str, Any] = {"prompt": prompt}

        if playbook_id:
            payload["playbook_id"] = playbook_id

        if idempotency_key:
            payload["idempotency_key"] = idempotency_key

        response = requests.post(
            f"{self.BASE_URL}/sessions",
            headers=self.headers,
            json=payload,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def get_session(self, session_id: str) -> dict[str, Any]:
        """
        Get the status and details of a session.

        Args:
            session_id: The ID of the session to retrieve.

        Returns:
            Dictionary containing session details and status.
        """
        response = requests.get(
            f"{self.BASE_URL}/session/{session_id}",
            headers=self.headers,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def send_message(self, session_id: str, message: str) -> dict[str, Any]:
        """
        Send a message to an existing session.

        Args:
            session_id: The ID of the session.
            message: The message to send.

        Returns:
            Dictionary containing the response.
        """
        response = requests.post(
            f"{self.BASE_URL}/session/{session_id}/message",
            headers=self.headers,
            json={"message": message},
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def wait_for_completion(
        self,
        session_id: str,
        poll_interval: int = 30,
        timeout: int = 3600,
    ) -> dict[str, Any]:
        """
        Wait for a session to complete.

        Args:
            session_id: The ID of the session to wait for.
            poll_interval: Seconds between status checks.
            timeout: Maximum seconds to wait.

        Returns:
            Final session status.
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            session = self.get_session(session_id)
            status = session.get("status_enum")

            if status in ["finished", "stopped", "failed"]:
                return session

            time.sleep(poll_interval)

        raise TimeoutError(f"Session {session_id} did not complete within {timeout}s")


def save_analysis_result(
    analysis_type: str,
    session_id: str,
    session_url: str,
    prompt: str,
    status: str = "initiated",
) -> str:
    """
    Save analysis result to the analysis folder.

    Args:
        analysis_type: Type of analysis (error, security, performance).
        session_id: Devin session ID.
        session_url: URL to the Devin session.
        prompt: The prompt used for analysis.
        status: Current status of the analysis.

    Returns:
        Path to the saved result file.
    """
    import json
    from datetime import datetime

    result = {
        "analysis_type": analysis_type,
        "session_id": session_id,
        "session_url": session_url,
        "prompt": prompt,
        "status": status,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    os.makedirs("analysis", exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"analysis/{analysis_type}_analysis_{timestamp}.json"

    with open(filename, "w") as f:
        json.dump(result, f, indent=2)

    return filename
