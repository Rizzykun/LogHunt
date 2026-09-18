"""Capture dashboard screenshots for the README.

Starts nothing itself - run the app first, then point this at it:

    streamlit run app.py
    python tools/capture_screenshots.py --url http://localhost:8501

Uses Selenium with headless Chrome. Selenium Manager fetches a matching
driver on first run, so no manual driver install is needed.
"""
from __future__ import annotations

import argparse
import os
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

# (file name, sidebar label, extra scroll in pixels, settle seconds)
VIEWS = [
    ("01-overview", "Overview", 0, 6),
    ("02-alerts", "Alerts", 0, 6),
    ("03-timeline", "Timeline", 0, 8),
    ("04-attack-chains", "Attack chains", 0, 7),
    ("05-ip-investigation", "IP investigation", 0, 8),
    ("06-account-investigation", "Account investigation", 0, 8),
    ("07-mitre-attack", "MITRE ATT&CK", 0, 7),
    ("08-detection-rules", "Detection rules", 0, 5),
    ("09-report", "Reports", 0, 9),
]


def click_sidebar(driver, label: str) -> bool:
    """Select a view in the sidebar's navigation radio group.

    Streamlit renders st.radio as a role="radiogroup" of labels wrapping a
    hidden radio input. Clicking the label text does nothing useful; the input
    is what carries the change event, so that is what gets clicked. The page's
    second radio group is the navigation (the first picks the dataset).
    """
    return driver.execute_script(
        """
        const groups = document.querySelectorAll('div[role="radiogroup"]');
        const nav = groups[groups.length - 1];
        if (!nav) return false;
        for (const option of nav.querySelectorAll('label')) {
            if (option.innerText.trim() === arguments[0]) {
                const input = option.querySelector('input[type="radio"]');
                (input || option).click();
                return true;
            }
        }
        return false;
        """,
        label,
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8501")
    ap.add_argument("--out", default="screenshots")
    ap.add_argument("--width", type=int, default=1600)
    ap.add_argument("--height", type=int, default=1100)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument(f"--window-size={args.width},{args.height}")
    options.add_argument("--force-device-scale-factor=1")
    options.add_argument("--hide-scrollbars")

    driver = webdriver.Chrome(options=options)
    try:
        driver.get(args.url)
        time.sleep(12)          # first load parses the sample dataset

        for name, label, scroll, settle in VIEWS:
            if not click_sidebar(driver, label):
                print(f"  ! could not find the '{label}' nav item, skipping")
                continue
            time.sleep(settle)
            if scroll:
                driver.execute_script(f"window.scrollTo(0, {scroll});")
                time.sleep(1)
            path = os.path.join(args.out, f"{name}.png")
            driver.save_screenshot(path)
            print(f"  saved {path}")
    finally:
        driver.quit()


if __name__ == "__main__":
    main()
